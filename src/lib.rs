use std::borrow::Cow;
use std::collections::HashMap;

use binaryninja::architecture::{
    Architecture, CoreArchitecture, CustomArchitectureHandle, Flag, FlagClass, FlagCondition,
    FlagGroup, FlagRole, FlagWrite, ImplicitRegisterExtend, InstructionInfo, Intrinsic, Register,
    RegisterInfo, RegisterStack, RegisterStackInfo,
};
use binaryninja::disassembly::{InstructionTextToken, InstructionTextTokenContents};
use binaryninja::llil::{self, Lifter};
use binaryninja::rc::Ref;
use binaryninja::types::{Conf, NameAndType, Type};
use binaryninja::Endianness;

use sleigh_eval::sleigh_rs::{NumberNonZeroUnsigned, Sleigh, VarnodeId};
use sleigh_eval::*;
use sleigh_rs::BitrangeId;

#[derive(Clone)]
pub struct SleighArch {
    pub core: CoreArchitecture,
    pub handle: CustomArchitectureHandle<SleighArch>,
    pub sleigh: &'static Sleigh,
    pub default_context: Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct SleighRegister {
    sleigh: &'static Sleigh,
    id: VarnodeId,
}

impl From<SleighRegister> for llil::Register<SleighRegister> {
    fn from(value: SleighRegister) -> Self {
        llil::Register::ArchReg(value)
    }
}

impl PartialEq for SleighRegister {
    fn eq(&self, other: &Self) -> bool {
        self.sleigh as *const _ as usize == other.sleigh as *const _ as usize && self.id == other.id
    }
}
impl Eq for SleighRegister {}
impl core::hash::Hash for SleighRegister {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (self.sleigh as *const _ as usize).hash(state);
        self.id.hash(state);
    }
}

#[derive(Clone, Copy)]
pub struct SleighRegisterInfo {
    size: NumberNonZeroUnsigned,
    offset: u64,
}

#[derive(Clone, Copy)]
pub struct SleighRegisterStack {}

#[derive(Clone, Copy)]
pub struct SleighRegisterStackInfo {}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum SleighFlag {}

#[derive(Clone, Copy)]
pub struct SleighFlagWrite {}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SleighFlagClass {}

#[derive(Clone, Copy)]
pub struct SleighFlagGroup {}

#[derive(Clone, Copy)]
pub struct SleighIntrinsic {
    sleigh: &'static Sleigh,
    id: sleigh_rs::UserFunctionId,
}

impl Architecture for SleighArch {
    type Handle = CustomArchitectureHandle<Self>;
    type RegisterInfo = SleighRegisterInfo;
    type Register = SleighRegister;
    type RegisterStackInfo = SleighRegisterStackInfo;
    type RegisterStack = SleighRegisterStack;
    type Flag = SleighFlag;
    type FlagWrite = SleighFlagWrite;
    type FlagClass = SleighFlagClass;
    type FlagGroup = SleighFlagGroup;
    type Intrinsic = SleighIntrinsic;

    fn endianness(&self) -> Endianness {
        match self.sleigh.endian() {
            sleigh_rs::Endian::Little => Endianness::LittleEndian,
            sleigh_rs::Endian::Big => Endianness::BigEndian,
        }
    }

    fn address_size(&self) -> usize {
        self.sleigh.addr_bytes().get().try_into().unwrap()
    }

    fn default_integer_size(&self) -> usize {
        // TODO C int or address size?
        self.address_size()
    }

    fn instruction_alignment(&self) -> usize {
        self.sleigh.alignemnt().into()
    }

    fn max_instr_len(&self) -> usize {
        self.sleigh
            .table(self.sleigh.instruction_table())
            .pattern_len
            .max()
            .map(|x| x.try_into().unwrap())
            // TODO find a reasonable value in case sleigh instruction table
            // have a growing pattern matching.
            .unwrap_or(32)
    }

    fn opcode_display_len(&self) -> usize {
        todo!()
    }

    fn associated_arch_by_addr(&self, _addr: &mut u64) -> CoreArchitecture {
        todo!()
    }

    fn instruction_info(&self, _data: &[u8], _addr: u64) -> Option<InstructionInfo> {
        // TODO extract this information from sleigh execution
        None
    }

    fn instruction_text(
        &self,
        data: &[u8],
        addr: u64,
    ) -> Option<(usize, Vec<InstructionTextToken>)> {
        let instruction =
            match_instruction(&self.sleigh, self.default_context.clone(), addr, data)?;
        // TODO convert the display segment directly into InstructionTextTokenContents
        let disassembly = to_string_instruction(&self.sleigh, addr, &instruction);
        let output = InstructionTextToken::new(&disassembly, InstructionTextTokenContents::Text);
        Some((instruction.constructor.len, vec![output]))
    }

    fn instruction_llil(
        &self,
        data: &[u8],
        addr: u64,
        il: &mut Lifter<Self>,
    ) -> Option<(usize, bool)> {
        let instruction =
            match_instruction(&self.sleigh, self.default_context.clone(), addr, data)?;
        let execution = sleigh_eval::to_execution_instruction(&self.sleigh, addr, &instruction)?;

        // create all the labels for blocks
        let mut map_label: Option<HashMap<BlockId, llil::Label>> = (execution.blocks.len() > 1)
            .then(|| {
                execution
                    .blocks
                    .iter()
                    .enumerate()
                    .map(|(id, _block)| (BlockId(id), llil::Label::default()))
                    .collect()
            });
        for (block_id, block) in execution.blocks.iter().enumerate() {
            if let Some(map_label) = &mut map_label {
                il.mark_label(map_label.get_mut(&BlockId(block_id)).unwrap());
            }
            for instr in &block.statements {
                match instr {
                    Statement::CpuBranch(branch) => {
                        let dst = ExecutionContext {
                            sleigh: &self.sleigh,
                            execution: &execution,
                            expr: &branch.dst,
                        };
                        let add_call = || match branch.call {
                            sleigh_rs::execution::BranchCall::Goto => il.jump(dst).append(),
                            sleigh_rs::execution::BranchCall::Call => il.call(dst).append(),
                            sleigh_rs::execution::BranchCall::Return => il.ret(dst).append(),
                        };
                        if let Some(cond) = &branch.cond {
                            let cond = ExecutionContext {
                                sleigh: &self.sleigh,
                                execution: &execution,
                                expr: cond,
                            };
                            assert!(il.label_for_address(addr).is_none());
                            let next_insts =
                                addr + u64::try_from(instruction.constructor.len).unwrap();
                            assert!(il.label_for_address(next_insts).is_none());
                            let mut tl = llil::Label::default();
                            il.mark_label(&mut tl);
                            add_call();
                            let mut fl = llil::Label::default();
                            il.if_expr(cond, &tl, &fl).append();
                            il.mark_label(&mut fl);
                        } else {
                            add_call()
                        }
                    }
                    Statement::LocalGoto(goto) => {
                        let label = map_label.as_mut().unwrap().get(&goto.dst).unwrap();
                        il.goto(label);
                    }
                    Statement::UserCall(call) => {
                        il.intrinsic::<'_, SleighRegister, _, _, _, _>(
                            [],
                            SleighIntrinsic {
                                sleigh: self.sleigh,
                                id: call.function,
                            },
                            call.params.iter().map(|p| ExecutionContext {
                                sleigh: &self.sleigh,
                                execution: &execution,
                                expr: p,
                            }),
                        )
                        .append();
                    }
                    Statement::Assignment(ass) => {
                        let expr = ExecutionContext {
                            sleigh: &self.sleigh,
                            execution: &execution,
                            expr: &ass.right,
                        };
                        match ass.var {
                            WriteValue::Varnode(varnode_id) => {
                                let varnode = self.sleigh.varnode(varnode_id);
                                il.set_reg(
                                    varnode.len_bytes.get().try_into().unwrap(),
                                    llil::Register::ArchReg(SleighRegister {
                                        sleigh: self.sleigh,
                                        id: varnode_id,
                                    }),
                                    expr,
                                )
                                .append();
                            }
                            WriteValue::Variable(variable_id) => {
                                let varnode = execution.variable(variable_id);
                                il.set_reg(
                                    ((varnode.len_bits.get() + 7) / 8).try_into().unwrap(),
                                    llil::Register::Temp(variable_id.0.try_into().unwrap()),
                                    expr,
                                )
                                .append();
                            }
                            WriteValue::Bitrange(_) => todo!(),
                        }
                    }
                    Statement::MemWrite(mem) => {
                        il.store(
                            mem.mem.len_bytes.get().try_into().unwrap(),
                            ExecutionContext {
                                sleigh: &self.sleigh,
                                execution: &execution,
                                expr: &mem.addr,
                            },
                            ExecutionContext {
                                sleigh: &self.sleigh,
                                execution: &execution,
                                expr: &mem.right,
                            },
                        )
                        .append();
                    }
                }
            }
        }
        // TODO implement sleigh execution and disable the debug flag
        Some((execution.delay_slot.try_into().unwrap(), true))
    }

    fn registers_all(&self) -> Vec<Self::Register> {
        use sleigh_rs::space::SpaceType::Register;
        let Some((space_id, _space)) = self
            .sleigh
            .spaces()
            .iter()
            .enumerate()
            .find(|(_, space)| space.space_type == Register)
        else {
            return vec![];
        };
        self.sleigh
            .varnodes()
            .iter()
            .enumerate()
            .filter(|(_id, varnode)| varnode.space.0 == space_id)
            .map(|(id, _varnode)| SleighRegister::from_sleigh(self.sleigh, VarnodeId(id)))
            .collect()
    }

    fn registers_full_width(&self) -> Vec<Self::Register> {
        // TODO identify register that have overlapping data
        self.registers_all()
    }

    fn stack_pointer_reg(&self) -> Option<Self::Register> {
        todo!()
    }

    fn register_from_id(&self, id: u32) -> Option<Self::Register> {
        let id = VarnodeId(id.try_into().unwrap());
        Some(SleighRegister::from_sleigh(self.sleigh, id))
    }

    fn handle(&self) -> Self::Handle {
        self.handle
    }
}

impl AsRef<CoreArchitecture> for SleighArch {
    fn as_ref(&self) -> &CoreArchitecture {
        &self.core
    }
}

impl SleighRegister {
    fn from_sleigh(inner: &'static Sleigh, id: VarnodeId) -> Self {
        SleighRegister { sleigh: inner, id }
    }
}

impl Register for SleighRegister {
    type InfoType = SleighRegisterInfo;

    fn name(&self) -> Cow<str> {
        let varnode = self.sleigh.varnode(self.id);
        Cow::Borrowed(varnode.name())
    }

    fn info(&self) -> Self::InfoType {
        let varnode = self.sleigh.varnode(self.id);
        SleighRegisterInfo {
            size: varnode.len_bytes,
            offset: varnode.address,
        }
    }

    fn id(&self) -> u32 {
        if self.id.0 >= 0x8000_0000 {
            todo!();
        }
        self.id.0 as u32
    }
}

impl RegisterInfo for SleighRegisterInfo {
    type RegType = SleighRegister;

    fn parent(&self) -> Option<Self::RegType> {
        // TODO Sleigh don't define hierarchy for registers, it allow all sorts
        // of overlapping
        None
    }

    fn size(&self) -> usize {
        self.size.get().try_into().unwrap()
    }

    fn offset(&self) -> usize {
        self.offset.try_into().unwrap()
    }

    fn implicit_extend(&self) -> ImplicitRegisterExtend {
        // TODO idenitfy registers that represent memory addresses to allow
        // it to ZeroExtendToFullWidth
        ImplicitRegisterExtend::NoExtend
    }
}

impl RegisterStack for SleighRegisterStack {
    type InfoType = SleighRegisterStackInfo;
    type RegType = SleighRegister;
    type RegInfoType = SleighRegisterInfo;

    fn name(&self) -> Cow<str> {
        todo!()
    }

    fn info(&self) -> Self::InfoType {
        todo!()
    }

    fn id(&self) -> u32 {
        // MUST be in the range [0, 0x7fff_ffff]
        todo!()
    }
}

impl RegisterStackInfo for SleighRegisterStackInfo {
    type RegStackType = SleighRegisterStack;
    type RegType = SleighRegister;
    type RegInfoType = SleighRegisterInfo;

    fn storage_regs(&self) -> (Self::RegType, u32) {
        todo!()
    }

    fn top_relative_regs(&self) -> Option<(Self::RegType, u32)> {
        todo!()
    }

    fn stack_top_reg(&self) -> Self::RegType {
        todo!()
    }
}

impl Flag for SleighFlag {
    type FlagClass = SleighFlagClass;

    fn name(&self) -> Cow<str> {
        todo!()
    }

    fn role(&self, _class: Option<Self::FlagClass>) -> FlagRole {
        todo!()
    }

    fn id(&self) -> u32 {
        // MUST be in the range [0, 0x7fff_ffff]
        todo!()
    }
}

impl FlagWrite for SleighFlagWrite {
    type FlagType = SleighFlag;
    type FlagClass = SleighFlagClass;

    fn name(&self) -> Cow<str> {
        todo!()
    }

    fn class(&self) -> Option<Self::FlagClass> {
        todo!()
    }

    fn id(&self) -> u32 {
        // MUST NOT be 0. MUST be in the range [1, 0x7fff_ffff]
        todo!()
    }

    fn flags_written(&self) -> Vec<Self::FlagType> {
        todo!()
    }
}

impl FlagClass for SleighFlagClass {
    fn name(&self) -> Cow<str> {
        todo!()
    }
    fn id(&self) -> u32 {
        // MUST NOT be 0. MUST be in the range [1, 0x7fff_ffff]
        todo!()
    }
}

impl FlagGroup for SleighFlagGroup {
    type FlagType = SleighFlag;
    type FlagClass = SleighFlagClass;

    fn name(&self) -> Cow<str> {
        todo!()
    }

    fn id(&self) -> u32 {
        // MUST be in the range [0, 0x7fff_ffff]
        todo!()
    }

    fn flags_required(&self) -> Vec<Self::FlagType> {
        todo!()
    }

    fn flag_conditions(&self) -> HashMap<Self::FlagClass, FlagCondition> {
        todo!()
    }
}

impl Intrinsic for SleighIntrinsic {
    fn name(&self) -> Cow<str> {
        let intrinsic = self.sleigh.user_function(self.id);
        Cow::Borrowed(intrinsic.name())
    }

    fn id(&self) -> u32 {
        self.id.0.try_into().unwrap()
    }

    fn inputs(&self) -> Vec<Ref<NameAndType>> {
        // TODO identify number of parameters, also solve functions that allow
        // variable number of parameters
        vec![]
    }

    fn outputs(&self) -> Vec<Conf<Ref<Type>>> {
        // TODO identify number of outputs, I assume it's always 0/1
        vec![]
    }
}

#[derive(Clone, Copy)]
struct ExecutionContext<'a, 'b, E> {
    sleigh: &'static Sleigh,
    execution: &'b Execution,
    expr: &'a E,
}

impl<'a, 'b, E> ExecutionContext<'a, 'b, E> {
    pub fn map<N>(&self, expr: &'a N) -> ExecutionContext<'a, 'b, N> {
        ExecutionContext {
            sleigh: self.sleigh,
            execution: self.execution,
            expr: expr,
        }
    }
}

impl<'a, 'b> llil::Liftable<'a, SleighArch> for ExecutionContext<'a, 'b, Expr> {
    type Result = llil::ValueExpr;

    fn lift(
        il: &'a binaryninja::llil::Function<
            SleighArch,
            llil::Mutable,
            llil::NonSSA<binaryninja::llil::LiftedNonSSA>,
        >,
        ctxt: Self,
    ) -> llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        Self::Result,
    > {
        let len_bytes = ((ctxt.expr.len_bits(ctxt.sleigh, ctxt.execution).get() + 7) / 8)
            .try_into()
            .unwrap();
        <Self as llil::LiftableWithSize<'a, SleighArch>>::lift_with_size(il, ctxt, len_bytes)
    }
}

impl<'a, 'b> llil::LiftableWithSize<'a, SleighArch> for ExecutionContext<'a, 'b, Expr> {
    fn lift_with_size(
        il: &'a binaryninja::llil::Function<
            SleighArch,
            llil::Mutable,
            llil::NonSSA<binaryninja::llil::LiftedNonSSA>,
        >,
        ctxt: Self,
        // TODO don't ignore that
        bytes: usize,
    ) -> llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        llil::ValueExpr,
    > {
        use sleigh_rs::execution::Binary::*;
        match &ctxt.expr {
            Expr::Value(value) => <ExecutionContext<'a, 'b, ExprElement> as llil::LiftableWithSize<
                'a,
                SleighArch,
            >>::lift_with_size(il, ctxt.map(value), bytes),
            Expr::Op(expr) => {
                let value_bytes = usize::try_from((expr.len_bits.get() + 7) / 8).unwrap();
                assert_eq!(bytes, value_bytes);
                let left = ctxt.map(&*expr.left);
                let right = ctxt.map(&*expr.right);
                match expr.op {
                    Mult => il.mul(bytes, left, right).build(),
                    Div => il.divu(bytes, left, right).build(),
                    SigDiv => il.divs(bytes, left, right).build(),
                    Rem => il.modu(bytes, left, right).build(),
                    SigRem => il.mods(bytes, left, right).build(),
                    FloatDiv => il.fdiv(bytes, left, right).build(),
                    FloatMult => il.fmul(bytes, left, right).build(),
                    Add => il.add(bytes, left, right).build(),
                    Sub => il.sub(bytes, left, right).build(),
                    FloatAdd => il.fadd(bytes, left, right).build(),
                    FloatSub => il.fsub(bytes, left, right).build(),
                    Lsl => il.lsl(bytes, left, right).build(),
                    Lsr => il.lsr(bytes, left, right).build(),
                    Asr => il.asr(bytes, left, right).build(),
                    // TODO il.and is bit AND?
                    BitAnd => il.and(bytes, left, right).build(),
                    BitXor => il.xor(bytes, left, right).build(),
                    BitOr => il.or(bytes, left, right).build(),
                    SigLess => il.cmp_slt(bytes, left, right).build(),
                    SigGreater => il.cmp_sgt(bytes, left, right).build(),
                    SigLessEq => il.cmp_sle(bytes, left, right).build(),
                    SigGreaterEq => il.cmp_sge(bytes, left, right).build(),
                    Less => il.cmp_ult(bytes, left, right).build(),
                    Greater => il.cmp_ugt(bytes, left, right).build(),
                    LessEq => il.cmp_ule(bytes, left, right).build(),
                    GreaterEq => il.cmp_uge(bytes, left, right).build(),
                    FloatLess => il.fcmp_lt(bytes, left, right).build(),
                    FloatGreater => il.fcmp_gt(bytes, left, right).build(),
                    FloatLessEq => il.fcmp_le(bytes, left, right).build(),
                    FloatGreaterEq => il.fcmp_ge(bytes, left, right).build(),
                    // TODO il.and is logical AND?
                    And => il.and(bytes, left, right).build(),
                    Xor => il.xor(bytes, left, right).build(),
                    Or => il.or(bytes, left, right).build(),
                    Eq => il.cmp_e(bytes, left, right).build(),
                    Ne => il.cmp_ne(bytes, left, right).build(),
                    FloatEq => il.fcmp_e(bytes, left, right).build(),
                    FloatNe => il.fcmp_ne(bytes, left, right).build(),
                    Carry => todo!(),
                    SCarry => todo!(),
                    SBorrow => todo!(),
                }
            }
        }
    }
}

impl<'a, 'b> llil::Liftable<'a, SleighArch> for ExecutionContext<'a, 'b, ExprElement> {
    type Result = llil::ValueExpr;

    fn lift(
        il: &'a binaryninja::llil::Function<
            SleighArch,
            llil::Mutable,
            llil::NonSSA<binaryninja::llil::LiftedNonSSA>,
        >,
        ctxt: Self,
    ) -> llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        Self::Result,
    > {
        let len = ((ctxt.expr.len_bits(&ctxt.sleigh, &ctxt.execution).get() + 7) / 8)
            .try_into()
            .unwrap();
        <ExecutionContext<'a, 'b, ExprElement> as llil::LiftableWithSize<'a, SleighArch>>::lift_with_size(il, ctxt, len)
    }
}

impl<'a, 'b> llil::LiftableWithSize<'a, SleighArch> for ExecutionContext<'a, 'b, ExprElement> {
    fn lift_with_size(
        il: &'a binaryninja::llil::Function<
            SleighArch,
            llil::Mutable,
            llil::NonSSA<binaryninja::llil::LiftedNonSSA>,
        >,
        ctxt: Self,
        // TODO don't ignore that
        bytes: usize,
    ) -> llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        llil::ValueExpr,
    > {
        match &ctxt.expr {
            ExprElement::Value(value) => <ExecutionContext<'a, 'b, ExprValue> as llil::Liftable<
                'a,
                SleighArch,
            >>::lift(il, ctxt.map(value)),
            ExprElement::UserCall(_) => todo!("BN don't allow intrinsic inline returning"),
            ExprElement::Op(expr_op) => {
                use sleigh_rs::execution::Unary::*;
                let size = usize::try_from((expr_op.output_bits.get() + 7) / 8).unwrap();
                let expr =
                    llil::LiftableWithSize::lift_with_size(il, ctxt.map(&*expr_op.input), size);
                match &expr_op.op {
                    TakeLsb(bytes) => il.low_part(bytes.get().try_into().unwrap(), expr).build(),
                    TrunkLsb(trunk) => ctxt.trunk_lsb(il, expr, *trunk, size, bytes),
                    BitRange(bits) => ctxt.bitrange(
                        il,
                        expr,
                        usize::try_from(bits.start - bits.end).unwrap(),
                        size,
                        bytes,
                    ),
                    Dereference(mem) => {
                        // TODO check if it's names RAM
                        if ctxt.sleigh.space(mem.space).space_type
                            != sleigh_rs::space::SpaceType::Ram
                        {
                            todo!();
                        }
                        il.load(size, expr).build()
                    }
                    // TODO logical negation and bit-negation?
                    Negation => il.not(size, expr).build(),
                    BitNegation => il.not(size, expr).build(),
                    Negative => il.neg(size, expr).build(),
                    FloatNegative => il.fneg(size, expr).build(),
                    Popcount => todo!(),
                    Lzcount => todo!(),
                    Zext => il.zx(size, expr).build(),
                    Sext => il.sx(size, expr).build(),
                    FloatNan => todo!(),
                    FloatAbs => il.fabs(size, expr).build(),
                    FloatSqrt => il.fsqrt(size, expr).build(),
                    Int2Float => il.int_to_float(size, expr).build(),
                    Float2Float => todo!(),
                    SignTrunc => todo!(),
                    FloatCeil => il.ceil(size, expr).build(),
                    FloatFloor => il.floor(size, expr).build(),
                    FloatRound => todo!(),
                }
            }
        }
    }
}

impl<'a, 'b> llil::Liftable<'a, SleighArch> for ExecutionContext<'a, 'b, ExprValue> {
    type Result = llil::ValueExpr;

    fn lift(
        il: &'a binaryninja::llil::Function<
            SleighArch,
            llil::Mutable,
            llil::NonSSA<binaryninja::llil::LiftedNonSSA>,
        >,
        ctxt: Self,
    ) -> llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        Self::Result,
    > {
        let len = ((ctxt.expr.len_bits(&ctxt.sleigh, &ctxt.execution).get() + 7) / 8)
            .try_into()
            .unwrap();
        <ExecutionContext<'a, 'b, ExprValue> as llil::LiftableWithSize<'a, SleighArch>>::lift_with_size(il, ctxt, len)
    }
}

impl<'a, 'b> llil::LiftableWithSize<'a, SleighArch> for ExecutionContext<'a, 'b, ExprValue> {
    fn lift_with_size(
        il: &'a binaryninja::llil::Function<
            SleighArch,
            llil::Mutable,
            llil::NonSSA<binaryninja::llil::LiftedNonSSA>,
        >,
        ctxt: Self,
        bytes: usize,
    ) -> llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        llil::ValueExpr,
    > {
        match &ctxt.expr {
            ExprValue::Int {
                len_bits: _,
                number,
            } => ctxt.const_from_int(il, *number, bytes),
            ExprValue::Varnode(var) => ctxt.read_varnode(il, *var, bytes),
            ExprValue::Bitrange { len_bits, value } => {
                ctxt.read_bitrange(il, *value, len_bits.get(), bytes)
            }
            ExprValue::ExeVar(var_id) => ctxt.read_variable(il, *var_id, bytes),
        }
    }
}

impl<'a, 'b, E> ExecutionContext<'a, 'b, E> {
    fn const_from_int(
        &self,
        il: &'a binaryninja::llil::Function<
            SleighArch,
            llil::Mutable,
            llil::NonSSA<binaryninja::llil::LiftedNonSSA>,
        >,
        number: sleigh_rs::Number,
        bytes: usize,
    ) -> llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        llil::ValueExpr,
    > {
        il.const_int(bytes, number.signed_super() as u64)
    }

    fn read_varnode(
        &self,
        il: &'a binaryninja::llil::Function<
            SleighArch,
            llil::Mutable,
            llil::NonSSA<binaryninja::llil::LiftedNonSSA>,
        >,
        varnode_id: VarnodeId,
        bytes: usize,
    ) -> llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        llil::ValueExpr,
    > {
        let varnode = self.sleigh.varnode(varnode_id);
        let varnode_bytes = usize::try_from(varnode.len_bytes.get()).unwrap();
        assert_eq!(varnode_bytes, bytes);
        il.reg(
            bytes,
            SleighRegister {
                sleigh: self.sleigh,
                id: varnode_id,
            },
        )
    }

    fn read_variable(
        &self,
        il: &'a binaryninja::llil::Function<
            SleighArch,
            llil::Mutable,
            llil::NonSSA<binaryninja::llil::LiftedNonSSA>,
        >,
        variable_id: VariableId,
        bytes: usize,
    ) -> llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        llil::ValueExpr,
    > {
        let variable = self.execution.variable(variable_id);
        let bits = usize::try_from(variable.len_bits.get()).unwrap();
        assert!(bits <= bytes * 8);
        il.reg(
            bytes,
            llil::Register::Temp(variable_id.0.try_into().unwrap()),
        )
    }

    fn read_bitrange(
        &self,
        il: &'a binaryninja::llil::Function<
            SleighArch,
            llil::Mutable,
            llil::NonSSA<binaryninja::llil::LiftedNonSSA>,
        >,
        bitrange_id: BitrangeId,
        bits: u64,
        bytes: usize,
    ) -> llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        llil::ValueExpr,
    > {
        let bitrange = self.sleigh.bitrange(bitrange_id);

        let bits = usize::try_from(bits).unwrap();
        let bitrange_bits = usize::try_from(bitrange.bits.len().get()).unwrap();

        assert!(bits >= bitrange_bits);
        assert!(bytes * 8 >= bits);

        let varnode = self.sleigh.varnode(bitrange.varnode);
        let varnode_bytes = usize::try_from(varnode.len_bytes.get()).unwrap();
        let expr = self.read_varnode(il, bitrange.varnode, varnode_bytes);

        // truncate the varnode into the bitrange
        self.bitrange(il, expr, bitrange_bits, varnode_bytes, bytes)
    }

    fn trunk_lsb(
        &self,
        il: &'a binaryninja::llil::Function<
            SleighArch,
            llil::Mutable,
            llil::NonSSA<binaryninja::llil::LiftedNonSSA>,
        >,
        mut expr: llil::Expression<
            'a,
            SleighArch,
            llil::Mutable,
            llil::NonSSA<llil::LiftedNonSSA>,
            llil::ValueExpr,
        >,
        trunk_lsb: u64,
        value_bytes: usize,
        output_bytes: usize,
    ) -> llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        llil::ValueExpr,
    > {
        if trunk_lsb > 0 {
            expr = il
                .lsr(
                    value_bytes,
                    expr,
                    self.const_from_int(il, (trunk_lsb * 8).into(), 4),
                )
                .build();
        }

        if output_bytes != value_bytes {
            expr = il.low_part(output_bytes, expr).build();
        }

        expr
    }

    fn bitrange(
        &self,
        il: &'a binaryninja::llil::Function<
            SleighArch,
            llil::Mutable,
            llil::NonSSA<binaryninja::llil::LiftedNonSSA>,
        >,
        mut expr: llil::Expression<
            'a,
            SleighArch,
            llil::Mutable,
            llil::NonSSA<llil::LiftedNonSSA>,
            llil::ValueExpr,
        >,
        bitrange_bits: usize,
        value_bytes: usize,
        output_bytes: usize,
    ) -> llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        llil::ValueExpr,
    > {
        if bitrange_bits > 0 {
            expr = il
                .lsr(
                    value_bytes,
                    expr,
                    self.const_from_int(il, u64::try_from(bitrange_bits).unwrap().into(), 4),
                )
                .build();
        }

        let mask = usize::MAX >> (usize::BITS - u32::try_from(bitrange_bits).unwrap());
        let mask = self.const_from_int(il, u64::try_from(mask).unwrap().into(), value_bytes);
        expr = il.and(value_bytes, expr, mask).build();

        if output_bytes != value_bytes {
            expr = il.low_part(output_bytes, expr).build();
        }

        expr
    }
}
