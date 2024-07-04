use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;

use binaryninja::architecture::{
    Architecture, CoreArchitecture, CustomArchitectureHandle, Flag, FlagClass, FlagCondition,
    FlagGroup, FlagRole, FlagWrite, ImplicitRegisterExtend, InstructionInfo, Intrinsic, Register,
    RegisterInfo, RegisterStack, RegisterStackInfo,
};
use binaryninja::custombinaryview::{BinaryViewType, BinaryViewTypeExt};
use binaryninja::disassembly::{InstructionTextToken, InstructionTextTokenContents};
use binaryninja::rc::Ref;
use binaryninja::types::{Conf, NameAndType, Type};
use binaryninja::Endianness;
use binaryninja::{add_optional_plugin_dependency, llil};

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
        // TODO is this exacly?
        self.max_instr_len()
    }

    fn associated_arch_by_addr(&self, _addr: &mut u64) -> CoreArchitecture {
        self.core
    }

    fn instruction_info(&self, data: &[u8], addr: u64) -> Option<InstructionInfo> {
        let instruction =
            match_instruction(&self.sleigh, self.default_context.clone(), addr, data)?;
        let execution = sleigh_eval::to_execution_instruction(&self.sleigh, addr, &instruction)?;
        Some(InstructionInfo::new(
            instruction.constructor.len,
            execution.delay_slot.try_into().unwrap(),
        ))
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
        il: &mut llil::Lifter<Self>,
    ) -> Option<(usize, bool)> {
        let instruction =
            match_instruction(&self.sleigh, self.default_context.clone(), addr, data)?;
        let execution = sleigh_eval::to_execution_instruction(&self.sleigh, addr, &instruction)?;

        // TODO handle context changes and GlobalSet

        // TODO for now only implement direct blocks
        if execution.blocks.len() > 1 {
            return None;
        }

        for instr in execution.blocks.iter().flat_map(|b| &b.statements) {
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
                        let next_insts = addr + u64::try_from(instruction.constructor.len).unwrap();
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
                Statement::LocalGoto(_goto) => {
                    unreachable!("Local goto should not exist in single block execution");
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
                                SleighRegister::from_sleigh(self.sleigh, varnode_id),
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
                        WriteValue::Bitrange(bitrange_id) => {
                            // write only a few bits to the reg,
                            // eg: varnode = (varnode & !0x1111) | value;
                            let bitrange = self.sleigh.bitrange(bitrange_id);
                            let varnode = self.sleigh.varnode(bitrange.varnode);
                            let varnode_len = varnode.len_bytes.get().try_into().unwrap();
                            let mask = (u64::MAX
                                >> (u64::BITS - u32::try_from(bitrange.bits.len().get()).unwrap()))
                                << bitrange.bits.start();
                            let left = il.and(
                                varnode_len,
                                il.reg(
                                    varnode_len,
                                    SleighRegister::from_sleigh(self.sleigh, bitrange.varnode),
                                ),
                                il.const_int(
                                    varnode_len,
                                    !mask
                                        & u64::MAX
                                            >> (u64::BITS
                                                - u32::try_from(varnode_len * 8).unwrap()),
                                ),
                            );
                            let expr = il.or(varnode_len, left, expr);
                            il.set_reg(
                                varnode_len,
                                SleighRegister::from_sleigh(self.sleigh, bitrange.varnode),
                                expr,
                            )
                            .append();
                        }
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
        // TODO find with external files?
        None
    }

    fn register_from_id(&self, id: u32) -> Option<Self::Register> {
        if id >= 0x8000_0000 {
            return None;
        }
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
    fn from_sleigh(sleigh: &'static Sleigh, id: VarnodeId) -> Self {
        assert!(id.0 < 0x8000_0000);
        SleighRegister { sleigh, id }
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
            panic!();
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
                let left = ctxt.map(&*expr.left);
                let right = ctxt.map(&*expr.right);
                let lifted_expr = match expr.op {
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
                    // TODO unimplemented for now
                    Carry => il.unimplemented(),
                    SCarry => il.unimplemented(),
                    SBorrow => il.unimplemented(),
                };
                cut_bits(lifted_expr, il, expr.len_bits.get().try_into().unwrap(), bytes)
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
                let lifted_expr = match &expr_op.op {
                    TakeLsb(bytes) => il.low_part(bytes.get().try_into().unwrap(), expr).build(),
                    TrunkLsb(trunk) => ctxt.trunk_lsb(il, expr, *trunk, size, bytes),
                    BitRange(bits) => ctxt.bitrange(il, expr, bits.start, bits.end, size, bytes),
                    Dereference(mem) => {
                        // TODO check if it's named RAM
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
                    Zext => il.zx(size, expr).build(),
                    Sext => il.sx(size, expr).build(),
                    FloatAbs => il.fabs(size, expr).build(),
                    FloatSqrt => il.fsqrt(size, expr).build(),
                    Int2Float => il.int_to_float(size, expr).build(),
                    FloatCeil => il.ceil(size, expr).build(),
                    FloatFloor => il.floor(size, expr).build(),
                    FloatNan => il.unimplemented(),
                    Float2Float => il.unimplemented(),
                    SignTrunc => il.unimplemented(),
                    FloatRound => il.unimplemented(),
                    Popcount => il.unimplemented(),
                    Lzcount => il.unimplemented(),
                };
                cut_bits(
                    lifted_expr,
                    il,
                    expr_op.output_bits.get().try_into().unwrap(),
                    bytes,
                )
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
        il.reg(bytes, SleighRegister::from_sleigh(self.sleigh, varnode_id))
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
        let bitrange_len = usize::try_from(bitrange.bits.len().get()).unwrap();

        assert!(bits >= bitrange_len);
        assert!(bytes * 8 >= bits);

        let varnode = self.sleigh.varnode(bitrange.varnode);
        let varnode_bytes = usize::try_from(varnode.len_bytes.get()).unwrap();
        let expr = self.read_varnode(il, bitrange.varnode, varnode_bytes);

        // truncate the varnode into the bitrange
        self.bitrange(
            il,
            expr,
            bitrange.bits.start(),
            bitrange.bits.end().get(),
            varnode_bytes,
            bytes,
        )
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
        bits_start: u64,
        bits_end: u64,
        value_bytes: usize,
        output_bytes: usize,
    ) -> llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        llil::ValueExpr,
    > {
        if bits_start > 0 {
            expr = il
                .lsr(
                    value_bytes,
                    expr,
                    self.const_from_int(il, bits_start.into(), 4),
                )
                .build();
        }

        let bitrange_bits = bits_end - bits_start;
        if bitrange_bits != u64::try_from(value_bytes * 8).unwrap() {
            let mask = usize::MAX >> (usize::BITS - u32::try_from(bitrange_bits).unwrap());
            let mask = self.const_from_int(il, u64::try_from(mask).unwrap().into(), value_bytes);
            expr = il.and(value_bytes, expr, mask).build();
        }

        if output_bytes != value_bytes {
            expr = il.low_part(output_bytes, expr).build();
        }

        expr
    }
}

fn cut_bits<'a>(
    lifted_expr: llil::Expression<
        'a,
        SleighArch,
        llil::Mutable,
        llil::NonSSA<llil::LiftedNonSSA>,
        llil::ValueExpr,
    >,
    il: &'a binaryninja::llil::Function<
        SleighArch,
        llil::Mutable,
        llil::NonSSA<binaryninja::llil::LiftedNonSSA>,
    >,
    bits: usize,
    bytes: usize,
) -> llil::Expression<
    'a,
    SleighArch,
    llil::Mutable,
    llil::NonSSA<llil::LiftedNonSSA>,
    llil::ValueExpr,
> {
    assert!(bytes * 8 >= bits);
    // if correct size, just return the expr
    if bytes * 8 == bits {
        return lifted_expr;
    }

    let mask = il.const_int(
        bytes,
        u64::MAX >> (u64::BITS - u32::try_from(bits).unwrap()),
    );
    il.and(bytes, lifted_expr, mask).build()
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    let handle = binaryninja::architecture::register_architecture("sleigh-sparc32", arch_builder);

    if let Ok(bvt) = BinaryViewType::by_name("ELF") {
        let endian = if handle.sleigh.endian().is_big() {
            binaryninja::Endianness::BigEndian
        } else {
            binaryninja::Endianness::LittleEndian
        };
        bvt.register_arch(2, endian, handle);
    }

    true
}

fn arch_builder(
    handle: CustomArchitectureHandle<SleighArch>,
    core: CoreArchitecture,
) -> SleighArch {
    const SLEIGH_FILE: &str = "Ghidra/Processors/Sparc/data/languages/SparcV9_32.slaspec";

    let home = std::env::var("GHIDRA_SRC").expect("Enviroment variable GHIDRA_SRC not found");
    let path = format!("{home}/{SLEIGH_FILE}");
    let sleigh = match sleigh_rs::file_to_sleigh(Path::new(&path)) {
        Ok(data) => data,
        Err(e) => panic!("Error: {e}"),
    };
    let default_context = new_default_context(&sleigh);
    SleighArch {
        default_context,
        sleigh: Box::leak(Box::new(sleigh)),
        core,
        handle,
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginDependencies() {
    add_optional_plugin_dependency("view_elf");
}
