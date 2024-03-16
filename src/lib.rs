use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use arrayvec::ArrayString;

use binaryninja::architecture::{
    Architecture, CoreArchitecture, Flag, FlagClass, FlagCondition, FlagGroup, FlagRole, FlagWrite,
    ImplicitRegisterExtend, InstructionInfo, Intrinsic, Register, RegisterInfo, RegisterStack,
    RegisterStackInfo, CustomArchitectureHandle,
};
use binaryninja::disassembly::{InstructionTextToken, InstructionTextTokenContents};
use binaryninja::llil::Lifter;
use binaryninja::rc::Ref;
use binaryninja::string::BnString;
use binaryninja::types::{Conf, NameAndType, Type};
use binaryninja::Endianness;

use sleigh_eval::*;
use sleigh_rs::space::SpaceType;
use sleigh_rs::varnode::Varnode;
use sleigh_rs::{NumberNonZeroUnsigned, Sleigh, VarnodeId};

const MAX_NAME_SIZE: usize = 128;

pub struct SleighArch(pub Arc<SleighArchInner>);

#[derive(Clone)]
pub struct SleighArchInner {
    pub core: CoreArchitecture,
    pub handle: CustomArchitectureHandle<SleighArch>,
    pub sleigh: Sleigh,
    pub context: Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct SleighRegister {
    name: ArrayString<MAX_NAME_SIZE>,
    info: SleighRegisterInfo,
    id: VarnodeId,
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

#[derive(Clone, Copy)]
pub enum SleighFlag {}

#[derive(Clone, Copy)]
pub struct SleighFlagWrite {}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SleighFlagClass {}

#[derive(Clone, Copy)]
pub struct SleighFlagGroup {}

#[derive(Clone, Copy)]
pub struct SleighIntrinsic {
    name: ArrayString<MAX_NAME_SIZE>,
    id: sleigh_rs::UserFunctionId,
}

impl AsRef<SleighArchInner> for SleighArch {
    fn as_ref(&self) -> &SleighArchInner {
        self.0.as_ref()
    }
}

impl std::ops::Deref for SleighArch {
    type Target = SleighArchInner;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl Clone for SleighArch {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
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
        let mut context = self.context.clone();
        let instruction = match_instruction(&self.sleigh, &mut context, addr, data)?;
        // TODO convert the display segment directly into InstructionTextTokenContents
        let disassembly = to_string_instruction(&self.sleigh, &context, addr, &instruction);
        let output = InstructionTextToken::new(
            BnString::new(disassembly),
            InstructionTextTokenContents::Text,
        );
        Some((instruction.instruction.len, vec![output]))
    }

    fn instruction_llil(
        &self,
        _data: &[u8],
        _addr: u64,
        _il: &mut Lifter<Self>,
    ) -> Option<(usize, bool)> {
        // TODO implement sleigh execution and disable the debug flag
        None
    }

    fn registers_all(&self) -> Vec<Self::Register> {
        let Some((space_id, _space)) = self
            .sleigh
            .spaces()
            .iter()
            .enumerate()
            .find(|(_, space)| space.space_type == SpaceType::Register)
        else {
            return vec![];
        };
        self.sleigh
            .varnodes()
            .iter()
            .enumerate()
            .filter(|(_id, varnode)| varnode.space.0 == space_id)
            .map(|(id, varnode)| SleighRegister::from_sleigh(VarnodeId(id), varnode))
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
        let varnode = self.sleigh.varnode(id);
        Some(SleighRegister::from_sleigh(id, varnode))
    }

    fn handle(&self) -> Self::Handle {
        self.0.handle
    }
}

impl AsRef<CoreArchitecture> for SleighArch {
    fn as_ref(&self) -> &CoreArchitecture {
        &self.core
    }
}

impl SleighRegister {
    fn from_sleigh(id: VarnodeId, varnode: &Varnode) -> Self {
        let info = SleighRegisterInfo {
            size: varnode.len_bytes,
            offset: varnode.address,
        };
        SleighRegister {
            id,
            info,
            name: varnode.name().try_into().unwrap(),
        }
    }
}

impl Register for SleighRegister {
    type InfoType = SleighRegisterInfo;

    fn name(&self) -> Cow<str> {
        Cow::Borrowed(&self.name)
    }

    fn info(&self) -> Self::InfoType {
        self.info
    }

    fn id(&self) -> u32 {
        self.id.0.try_into().unwrap()
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
        Cow::Borrowed(&self.name)
    }

    fn id(&self) -> u32 {
        self.id.0.try_into().unwrap()
    }

    fn inputs(&self) -> Vec<NameAndType<String>> {
        // TODO identify number of parameters, also solve functions that allow
        // variable number of parameters
        vec![]
    }

    fn outputs(&self) -> Vec<Conf<Ref<Type>>> {
        // TODO identify number of outputs, I assume it's always 0/1
        vec![]
    }
}
