use std::{path::Path, sync::Arc};

use binaryninja::architecture::{CoreArchitecture, CustomArchitectureHandle};
use sleigh_eval::new_default_context;
use sleigh_ninja::{SleighArch, SleighArchInner};
use sleigh_rs::ContextId;

fn main() {
    let _handle = binaryninja::architecture::register_architecture("sleigh-x86", register_arch);
}

fn register_arch(
    handle: CustomArchitectureHandle<SleighArch>,
    core: CoreArchitecture,
) -> SleighArch {
    const SLEIGH_FILE: &str = "Ghidra/Processors/x86/data/languages/x86-64.slaspec";

    let home = std::env::var("GHIDRA_SRC").expect("Enviroment variable GHIDRA_SRC not found");
    let path = format!("{home}/{SLEIGH_FILE}");
    let sleigh = match sleigh_rs::file_to_sleigh(Path::new(&path)) {
        Ok(data) => data,
        Err(e) => panic!("Error: {e}"),
    };
    let mut context = new_default_context(&sleigh);
    sleigh_eval::set_context_field_value(
        &sleigh,
        &mut context,
        sleigh
            .contexts()
            .iter()
            .position(|c| c.name() == "opsize")
            .map(ContextId)
            .unwrap(),
        1,
    );
    sleigh_eval::set_context_field_value(
        &sleigh,
        &mut context,
        sleigh
            .contexts()
            .iter()
            .position(|c| c.name() == "addrsize")
            .map(ContextId)
            .unwrap(),
        1,
    );
    SleighArch(Arc::new(SleighArchInner {
        context,
        sleigh,
        core,
        handle,
    }))
}
