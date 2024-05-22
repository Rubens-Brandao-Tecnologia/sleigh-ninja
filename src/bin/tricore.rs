use std::path::Path;

use binaryninja::architecture::{CoreArchitecture, CustomArchitectureHandle};
use sleigh_eval::new_default_context;
use sleigh_ninja::SleighArch;

fn main() {
    let _handle = binaryninja::architecture::register_architecture("sleigh-tricore", register_arch);
}

fn register_arch(
    handle: CustomArchitectureHandle<SleighArch>,
    core: CoreArchitecture,
) -> SleighArch {
    const SLEIGH_FILE: &str = "Ghidra/Processors/tricore/data/languages/tricore.slaspec";

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
