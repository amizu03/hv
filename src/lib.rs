#![feature(
    optimize_attribute,
    iter_array_chunks,
    f128,
    link_llvm_intrinsics,
    ptr_as_ref_unchecked
)]
#![allow(
    dead_code,
    unused,
    non_upper_case_globals,
    internal_features,
    incomplete_features,
    integer_to_ptr_transmutes,
    static_mut_refs
)]
#![no_std]
#![no_main]

extern crate alloc;
extern crate static_assertions;

mod allocator;
mod amd;
mod error;
mod hash;
mod hypervisor;
mod intel;
mod offsets;
mod panic;
mod prelude;
mod wdk;

use crate::{
    hypervisor::{compatibility::platform, Hypervisor},
    prelude::*,
};

static mut HV: Option<Hypervisor> = None;

#[unsafe(no_mangle)]
#[optimize(speed)]
extern "system" fn entry() -> isize {
    Module::init();

    let Ok(platform) = platform() else {
        return 0xC0000002; // STATUS_NOT_IMPLEMENTED
    };

    if !platform.is_supported() {
        return 0xC00000BB; // STATUS_NOT_SUPPORTED
    }

    unsafe {
        core::mem::forget(HV.take());
    }

    match Hypervisor::new() {
        Ok(hv) => unsafe {
            // if hv.virtualize().is_err() {
            //     return 0xC0000709; // STATUS_HARDWARE_MEMORY_ERROR
            // }
            HV = Some(hv);

            if let Some(hv) = &mut HV {
                hv.virtualize();
            }

            0
        },
        Err(_) => {
            0xC0000145 // STATUS_APP_INIT_FAILURE
        }
    }
}
