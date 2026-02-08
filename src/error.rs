use core::arch::asm;
use derive_more::*;
use x86::dtables::DescriptorTablePointer;
use x86::vmx::VmFail;

#[derive(Debug, From)]
pub enum HypervisorError {
    GetPlatform,
    UnknownPlatform,
    EnableVirt,
    OutOfMemory,
    PageSplitRequired,
    #[from]
    VmFail(VmFail),
}

pub type Result<T> = core::result::Result<T, HypervisorError>;
