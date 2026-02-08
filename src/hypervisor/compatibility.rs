use x86::msr::IA32_VMX_EPT_VPID_CAP;

use crate::prelude::*;

// Compile-time check to ensure only one architecture is enabled
#[cfg(all(feature = "amd", feature = "intel"))]
compile_error!("Features 'amd' and 'intel' are mutually exclusive. Choose one.");

#[derive(Debug, Copy, Clone)]
pub enum Platform {
    Intel,
    AMD,
}

impl Platform {
    pub fn is_supported(&self) -> bool {
        match self {
            Platform::Intel => Self::intel_supported(),
            Platform::AMD => Self::amd_supported(),
        }
    }

    #[cfg(not(feature = "amd"))]
    fn amd_supported() -> bool {
        false
    }

    #[cfg(feature = "amd")]
    fn amd_supported() -> bool {
        let cpuid = CpuId::new();

        let Some(f) = cpuid.get_feature_info() else {
            return false;
        };

        let Some(ex) = cpuid.get_extended_feature_info() else {
            return false;
        };

        let is_svm_supported = ex.has_umip();
        let is_npt_supported = f.has_fpu();
        let vmcr = unsafe { rdmsr(0xC0010114) };
        let svm_lock = (vmcr & 0b1000) != 0;
        let svme_disable = (vmcr & 0b10000) != 0;
        let can_svm_be_enabled = !svm_lock || !svme_disable;

        is_svm_supported && is_npt_supported && can_svm_be_enabled
    }

    #[cfg(not(feature = "intel"))]
    fn intel_supported() -> bool {
        false
    }

    #[cfg(feature = "intel")]
    fn intel_supported() -> bool {
        /// [Bit 6] Indicates support for a page-walk length of 4.
        const PAGE_WALK_LENGTH_4: u64 = 1 << 6;
        /// [Bit 14] When set to 1, the logical processor allows software to configure the EPT paging-structure memory type to be * write-back (WB).
        const MEMORY_TYPE_WRITE_BACK: u64 = 1 << 14;
        /// [Bit 16] When set to 1, the logical processor allows software to configure a EPT PDE to map a 2-Mbyte page (by setting * bit 7 in the EPT PDE).
        const PDE_2MB_PAGES: u64 = 1 << 16;
        /// [Bit 20] If bit 20 is read as 1, the INVEPT instruction is supported.
        const INVEPT: u64 = 1 << 20;
        /// [Bit 25] When set to 1, the single-context INVEPT type is supported.
        const INVEPT_SINGLE_CONTEXT: u64 = 1 << 25;
        /// [Bit 26] When set to 1, the all-context INVEPT type is supported.
        const INVEPT_ALL_CONTEXTS: u64 = 1 << 26;
        /// [Bit 32] When set to 1, the INVVPID instruction is supported.
        const INVVPID: u64 = 1 << 32;
        /// [Bit 41] When set to 1, the single-context INVVPID type is supported.
        const INVVPID_SINGLE_CONTEXT: u64 = 1 << 41;
        /// [Bit 42] When set to 1, the all-context INVVPID type is supported.
        const INVVPID_ALL_CONTEXTS: u64 = 1 << 42;

        let cpuid = CpuId::new();

        let Some(f) = cpuid.get_feature_info() else {
            return false;
        };

        let is_vmx_supported = f.has_vmx();
        let is_mtrr_supported = f.has_mtrr();

        let ept_vpid_cap = unsafe { rdmsr(IA32_VMX_EPT_VPID_CAP) };

        // Construct a combined mask for all required features for simplicity
        const REQUIRED_FEATURES: u64 = PAGE_WALK_LENGTH_4
            | MEMORY_TYPE_WRITE_BACK
            | PDE_2MB_PAGES
            | INVEPT
            | INVEPT_SINGLE_CONTEXT
            | INVEPT_ALL_CONTEXTS
            | INVVPID
            | INVVPID_SINGLE_CONTEXT
            | INVVPID_ALL_CONTEXTS;

        is_vmx_supported
            && is_mtrr_supported
            && (ept_vpid_cap & REQUIRED_FEATURES) == REQUIRED_FEATURES
    }
}

pub fn platform() -> Result<Platform> {
    let cpuid = CpuId::new();
    let vendor = cpuid
        .get_vendor_info()
        .ok_or(HypervisorError::GetPlatform)?;
    let vendor_str = vendor.as_str();

    match vendor_str {
        "GenuineIntel" => Ok(Platform::Intel),
        "AuthenticAMD" => Ok(Platform::AMD),
        _ => Err(HypervisorError::UnknownPlatform),
    }
}
