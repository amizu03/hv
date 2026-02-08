use x86::{
    debugregs::dr7,
    dtables::{ldtr, sgdt, sidt, DescriptorTablePointer},
    msr::*,
    segmentation::{cs, ds, es, fs, gs, ss},
    task::tr,
    vmx::vmcs::control::CR0_READ_SHADOW,
};

use crate::{intel::instructions::*, prelude::*};

pub const VPID_TAG: u16 = 0x1;

mod fields {
    // 16-bit control fields (0000_xxxx)
    pub const VIRTUAL_PROCESSOR_ID: u64 = 0x00000000;
    pub const POSTED_INTERRUPT_NOTIFICATION_VECTOR: u64 = 0x00000002;
    pub const EPTP_INDEX: u64 = 0x00000004;

    // 16-bit guest-state fields (0000_08xx)
    pub const GUEST_ES_SELECTOR: u64 = 0x00000800;
    pub const GUEST_CS_SELECTOR: u64 = 0x00000802;
    pub const GUEST_SS_SELECTOR: u64 = 0x00000804;
    pub const GUEST_DS_SELECTOR: u64 = 0x00000806;
    pub const GUEST_FS_SELECTOR: u64 = 0x00000808;
    pub const GUEST_GS_SELECTOR: u64 = 0x0000080A;
    pub const GUEST_LDTR_SELECTOR: u64 = 0x0000080C;
    pub const GUEST_TR_SELECTOR: u64 = 0x0000080E;
    pub const GUEST_INTERRUPT_STATUS: u64 = 0x00000810;
    pub const PML_INDEX: u64 = 0x00000812;

    // 16-bit host-state fields (0000_0Cxx)
    pub const HOST_ES_SELECTOR: u64 = 0x00000C00;
    pub const HOST_CS_SELECTOR: u64 = 0x00000C02;
    pub const HOST_SS_SELECTOR: u64 = 0x00000C04;
    pub const HOST_DS_SELECTOR: u64 = 0x00000C06;
    pub const HOST_FS_SELECTOR: u64 = 0x00000C08;
    pub const HOST_GS_SELECTOR: u64 = 0x00000C0A;
    pub const HOST_TR_SELECTOR: u64 = 0x00000C0C;

    // 64-bit control fields (0000_2xxx)
    pub const IO_BITMAP_A: u64 = 0x00002000;
    pub const IO_BITMAP_B: u64 = 0x00002002;
    pub const MSR_BITMAP: u64 = 0x00002004;
    pub const VM_EXIT_MSR_STORE_ADDR: u64 = 0x00002006;
    pub const VM_EXIT_MSR_LOAD_ADDR: u64 = 0x00002008;
    pub const VM_ENTRY_MSR_LOAD_ADDR: u64 = 0x0000200A;
    pub const EXECUTIVE_VMCS_POINTER: u64 = 0x0000200C;
    pub const PML_ADDRESS: u64 = 0x0000200E;
    pub const TSC_OFFSET: u64 = 0x00002010;
    pub const TSC_OFFSET_HIGH: u64 = 0x00002011;
    pub const VIRTUAL_APIC_PAGE_ADDR: u64 = 0x00002012;
    pub const APIC_ACCESS_ADDR: u64 = 0x00002014;
    pub const POSTED_INTERRUPT_DESCRIPTOR_ADDR: u64 = 0x00002016;
    pub const VM_FUNCTIONS: u64 = 0x00002018;
    pub const EPT_POINTER: u64 = 0x0000201A;
    pub const EPTP_LIST_ADDRESS: u64 = 0x00002024;
    pub const VMREAD_BITMAP: u64 = 0x00002026;
    pub const VMWRITE_BITMAP: u64 = 0x00002028;
    pub const VIRTUALIZATION_EXCEPTION_INFO_ADDR: u64 = 0x0000202A;
    pub const XSS_EXITING_BITMAP: u64 = 0x0000202C;
    pub const TSC_MULTIPLIER: u64 = 0x00002032;
    pub const TSC_MULTIPLIER_HIGH: u64 = 0x00002033;

    // 64-bit read-only data fields (0000_24xx)
    pub const GUEST_PHYSICAL_ADDRESS: u64 = 0x00002400;
    pub const GUEST_PHYSICAL_ADDRESS_HIGH: u64 = 0x00002401;

    // 64-bit guest-state fields (0000_28xx)
    pub const VMCS_LINK_POINTER: u64 = 0x00002800;
    pub const GUEST_IA32_DEBUGCTL: u64 = 0x00002802;
    pub const GUEST_IA32_PAT: u64 = 0x00002804;
    pub const GUEST_IA32_EFER: u64 = 0x00002806;
    pub const GUEST_IA32_PERF_GLOBAL_CTRL: u64 = 0x00002808;
    pub const GUEST_PDPTR0: u64 = 0x0000280A;
    pub const GUEST_PDPTR1: u64 = 0x0000280C;
    pub const GUEST_PDPTR2: u64 = 0x0000280E;
    pub const GUEST_PDPTR3: u64 = 0x00002810;
    pub const GUEST_IA32_BNDCFGS: u64 = 0x00002812;
    pub const GUEST_IA32_RTIT_CTL: u64 = 0x00002814;

    // 64-bit host-state fields (0000_2Cxx)
    pub const HOST_IA32_PAT: u64 = 0x00002C00;
    pub const HOST_IA32_EFER: u64 = 0x00002C02;
    pub const HOST_IA32_PERF_GLOBAL_CTRL: u64 = 0x00002C04;

    // 32-bit control fields (0000_40xx)
    pub const PIN_BASED_VM_EXEC_CONTROL: u64 = 0x00004000;
    pub const CPU_BASED_VM_EXEC_CONTROL: u64 = 0x00004002;
    pub const EXCEPTION_BITMAP: u64 = 0x00004004;
    pub const PAGE_FAULT_ERROR_CODE_MASK: u64 = 0x00004006;
    pub const PAGE_FAULT_ERROR_CODE_MATCH: u64 = 0x00004008;
    pub const CR3_TARGET_COUNT: u64 = 0x0000400A;
    pub const VM_EXIT_CONTROLS: u64 = 0x0000400C;
    pub const VM_EXIT_MSR_STORE_COUNT: u64 = 0x0000400E;
    pub const VM_EXIT_MSR_LOAD_COUNT: u64 = 0x00004010;
    pub const VM_ENTRY_CONTROLS: u64 = 0x00004012;
    pub const VM_ENTRY_MSR_LOAD_COUNT: u64 = 0x00004014;
    pub const VM_ENTRY_INTR_INFO: u64 = 0x00004016;
    pub const VM_ENTRY_EXCEPTION_ERROR_CODE: u64 = 0x00004018;
    pub const VM_ENTRY_INSTRUCTION_LEN: u64 = 0x0000401A;
    pub const TPR_THRESHOLD: u64 = 0x0000401C;
    pub const SECONDARY_VM_EXEC_CONTROL: u64 = 0x0000401E;
    pub const PLE_GAP: u64 = 0x00004020;
    pub const PLE_WINDOW: u64 = 0x00004022;

    // 32-bit read-only fields (0000_44xx)
    pub const VM_INSTRUCTION_ERROR: u64 = 0x00004400;
    pub const VM_EXIT_REASON: u64 = 0x00004402;
    pub const VM_EXIT_INTR_INFO: u64 = 0x00004404;
    pub const VM_EXIT_INTR_ERROR_CODE: u64 = 0x00004406;
    pub const IDT_VECTORING_INFO: u64 = 0x00004408;
    pub const IDT_VECTORING_ERROR_CODE: u64 = 0x0000440A;
    pub const VM_EXIT_INSTRUCTION_LEN: u64 = 0x0000440C;
    pub const VMX_INSTRUCTION_INFO: u64 = 0x0000440E;

    // 32-bit guest-state fields (0000_48xx)
    pub const GUEST_ES_LIMIT: u64 = 0x00004800;
    pub const GUEST_CS_LIMIT: u64 = 0x00004802;
    pub const GUEST_SS_LIMIT: u64 = 0x00004804;
    pub const GUEST_DS_LIMIT: u64 = 0x00004806;
    pub const GUEST_FS_LIMIT: u64 = 0x00004808;
    pub const GUEST_GS_LIMIT: u64 = 0x0000480A;
    pub const GUEST_LDTR_LIMIT: u64 = 0x0000480C;
    pub const GUEST_TR_LIMIT: u64 = 0x0000480E;
    pub const GUEST_GDTR_LIMIT: u64 = 0x00004810;
    pub const GUEST_IDTR_LIMIT: u64 = 0x00004812;

    pub const GUEST_ES_AR_BYTES: u64 = 0x00004814;
    pub const GUEST_CS_AR_BYTES: u64 = 0x00004816;
    pub const GUEST_SS_AR_BYTES: u64 = 0x00004818;
    pub const GUEST_DS_AR_BYTES: u64 = 0x0000481A;
    pub const GUEST_FS_AR_BYTES: u64 = 0x0000481C;
    pub const GUEST_GS_AR_BYTES: u64 = 0x0000481E;

    pub const GUEST_LDTR_AR_BYTES: u64 = 0x00004820;
    pub const GUEST_TR_AR_BYTES: u64 = 0x00004822;
    pub const GUEST_INTERRUPTIBILITY_STATE: u64 = 0x00004824;
    pub const GUEST_ACTIVITY_STATE: u64 = 0x00004826;
    pub const GUEST_SYSENTER_CS: u64 = 0x0000482A;
    pub const VMX_PREEMPTION_TIMER_VALUE: u64 = 0x0000482E;

    // 32-bit host-state fields (0000_4Cxx)
    pub const HOST_IA32_SYSENTER_CS: u64 = 0x00004C00;

    // Natural-width control fields (0000_60xx)
    pub const CR0_GUEST_HOST_MASK: u64 = 0x00006000;
    pub const CR4_GUEST_HOST_MASK: u64 = 0x00006002;
    pub const CR0_READ_SHADOW: u64 = 0x00006004;
    pub const CR4_READ_SHADOW: u64 = 0x00006006;
    pub const CR3_TARGET_VALUE0: u64 = 0x00006008;
    pub const CR3_TARGET_VALUE1: u64 = 0x0000600A;
    pub const CR3_TARGET_VALUE2: u64 = 0x0000600C;
    pub const CR3_TARGET_VALUE3: u64 = 0x0000600E;

    // Natural-width read-only fields (0000_64xx)
    pub const EXIT_QUALIFICATION: u64 = 0x00006400;
    pub const IO_RCX: u64 = 0x00006402;
    pub const IO_RSI: u64 = 0x00006404;
    pub const IO_RDI: u64 = 0x00006406;
    pub const IO_RIP: u64 = 0x00006408;
    pub const GUEST_LINEAR_ADDRESS: u64 = 0x0000640A;

    // Natural-width guest-state fields (0000_68xx)
    pub const GUEST_CR0: u64 = 0x00006800;
    pub const GUEST_CR3: u64 = 0x00006802;
    pub const GUEST_CR4: u64 = 0x00006804;
    pub const GUEST_ES_BASE: u64 = 0x00006806;
    pub const GUEST_CS_BASE: u64 = 0x00006808;
    pub const GUEST_SS_BASE: u64 = 0x0000680A;
    pub const GUEST_DS_BASE: u64 = 0x0000680C;
    pub const GUEST_FS_BASE: u64 = 0x0000680E;
    pub const GUEST_GS_BASE: u64 = 0x00006810;
    pub const GUEST_LDTR_BASE: u64 = 0x00006812;
    pub const GUEST_TR_BASE: u64 = 0x00006814;
    pub const GUEST_GDTR_BASE: u64 = 0x00006816;
    pub const GUEST_IDTR_BASE: u64 = 0x00006818;
    pub const GUEST_DR7: u64 = 0x0000681A;
    pub const GUEST_RSP: u64 = 0x0000681C;
    pub const GUEST_RIP: u64 = 0x0000681E;
    pub const GUEST_RFLAGS: u64 = 0x00006820;
    pub const GUEST_PENDING_DBG_EXCEPTIONS: u64 = 0x00006822;
    pub const GUEST_SYSENTER_ESP: u64 = 0x00006824;
    pub const GUEST_SYSENTER_EIP: u64 = 0x00006826;

    // Natural-width host-state fields (0000_6Cxx)
    pub const HOST_CR0: u64 = 0x00006C00;
    pub const HOST_CR3: u64 = 0x00006C02;
    pub const HOST_CR4: u64 = 0x00006C04;
    pub const HOST_FS_BASE: u64 = 0x00006C06;
    pub const HOST_GS_BASE: u64 = 0x00006C08;
    pub const HOST_TR_BASE: u64 = 0x00006C0A;
    pub const HOST_GDTR_BASE: u64 = 0x00006C0C;
    pub const HOST_IDTR_BASE: u64 = 0x00006C0E;
    pub const HOST_IA32_SYSENTER_ESP: u64 = 0x00006C10;
    pub const HOST_IA32_SYSENTER_EIP: u64 = 0x00006C12;
    pub const HOST_RSP: u64 = 0x00006C14;
    pub const HOST_RIP: u64 = 0x00006C16;

    // Guest register state (for state saves)
    pub const GUEST_RAX: u64 = 0x0000681E; // Note: RAX is saved in VMCB, not VMCS
    pub const GUEST_RBX: u64 = 0x00006820;
    pub const GUEST_RCX: u64 = 0x00006822;
    pub const GUEST_RDX: u64 = 0x00006824;
    pub const GUEST_RSI: u64 = 0x00006826;
    pub const GUEST_RDI: u64 = 0x00006828;
    pub const GUEST_RBP: u64 = 0x0000682A;
    pub const GUEST_R8: u64 = 0x0000682C;
    pub const GUEST_R9: u64 = 0x0000682E;
    pub const GUEST_R10: u64 = 0x00006830;
    pub const GUEST_R11: u64 = 0x00006832;
    pub const GUEST_R12: u64 = 0x00006834;
    pub const GUEST_R13: u64 = 0x00006836;
    pub const GUEST_R14: u64 = 0x00006838;
    pub const GUEST_R15: u64 = 0x0000683A;
    pub const GUEST_DR6: u64 = 0x0000683C;
}

#[repr(C, align(0x1000))]
pub struct Vmxon {
    /// Revision ID required for VMXON.
    pub revision_id: u32,

    /// Data array constituting the rest of the VMXON region.
    pub data: [u8; PAGE_SIZE - 4],
}

impl Vmxon {
    /// Initializes the VMXON region.
    pub fn init(&mut self) {
        self.revision_id = unsafe { rdmsr(IA32_VMX_BASIC) } as u32;
        self.revision_id &= !(1 << 31);
    }

    /// Enables VMX operation by setting the VMX-enable bit in CR4.
    ///
    /// Sets the CR4_VMX_ENABLE_BIT to enable VMX operations, preparing the processor to enter VMX operation mode.
    pub fn enable_vmx_operation() {
        let mut cr4 = unsafe { cr4() };

        cr4.set(Cr4::CR4_ENABLE_VMX, true);

        unsafe {
            cr4_write(cr4);
        }
    }

    /// Adjusts the IA32_FEATURE_CONTROL MSR to set the lock bit and enable VMXON outside SMX if necessary.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the MSR is successfully adjusted, or a `HypervisorError` if the lock bit is set but VMXON outside SMX is disabled.
    pub fn adjust_feature_control_msr() -> Result<()> {
        const VMX_LOCK_BIT: u64 = 1 << 0;
        const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

        let ia32_feature_control = unsafe { rdmsr(IA32_FEATURE_CONTROL) };

        if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
            unsafe {
                wrmsr(
                    IA32_FEATURE_CONTROL,
                    VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | ia32_feature_control,
                );
            }
        } else if (ia32_feature_control & VMXON_OUTSIDE_SMX) == 0 {
            return Err(HypervisorError::EnableVirt);
        }

        Ok(())
    }

    /// Sets and clears mandatory bits in CR0 as required for VMX operation.
    ///
    /// Adjusts CR0 based on the fixed0 and fixed1 MSRs to ensure that all required bits for VMX operation are correctly set.
    pub fn set_cr0_bits() {
        let ia32_vmx_cr0_fixed0 = unsafe { rdmsr(IA32_VMX_CR0_FIXED0) };
        let ia32_vmx_cr0_fixed1 = unsafe { rdmsr(IA32_VMX_CR0_FIXED1) };

        let mut cr0 = unsafe { cr0().bits() };

        cr0 |= ia32_vmx_cr0_fixed0 as usize;
        cr0 &= ia32_vmx_cr0_fixed1 as usize;

        unsafe {
            cr0_write(Cr0::from_bits_unchecked(cr0));
        }
    }

    /// Modifies CR4 to set and clear mandatory bits for VMX operation.
    ///
    /// Uses the IA32_VMX_CR4_FIXED0 and IA32_VMX_CR4_FIXED1 MSRs to adjust CR4, ensuring the processor meets the requirements for VMX operation.
    pub fn set_cr4_bits() {
        let ia32_vmx_cr4_fixed0 = unsafe { rdmsr(IA32_VMX_CR4_FIXED0) };
        let ia32_vmx_cr4_fixed1 = unsafe { rdmsr(IA32_VMX_CR4_FIXED1) };

        let mut cr4 = unsafe { cr4().bits() };

        cr4 |= ia32_vmx_cr4_fixed0 as usize;
        cr4 &= ia32_vmx_cr4_fixed1 as usize;

        unsafe {
            cr4_write(Cr4::from_bits_unchecked(cr4));
        }
    }
}

/// VM exit controls
pub struct VmExitControls {
    pub save_debug_controls: bool,
    pub host_address_space_size: bool,
    pub load_ia32_perf_global_ctrl: bool,
    pub acknowledge_interrupt_on_exit: bool,
    pub save_ia32_pat: bool,
    pub load_ia32_pat: bool,
    pub save_ia32_efer: bool,
    pub load_ia32_efer: bool,
    pub save_vmx_preemption_timer_value: bool,
}

/// VM entry controls
pub struct VmEntryControls {
    pub load_debug_controls: bool,
    pub ia32e_mode_guest: bool,
    pub entry_to_smm: bool,
    pub deactivate_dual_monitor_treatment: bool,
    pub load_ia32_perf_global_ctrl: bool,
    pub load_ia32_pat: bool,
    pub load_ia32_efer: bool,
}

/// Pin-based VM execution controls
pub struct PinBasedControls {
    pub external_interrupt_exiting: bool,
    pub nmi_exiting: bool,
    pub virtual_nmis: bool,
    pub activate_vmx_preemption_timer: bool,
    pub process_posted_interrupts: bool,
}

/// Primary processor-based VM execution controls
pub struct PrimaryProcessorControls {
    pub interrupt_window_exiting: bool,
    pub use_tsc_offsetting: bool,
    pub hlt_exiting: bool,
    pub invlpg_exiting: bool,
    pub mwait_exiting: bool,
    pub rdpmc_exiting: bool,
    pub rdtsc_exiting: bool,
    pub cr3_load_exiting: bool,
    pub cr3_store_exiting: bool,
    pub cr8_load_exiting: bool,
    pub cr8_store_exiting: bool,
    pub use_tpr_shadow: bool,
    pub nmi_window_exiting: bool,
    pub mov_dr_exiting: bool,
    pub unconditional_io_exiting: bool,
    pub use_io_bitmaps: bool,
    pub monitor_trap_flag: bool,
    pub use_msr_bitmaps: bool,
    pub monitor_exiting: bool,
    pub pause_exiting: bool,
    pub activate_secondary_controls: bool,
}

/// Secondary processor-based VM execution controls
pub struct SecondaryProcessorControls {
    pub virtualize_apic_accesses: bool,
    pub enable_ept: bool,
    pub descriptor_table_exiting: bool,
    pub enable_rdtscp: bool,
    pub virtualize_x2apic_mode: bool,
    pub enable_vpid: bool,
    pub wbinvd_exiting: bool,
    pub unrestricted_guest: bool,
    pub apic_register_virtualization: bool,
    pub virtual_interrupt_delivery: bool,
    pub pause_loop_exiting: bool,
    pub rdrand_exiting: bool,
    pub enable_invpcid: bool,
    pub enable_vm_functions: bool,
    pub vmcs_shadowing: bool,
    pub enable_ept_violation: bool,
    pub rdseed_exiting: bool,
    pub enable_pml: bool,
    pub ept_violation_ve: bool,
    pub conceal_vmx_from_pt: bool,
    pub xsaves_xrstors: bool,
    pub mode_based_execute_control_ept: bool,
    pub sub_page_write_permissions_ept: bool,
    pub pt_guest_pa_uses_ia32_rtit: bool,
    pub use_tsc_scaling: bool,
}

#[repr(C, align(0x1000))]
pub struct Vmcs {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub reserved: [u8; PAGE_SIZE - 4 - 4],
}

impl Vmcs {
    /// Initializes the VMCS region.
    pub fn init(&mut self) {
        self.revision_id = unsafe { rdmsr(IA32_VMX_BASIC) } as u32;
        self.revision_id &= !(1 << 31);
    }

    /// Set pin-based controls
    pub fn set_pin_based_controls(&mut self, controls: PinBasedControls) -> Result<()> {
        let mut value: u64 = 0;

        if controls.external_interrupt_exiting {
            value |= 1 << 0;
        }
        if controls.nmi_exiting {
            value |= 1 << 3;
        }
        if controls.virtual_nmis {
            value |= 1 << 5;
        }
        if controls.activate_vmx_preemption_timer {
            value |= 1 << 6;
        }
        if controls.process_posted_interrupts {
            value |= 1 << 7;
        }

        unsafe {
            vmwrite(fields::PIN_BASED_VM_EXEC_CONTROL as u32, value)?;
        }

        Ok(())
    }

    /// Set primary processor-based controls
    pub fn set_primary_controls(&mut self, controls: PrimaryProcessorControls) -> Result<()> {
        let mut value: u64 = 0;

        if controls.interrupt_window_exiting {
            value |= 1 << 2;
        }
        if controls.use_tsc_offsetting {
            value |= 1 << 3;
        }
        if controls.hlt_exiting {
            value |= 1 << 7;
        }
        if controls.invlpg_exiting {
            value |= 1 << 9;
        }
        if controls.mwait_exiting {
            value |= 1 << 10;
        }
        if controls.rdpmc_exiting {
            value |= 1 << 11;
        }
        if controls.rdtsc_exiting {
            value |= 1 << 12;
        }
        if controls.cr3_load_exiting {
            value |= 1 << 15;
        }
        if controls.cr3_store_exiting {
            value |= 1 << 16;
        }
        if controls.cr8_load_exiting {
            value |= 1 << 19;
        }
        if controls.cr8_store_exiting {
            value |= 1 << 20;
        }
        if controls.use_tpr_shadow {
            value |= 1 << 21;
        }
        if controls.nmi_window_exiting {
            value |= 1 << 22;
        }
        if controls.mov_dr_exiting {
            value |= 1 << 23;
        }
        if controls.unconditional_io_exiting {
            value |= 1 << 24;
        }
        if controls.use_io_bitmaps {
            value |= 1 << 25;
        }
        if controls.monitor_trap_flag {
            value |= 1 << 27;
        }
        if controls.use_msr_bitmaps {
            value |= 1 << 28;
        }
        if controls.monitor_exiting {
            value |= 1 << 29;
        }
        if controls.pause_exiting {
            value |= 1 << 30;
        }
        if controls.activate_secondary_controls {
            value |= 1 << 31;
        }

        unsafe {
            vmwrite(fields::CPU_BASED_VM_EXEC_CONTROL as u32, value)?;
        }

        Ok(())
    }

    /// Set secondary processor-based controls
    pub fn set_secondary_controls(&mut self, controls: SecondaryProcessorControls) -> Result<()> {
        let mut value: u64 = 0;

        if controls.virtualize_apic_accesses {
            value |= 1 << 0;
        }
        if controls.enable_ept {
            value |= 1 << 1;
        }
        if controls.descriptor_table_exiting {
            value |= 1 << 2;
        }
        if controls.enable_rdtscp {
            value |= 1 << 3;
        }
        if controls.virtualize_x2apic_mode {
            value |= 1 << 4;
        }
        if controls.enable_vpid {
            value |= 1 << 5;
        }
        if controls.wbinvd_exiting {
            value |= 1 << 6;
        }
        if controls.unrestricted_guest {
            value |= 1 << 7;
        }
        if controls.apic_register_virtualization {
            value |= 1 << 8;
        }
        if controls.virtual_interrupt_delivery {
            value |= 1 << 9;
        }
        if controls.pause_loop_exiting {
            value |= 1 << 10;
        }
        if controls.rdrand_exiting {
            value |= 1 << 11;
        }
        if controls.enable_invpcid {
            value |= 1 << 12;
        }
        if controls.enable_vm_functions {
            value |= 1 << 13;
        }
        if controls.vmcs_shadowing {
            value |= 1 << 14;
        }
        if controls.enable_ept_violation {
            value |= 1 << 15;
        }
        if controls.rdseed_exiting {
            value |= 1 << 16;
        }
        if controls.enable_pml {
            value |= 1 << 17;
        }
        if controls.ept_violation_ve {
            value |= 1 << 18;
        }
        if controls.conceal_vmx_from_pt {
            value |= 1 << 19;
        }
        if controls.xsaves_xrstors {
            value |= 1 << 20;
        }
        if controls.mode_based_execute_control_ept {
            value |= 1 << 22;
        }
        if controls.sub_page_write_permissions_ept {
            value |= 1 << 23;
        }
        if controls.pt_guest_pa_uses_ia32_rtit {
            value |= 1 << 24;
        }
        if controls.use_tsc_scaling {
            value |= 1 << 25;
        }

        unsafe {
            vmwrite(fields::SECONDARY_VM_EXEC_CONTROL as u32, value)?;
        }

        Ok(())
    }

    /// Set VM-exit controls
    pub fn set_exit_controls(&mut self, controls: VmExitControls) -> Result<()> {
        let mut value: u64 = 0;

        if controls.save_debug_controls {
            value |= 1 << 2;
        }
        if controls.host_address_space_size {
            value |= 1 << 9;
        }
        if controls.load_ia32_perf_global_ctrl {
            value |= 1 << 12;
        }
        if controls.acknowledge_interrupt_on_exit {
            value |= 1 << 15;
        }
        if controls.save_ia32_pat {
            value |= 1 << 18;
        }
        if controls.load_ia32_pat {
            value |= 1 << 19;
        }
        if controls.save_ia32_efer {
            value |= 1 << 20;
        }
        if controls.load_ia32_efer {
            value |= 1 << 21;
        }
        if controls.save_vmx_preemption_timer_value {
            value |= 1 << 22;
        }

        unsafe {
            vmwrite(fields::VM_EXIT_CONTROLS as u32, value)?;
        }

        Ok(())
    }

    /// Set VM-entry controls
    pub fn set_entry_controls(&mut self, controls: VmEntryControls) -> Result<()> {
        let mut value: u64 = 0;

        if controls.load_debug_controls {
            value |= 1 << 2;
        }
        if controls.ia32e_mode_guest {
            value |= 1 << 9;
        }
        if controls.entry_to_smm {
            value |= 1 << 10;
        }
        if controls.deactivate_dual_monitor_treatment {
            value |= 1 << 11;
        }
        if controls.load_ia32_perf_global_ctrl {
            value |= 1 << 13;
        }
        if controls.load_ia32_pat {
            value |= 1 << 14;
        }
        if controls.load_ia32_efer {
            value |= 1 << 15;
        }

        unsafe {
            vmwrite(fields::VM_ENTRY_CONTROLS as u32, value)?;
        }

        Ok(())
    }
}

#[repr(C, align(0x1000))]
pub struct VmxMsrBitmap {
    pub rdmsr_lo: [u8; 1024],
    pub rdmsr_hi: [u8; 1024],
    pub wrmsr_lo: [u8; 1024],
    pub wrmsr_hi: [u8; 1024],
}

/// Task State Segment (64-bit)
///
/// See Intel SDM Vol. 3C, Section 7.7 (Task Management in 64-bit Mode)
#[repr(C, packed)]
pub struct TaskStateSegment64 {
    /// Reserved bits. Set to 0.
    pub reserved0: u32,
    /// Stack pointer for privilege level 0.
    pub rsp0: u64,
    /// Stack pointer for privilege level 1.
    pub rsp1: u64,
    /// Stack pointer for privilege level 2.
    pub rsp2: u64,
    /// Reserved bits. Set to 0.
    pub reserved1: u64,
    /// Interrupt stack table pointer (1).
    pub ist1: u64,
    /// Interrupt stack table pointer (2).
    pub ist2: u64,
    /// Interrupt stack table pointer (3).
    pub ist3: u64,
    /// Interrupt stack table pointer (4).
    pub ist4: u64,
    /// Interrupt stack table pointer (5).
    pub ist5: u64,
    /// Interrupt stack table pointer (6).
    pub ist6: u64,
    /// Interrupt stack table pointer (7).
    pub ist7: u64,
    /// Reserved bits. Set to 0.
    pub reserved2: u64,
    /// Reserved bits. Set to 0.
    pub reserved3: u16,
    /// The 16-bit offset to the I/O permission bit map from the 64-bit TSS base.
    pub io_map_base: u16,
}

const_assert_eq!(size_of::<TaskStateSegment64>(), 0x68);

#[repr(C, align(0x1000))]
pub struct VCpu {
    pub vmxon: Vmxon,
    pub vmcs: Vmcs,
    pub msr_bitmap: VmxMsrBitmap,
    pub stack: [u8; PAGE_SIZE * 6],
    pub tss: TaskStateSegment64,
    pub pad: [u8; PAGE_SIZE - size_of::<TaskStateSegment64>()],
}

const_assert_eq!(size_of::<VCpu>(), (PAGE_SIZE * 6) + (PAGE_SIZE * 4));

impl VCpuGeneric for VCpu {
    fn enable(&mut self) -> Result<()> {
        Vmxon::enable_vmx_operation();
        Vmxon::adjust_feature_control_msr()?;
        Vmxon::set_cr0_bits();
        Vmxon::set_cr4_bits();

        unsafe {
            vmxon(virt_to_phys(&raw mut self.vmxon as *mut _ as usize) as _)?;
        }

        Ok(())
    }

    fn setup(&mut self, hv: &mut Hypervisor, ctx: &Context) -> Result<()> {
        let vmcs_pa = virt_to_phys(&raw mut self.vmcs as *mut _ as usize);
        let msrpm_pa = virt_to_phys(hv.msr_permissions_bitmap.alloc);

        unsafe {
            vmclear(vmcs_pa as _)?;
            vmptrld(vmcs_pa as _)?;
        }

        let basic_msr = unsafe { rdmsr(IA32_VMX_BASIC) };

        let mut gdt = DescriptorTablePointer::<GDTEntry>::default();
        let mut idt = DescriptorTablePointer::<IDTEntry>::default();

        unsafe {
            sgdt(&mut gdt);
            sidt(&mut idt);
        }

        unsafe {
            // setup guest state
            vmwrite(fields::GUEST_CR0 as u32, cr0().bits() as _);
            vmwrite(fields::GUEST_CR3 as u32, cr3());
            vmwrite(fields::GUEST_CR4 as u32, cr4().bits() as _);

            vmwrite(fields::GUEST_DR7 as u32, unsafe { dr7().0 as u64 });

            vmwrite(fields::GUEST_RSP as u32, ctx.rsp);
            vmwrite(fields::GUEST_RIP as u32, ctx.rip);
            vmwrite(fields::GUEST_RFLAGS as u32, ctx.eflags as _);

            vmwrite(fields::GUEST_CS_SELECTOR as u32, cs().bits() as _);
            vmwrite(fields::GUEST_SS_SELECTOR as u32, ss().bits() as _);
            vmwrite(fields::GUEST_DS_SELECTOR as u32, ds().bits() as _);
            vmwrite(fields::GUEST_ES_SELECTOR as u32, es().bits() as _);
            vmwrite(fields::GUEST_FS_SELECTOR as u32, fs().bits() as _);
            vmwrite(fields::GUEST_GS_SELECTOR as u32, gs().bits() as _);
            vmwrite(fields::GUEST_LDTR_SELECTOR as u32, ldtr().bits() as _);
            vmwrite(fields::GUEST_TR_SELECTOR as u32, tr().bits() as _);

            // All segment base registers are assumed to be zero, except that of TR.
            vmwrite(
                fields::GUEST_TR_BASE as u32,
                segment_base(tr().bits(), gdt.base as _),
            );

            vmwrite(fields::GUEST_CS_LIMIT as u32, lsl(ss().bits()) as _);
            vmwrite(fields::GUEST_SS_LIMIT as u32, lsl(ss().bits()) as _);
            vmwrite(fields::GUEST_DS_LIMIT as u32, lsl(ds().bits()) as _);
            vmwrite(fields::GUEST_ES_LIMIT as u32, lsl(es().bits()) as _);
            vmwrite(fields::GUEST_FS_LIMIT as u32, lsl(fs().bits()) as _);
            vmwrite(fields::GUEST_GS_LIMIT as u32, lsl(gs().bits()) as _);
            vmwrite(fields::GUEST_LDTR_LIMIT as u32, lsl(ldtr().bits()) as _);
            vmwrite(fields::GUEST_TR_LIMIT as u32, lsl(tr().bits()) as _);

            vmwrite(
                fields::GUEST_CS_AR_BYTES as u32,
                segment_access_rights(cs().bits(), gdt.base as _) as u64,
            );
            vmwrite(
                fields::GUEST_SS_AR_BYTES as u32,
                segment_access_rights(ss().bits(), gdt.base as _) as u64,
            );
            vmwrite(
                fields::GUEST_DS_AR_BYTES as u32,
                segment_access_rights(ds().bits(), gdt.base as _) as u64,
            );
            vmwrite(
                fields::GUEST_ES_AR_BYTES as u32,
                segment_access_rights(es().bits(), gdt.base as _) as u64,
            );
            vmwrite(
                fields::GUEST_FS_AR_BYTES as u32,
                segment_access_rights(fs().bits(), gdt.base as _) as u64,
            );
            vmwrite(
                fields::GUEST_GS_AR_BYTES as u32,
                segment_access_rights(gs().bits(), gdt.base as _) as u64,
            );
            vmwrite(
                fields::GUEST_LDTR_AR_BYTES as u32,
                segment_access_rights(0, gdt.base as _) as u64,
            );
            vmwrite(
                fields::GUEST_TR_AR_BYTES as u32,
                segment_access_rights(tr().bits(), gdt.base as _) as u64,
            );

            vmwrite(fields::GUEST_GDTR_BASE as u32, gdt.base as u64);
            vmwrite(fields::GUEST_IDTR_BASE as u32, idt.base as u64);

            vmwrite(fields::GUEST_GDTR_LIMIT as u32, gdt.limit as u64);
            vmwrite(fields::GUEST_IDTR_LIMIT as u32, idt.limit as u64);

            vmwrite(fields::GUEST_IA32_DEBUGCTL as u32, rdmsr(IA32_DEBUGCTL));
            vmwrite(fields::GUEST_SYSENTER_CS as u32, rdmsr(IA32_SYSENTER_CS));
            vmwrite(fields::GUEST_SYSENTER_ESP as u32, rdmsr(IA32_SYSENTER_ESP));
            vmwrite(fields::GUEST_SYSENTER_EIP as u32, rdmsr(IA32_SYSENTER_EIP));

            vmwrite(fields::VMCS_LINK_POINTER as u32, u64::MAX);

            // setup host state
            vmwrite(fields::HOST_CR0 as u32, cr0().bits() as _);
            vmwrite(
                fields::HOST_CR3 as u32,
                hv.pml4(PageTableIndex::Primary).0 as _,
            );
            vmwrite(fields::HOST_CR4 as u32, cr4().bits() as _);

            vmwrite(fields::HOST_CS_SELECTOR as u32, cs().bits() as u64 & 0xF8);
            vmwrite(fields::HOST_SS_SELECTOR as u32, ss().bits() as u64 & 0xF8);
            vmwrite(fields::HOST_DS_SELECTOR as u32, ds().bits() as u64 & 0xF8);
            vmwrite(fields::HOST_ES_SELECTOR as u32, es().bits() as u64 & 0xF8);
            vmwrite(fields::HOST_FS_SELECTOR as u32, fs().bits() as u64 & 0xF8);
            vmwrite(fields::HOST_GS_SELECTOR as u32, gs().bits() as u64 & 0xF8);
            vmwrite(fields::HOST_TR_SELECTOR as u32, tr().bits() as u64 & 0xF8);

            vmwrite(fields::HOST_FS_BASE as u32, rdmsr(IA32_FS_BASE));
            vmwrite(fields::HOST_GS_BASE as u32, rdmsr(IA32_GS_BASE));
            vmwrite(
                fields::HOST_TR_BASE as u32,
                segment_base(tr().bits(), gdt.base as _),
            );

            vmwrite(fields::HOST_GDTR_BASE as u32, gdt.base as u64);
            vmwrite(fields::HOST_IDTR_BASE as u32, idt.base as u64);

            vmwrite(
                fields::HOST_IA32_SYSENTER_CS as u32,
                rdmsr(IA32_SYSENTER_CS),
            );
            vmwrite(
                fields::HOST_IA32_SYSENTER_ESP as u32,
                rdmsr(IA32_SYSENTER_ESP),
            );
            vmwrite(
                fields::HOST_IA32_SYSENTER_EIP as u32,
                rdmsr(IA32_SYSENTER_EIP),
            );
        }

        // Pin-based controls
        let pin_based = PinBasedControls {
            external_interrupt_exiting: false,
            nmi_exiting: false,
            virtual_nmis: false,
            activate_vmx_preemption_timer: false,
            process_posted_interrupts: false,
        };
        self.vmcs.set_pin_based_controls(pin_based)?;

        // Primary processor-based controls
        let primary = PrimaryProcessorControls {
            interrupt_window_exiting: false,
            use_tsc_offsetting: false, // Enable TSC virtualization
            hlt_exiting: false,
            invlpg_exiting: false,
            mwait_exiting: false,
            rdpmc_exiting: false,
            rdtsc_exiting: false, // Use TSC offset instead
            cr3_load_exiting: false,
            cr3_store_exiting: false,
            cr8_load_exiting: false,
            cr8_store_exiting: false,
            use_tpr_shadow: false,
            nmi_window_exiting: false,
            mov_dr_exiting: false,
            unconditional_io_exiting: false,
            use_io_bitmaps: false,
            monitor_trap_flag: false,
            use_msr_bitmaps: true,
            monitor_exiting: false,
            pause_exiting: false,
            activate_secondary_controls: true,
        };
        self.vmcs.set_primary_controls(primary)?;

        // Secondary processor-based controls
        let secondary = SecondaryProcessorControls {
            virtualize_apic_accesses: false,
            enable_ept: true,
            descriptor_table_exiting: false,
            enable_rdtscp: false,
            virtualize_x2apic_mode: false,
            enable_vpid: true,
            wbinvd_exiting: false,
            unrestricted_guest: false,
            apic_register_virtualization: false,
            virtual_interrupt_delivery: false,
            pause_loop_exiting: false,
            rdrand_exiting: false,
            enable_invpcid: false,
            enable_vm_functions: false,
            vmcs_shadowing: false,
            enable_ept_violation: false,
            rdseed_exiting: false,
            enable_pml: false,
            ept_violation_ve: false,
            conceal_vmx_from_pt: false,
            xsaves_xrstors: false,
            mode_based_execute_control_ept: false,
            sub_page_write_permissions_ept: false,
            pt_guest_pa_uses_ia32_rtit: false,
            use_tsc_scaling: false,
        };
        self.vmcs.set_secondary_controls(secondary)?;

        // VM-exit controls
        let exit_controls = VmExitControls {
            save_debug_controls: false,
            host_address_space_size: true, // 64-bit host
            load_ia32_perf_global_ctrl: false,
            acknowledge_interrupt_on_exit: false,
            save_ia32_pat: false,
            load_ia32_pat: false,
            save_ia32_efer: false,
            load_ia32_efer: false,
            save_vmx_preemption_timer_value: false,
        };
        self.vmcs.set_exit_controls(exit_controls)?;

        // VM-entry controls
        let entry_controls = VmEntryControls {
            load_debug_controls: false,
            ia32e_mode_guest: true, // 64-bit guest
            entry_to_smm: false,
            deactivate_dual_monitor_treatment: false,
            load_ia32_perf_global_ctrl: false,
            load_ia32_pat: false,
            load_ia32_efer: false,
        };
        self.vmcs.set_entry_controls(entry_controls)?;

        unsafe {
            vmwrite(fields::CR0_READ_SHADOW as u32, cr0().bits() as _);
            vmwrite(fields::CR4_READ_SHADOW as u32, cr4().bits() as _);

            vmwrite(fields::MSR_BITMAP as u32, msrpm_pa as _);
            // vmwrite(
            //     vmcs::control::EXCEPTION_BITMAP,
            //     1u64 << (ExceptionInterrupt::Breakpoint as u32),
            // );

            let ept = hv.pml4(PageTableIndex::Primary).0;
            vmwrite(fields::EPT_POINTER as u32, ept as _);
            vmwrite(fields::VIRTUAL_PROCESSOR_ID as u32, VPID_TAG as u64);

            invept_single_context(ept as _);
            invvpid_single_context(VPID_TAG);
        }

        Ok(())
    }
}
