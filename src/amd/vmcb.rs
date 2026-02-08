use crate::prelude::*;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SegmentAttribute64 {
    pub value: u16,
}

const_assert!(core::mem::size_of::<SegmentAttribute64>() == 2);

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SegRegister {
    pub selector: u16,
    pub attribute: SegmentAttribute64,
    pub limit: u32,
    pub base: u64,
}

const_assert!(core::mem::size_of::<SegRegister>() == 0x10);

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VmcbCtrlArea {
    pub intercept_cr_read: u16,
    pub intercept_cr_write: u16,
    pub intercept_dr_read: u16,
    pub intercept_dr_write: u16,
    pub intercept_exeption: u32,
    pub intercept_misc1: u32,
    pub intercept_misc2: u32,
    pub reserved1: [u8; 0x03c - 0x014],
    pub pause_filter_threshhold: u16,
    pub pause_filter_count: u16,
    pub iopm_base_pa: u64,
    pub msrpm_base_pa: u64,
    pub tsc_offset: u64,
    pub guest_asid: u32,
    pub tlb_control: u32,
    pub vintr: u64,
    pub interrupt_shadow: u64,
    pub exit_code: u64,
    pub exit_info1: u64,
    pub exit_info2: u64,
    pub exit_int_info: u64,
    pub np_enable: u64,
    pub avic_apic_bar: u64,
    pub guest_pa_of_ghcb: u64,
    pub event_inj: u64,
    pub ncr3: u64,
    pub lbr_virtualization_enable: u64,
    pub vmcb_clean: u64,
    pub next_rip: u64,
    pub num_of_bytes_fetched: u8,
    pub guest_instruction_bytes: [u8; 15],
    pub avic_apic_backing_page_ptr: u64,
    pub reserved2: u64,
    pub avic_logical_table_ptr: u64,
    pub avic_physical_table_ptr: u64,
    pub reserved3: u64,
    pub vmcb_save_state_ptr: u64,
    pub reserved4: [u8; 0x400 - 0x110],
}

const_assert!(core::mem::size_of::<VmcbCtrlArea>() == 0x400);

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VmcbStateSaveArea {
    pub es: SegRegister,
    pub cs: SegRegister,
    pub ss: SegRegister,
    pub ds: SegRegister,
    pub fs: SegRegister,
    pub gs: SegRegister,
    pub gdtr: SegRegister,
    pub ldtr: SegRegister,
    pub idtr: SegRegister,
    pub tr: SegRegister,
    pub reserved1: [u8; 0x0cb - 0x0a0],
    pub cpl: u8,
    pub reserved2: u32,
    pub efer: u64,
    pub reserved3: [u8; 0x148 - 0x0d8],
    pub cr4: u64,
    pub cr3: u64,
    pub cr0: u64,
    pub dr7: u64,
    pub dr6: u64,
    pub rflags: u64,
    pub rip: u64,
    pub reserved4: [u8; 0x1d8 - 0x180],
    pub rsp: u64,
    pub reserved5: [u8; 0x1f8 - 0x1e0],
    pub rax: u64,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub sfmask: u64,
    pub kernel_gs_base: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub cr2: u64,
    pub reserved6: [u8; 0x268 - 0x248],
    pub gpat: u64,
    pub dbg_ctl: u64,
    pub br_from: u64,
    pub br_to: u64,
    pub last_excep_from: u64,
    pub last_exep_to: u64,
}

const_assert!(core::mem::size_of::<VmcbStateSaveArea>() == 0x298);

#[repr(C, align(0x1000))]
#[derive(Debug, Copy, Clone)]
pub struct Vmcb {
    pub control_area: VmcbCtrlArea,
    pub state_save_area: VmcbStateSaveArea,
    pub reserved1: [u8; 0x1000 - 0x400 - 0x298],
}

const_assert!(core::mem::size_of::<Vmcb>() == 0x1000);

// =====================================================
// Table C-1. SVM Intercept Codes
// =====================================================

#[repr(i32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum VmExit {
    Cr0Read = 0x0,
    Cr1Read = 0x1,
    Cr2Read = 0x2,
    Cr3Read = 0x3,
    Cr4Read = 0x4,
    Cr5Read = 0x5,
    Cr6Read = 0x6,
    Cr7Read = 0x7,
    Cr8Read = 0x8,
    Cr9Read = 0x9,
    Cr10Read = 0xA,
    Cr11Read = 0xB,
    Cr12Read = 0xC,
    Cr13Read = 0xD,
    Cr14Read = 0xE,
    Cr15Read = 0xF,

    Cr0Write = 0x10,
    Cr1Write = 0x11,
    Cr2Write = 0x12,
    Cr3Write = 0x13,
    Cr4Write = 0x14,
    Cr5Write = 0x15,
    Cr6Write = 0x16,
    Cr7Write = 0x17,
    Cr8Write = 0x18,
    Cr9Write = 0x19,
    Cr10Write = 0x1A,
    Cr11Write = 0x1B,
    Cr12Write = 0x1C,
    Cr13Write = 0x1D,
    Cr14Write = 0x1E,
    Cr15Write = 0x1F,

    Dr0Read = 0x20,
    Dr1Read = 0x21,
    Dr2Read = 0x22,
    Dr3Read = 0x23,
    Dr4Read = 0x24,
    Dr5Read = 0x25,
    Dr6Read = 0x26,
    Dr7Read = 0x27,
    Dr8Read = 0x28,
    Dr9Read = 0x29,
    Dr10Read = 0x2A,
    Dr11Read = 0x2B,
    Dr12Read = 0x2C,
    Dr13Read = 0x2D,
    Dr14Read = 0x2E,
    Dr15Read = 0x2F,

    Dr0Write = 0x30,
    Dr1Write = 0x31,
    Dr2Write = 0x32,
    Dr3Write = 0x33,
    Dr4Write = 0x34,
    Dr5Write = 0x35,
    Dr6Write = 0x36,
    Dr7Write = 0x37,
    Dr8Write = 0x38,
    Dr9Write = 0x39,
    Dr10Write = 0x3A,
    Dr11Write = 0x3B,
    Dr12Write = 0x3C,
    Dr13Write = 0x3D,
    Dr14Write = 0x3E,
    Dr15Write = 0x3F,

    Excp0Write = 0x40,
    Excp1Write = 0x41,
    Excp2Write = 0x42,
    Excp3Write = 0x43,
    Excp4Write = 0x44,
    Excp5Write = 0x45,
    Excp6Write = 0x46,
    Excp7Write = 0x47,
    Excp8Write = 0x48,
    Excp9Write = 0x49,
    Excp10Write = 0x4A,
    Excp11Write = 0x4B,
    Excp12Write = 0x4C,
    Excp13Write = 0x4D,
    Excp14Write = 0x4E,
    Excp15Write = 0x4F,
    Excp16Write = 0x50,
    Excp17Write = 0x51,
    Excp18Write = 0x52,
    Excp19Write = 0x53,
    Excp20Write = 0x54,
    Excp21Write = 0x55,
    Excp22Write = 0x56,
    Excp23Write = 0x57,
    Excp24Write = 0x58,
    Excp25Write = 0x59,
    Excp26Write = 0x5A,
    Excp27Write = 0x5B,
    Excp28Write = 0x5C,
    Excp29Write = 0x5D,
    Excp30Write = 0x5E,
    Excp31Write = 0x5F,

    Intr = 0x60,
    Nmi = 0x61,
    Smi = 0x62,
    Init = 0x63,
    Vintr = 0x64,
    Cr0SelWrite = 0x65,
    IdtrRead = 0x66,
    GdtrRead = 0x67,
    LdtrRead = 0x68,
    TrRead = 0x69,
    IdtrWrite = 0x6A,
    GftrWrite = 0x6B,
    LdtrWrite = 0x6C,
    TrWrite = 0x6D,
    Rdtsc = 0x6E,
    Rdpmc = 0x6F,
    Pushf = 0x70,
    Popf = 0x71,
    Cpuid = 0x72,
    Rsm = 0x73,
    Iret = 0x74,
    Swint = 0x75,
    Invd = 0x76,
    Pause = 0x77,
    Hlt = 0x78,
    Invlpg = 0x79,
    Invlpga = 0x7A,
    Ioio = 0x7B,
    Msr = 0x7C,
    TaskSwitch = 0x7D,
    FerrFreeze = 0x7E,
    Shutdown = 0x7F,
    Vmrun = 0x80,
    Vmcall = 0x81,
    Vmload = 0x82,
    Vmsave = 0x83,
    Sigi = 0x84,
    Clgi = 0x85,
    Skinit = 0x86,
    Rdtscp = 0x87,
    Icebp = 0x88,
    Wbinvd = 0x89,
    Monitor = 0x8A,
    Mwait = 0x8B,
    MwaitConditional = 0x8C,
    Rdpru = 0x8D,
    Xsetbv = 0x8E,
    EferWriteTrap = 0x8F,

    Cr0WriteTrap = 0x90,
    Cr1WriteTrap = 0x91,
    Cr2WriteTrap = 0x92,
    Cr3WriteTrap = 0x93,
    Cr4WriteTrap = 0x94,
    Cr5WriteTrap = 0x95,
    Cr6WriteTrap = 0x96,
    Cr7WriteTrap = 0x97,
    Cr8WriteTrap = 0x98,
    Cr9WriteTrap = 0x99,
    Cr10WriteTrap = 0x9A,
    Cr11WriteTrap = 0x9B,
    Cr12WriteTrap = 0x9C,
    Cr13WriteTrap = 0x9D,
    Cr14WriteTrap = 0x9E,
    Cr15WriteTrap = 0x9F,

    Invlpgb = 0xA0,
    InvlpgbIllegal = 0xA1,
    Invpcid = 0xA2,
    Mcommit = 0xA3,
    Tlbsync = 0xA4,
    Npf = 0x400,
    IncompleteIpi = 0x401,
    AvicNoaccel = 0x402,
    Vmgexit = 0x403,

    Invalid = -1,
    Busy = -2,
}

const_assert!(core::mem::size_of::<VmExit>() == 4);

#[inline(always)]
pub fn event_inj(
    vector: u8,
    vector_type: u8,
    error_code_valid: bool,
    valid: bool,
    error_code: u32,
) -> u64 {
    let mut ev = 0;

    ev |= vector as u64;
    ev |= (vector_type as u64 & 0b111) << 8;
    ev |= (error_code_valid as u64 & 0b1) << 11;
    ev |= (valid as u64 & 0b1) << 31;
    ev |= (error_code as u64) << 32;

    ev
}

impl VmcbCtrlArea {
    pub fn inject_event(
        &mut self,
        vector: u8,
        vector_type: u8,
        error_code_valid: bool,
        valid: bool,
        error_code: u32,
    ) {
        self.event_inj = event_inj(vector, vector_type, error_code_valid, valid, error_code);
    }

    pub fn inject_ud(&mut self) {
        self.inject_event(6, 3, true, true, 0);
    }

    pub fn inject_gp(&mut self) {
        self.inject_event(13, 3, true, true, 0);
    }

    pub fn inject_pf(&mut self, error_code: u32) {
        self.inject_event(14, 3, true, true, error_code);
    }

    pub fn inject_db(&mut self) {
        self.inject_event(1, 3, false, true, 0);
    }

    pub fn _inject_bp(&mut self) {
        // Inject #GP(vector = 13, type = 3 = exception) with no error code.
        // See "#BP - Breakpoint Exception (Vector 3)".
        self.inject_event(3, 3, false, true, 0);
    }

    pub fn inject_external_interrupt(&mut self, vector: u8) {
        // Type 0 = External interrupt
        self.inject_event(vector, 0, false, true, 0);
    }

    pub fn inject_nmi(&mut self) {
        // Vector 2, Type 2 = NMI
        self.inject_event(2, 2, false, true, 0);
    }

    /// Inject virtual interrupt using V_IRQ mechanism (software interrupt virtualization)
    pub fn inject_virq(&mut self, vector: u8, priority: u8) {
        // Set V_IRQ bit (bit 0)
        self.vintr |= 1;

        // Set V_INTR_VECTOR (bits 8-15)
        self.vintr &= !0xFF00;
        self.vintr |= (vector as u64) << 8;

        // Set V_INTR_PRIO (bits 16-19)
        self.vintr &= !(0xF << 16);
        self.vintr |= (priority as u64) << 16;

        // V_IGN_TPR (bit 20) = 0 to respect TPR
        self.vintr &= !(1 << 20);
    }

    /// Clear V_IRQ after interrupt delivery
    pub fn clear_virq(&mut self) {
        // Clear V_IRQ bit (bit 0)
        self.vintr &= !1;
    }

    /// Check if V_IRQ is pending
    pub fn is_virq_pending(&self) -> bool {
        (self.vintr & 1) != 0
    }

    /// Get pending V_IRQ vector
    pub fn get_virq_vector(&self) -> u8 {
        ((self.vintr >> 8) & 0xFF) as u8
    }

    #[cfg(feature = "kvm")]
    pub fn flush_tlb(&mut self) {
        self.vmcb_clean &= 0xFFFFFFEF;
        self.tlb_control |= 1;
    }

    #[cfg(not(feature = "kvm"))]
    pub fn flush_tlb(&mut self) {
        self.vmcb_clean &= 0xFFFFFFEF;
        self.tlb_control |= 3;
    }
}
