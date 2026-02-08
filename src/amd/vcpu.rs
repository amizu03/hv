use core::arch::naked_asm;

use x86::{
    dtables::{sgdt, sidt, DescriptorTablePointer},
    msr::*,
    segmentation::{cs, ds, es, ss},
};

use super::vmcb::*;
use crate::{
    amd::instructions::{stgi, vmload, vmsave},
    hypervisor::Hypervisor,
    prelude::*,
};

// =====================================================
// Table B-1. VMCB Layout, Control Area
// =====================================================

#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Misc1Intercept {
    InterceptIntr = 1 << 0,
    InterceptNmi = 1 << 1,
    InterceptSmi = 1 << 2,
    InterceptInit = 1 << 3,
    InterceptVintr = 1 << 4,
    InterceptCr0_ = 1 << 5,

    InterceptReadIdtr = 1 << 6,
    InterceptReadGdtr = 1 << 7,
    InterceptReadLdtr = 1 << 8,
    InterceptReadTr = 1 << 9,

    InterceptWriteIdtr = 1 << 10,
    InterceptWriteGdtr = 1 << 11,
    InterceptWriteLdtr = 1 << 12,
    InterceptWriteTr = 1 << 13,

    InterceptRdtsc = 1 << 14,
    InterceptRdpmc = 1 << 15,
    InterceptPushf = 1 << 16,
    InterceptPopf = 1 << 17,
    InterceptCpuid = 1 << 18,
    InterceptRsm = 1 << 19,
    InterceptIret = 1 << 20,
    InterceptIntn = 1 << 21,
    InterceptInvd = 1 << 22,
    InterceptPause = 1 << 23,
    InterceptHlt = 1 << 24,
    InterceptInvldpg = 1 << 25,
    InterceptInvlpga = 1 << 26,
    InterceptIoioProt = 1 << 27,
    InterceptMsrProt = 1 << 28,
    InterceptTaskSwitches = 1 << 29,
    InterceptFerrFreeze = 1 << 30,
    InterceptShutdown = 1 << 31,
}
const_assert!(core::mem::size_of::<Misc1Intercept>() == 4);

#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Misc2Intercept {
    InterceptVmrun = 1 << 0,
    InterceptVmcall = 1 << 1,
    InterceptVmload = 1 << 2,
    InterceptVmsave = 1 << 3,

    InterceptStgi = 1 << 4,
    InterceptClgi = 1 << 5,
    InterceptSkinit = 1 << 6,
    InterceptRdtscp = 1 << 7,
    InterceptIncebp = 1 << 8,
    InterceptWbinvd = 1 << 9,
    InterceptMonitor = 1 << 10,
    InterceptMwait = 1 << 11,
    InterceptMwaitConditional = 1 << 12,
    InterceptXsetbv = 1 << 13,
    InterceptRdpru = 1 << 14,
    InterceptEfer = 1 << 15,

    InterceptCr0 = 1 << 16,
    InterceptCr1 = 1 << 17,
    InterceptCr2 = 1 << 18,
    InterceptCr3 = 1 << 19,
    InterceptCr4 = 1 << 20,
    InterceptCr5 = 1 << 21,
    InterceptCr6 = 1 << 22,
    InterceptCr7 = 1 << 23,
    InterceptCr8 = 1 << 24,
    InterceptCr9 = 1 << 25,
    InterceptCr10 = 1 << 26,
    InterceptCr11 = 1 << 27,
    InterceptCr12 = 1 << 28,
    InterceptCr13 = 1 << 29,
    InterceptCr14 = 1 << 30,
    InterceptCr15 = 1 << 31,
}
const_assert!(core::mem::size_of::<Misc2Intercept>() == 4);

#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ExceptionIntercept {
    DB = 1 << 1,
    BP = 1 << 3,
}

#[repr(C, align(0x1000))]
pub struct VCpu {
    pub stack: [u8; (PAGE_SIZE * 6) - (size_of::<usize>() * 6) - size_of::<KTrapFrame>()],
    pub trap_frame: KTrapFrame,
    pub guest_vmcb_pa: usize, // host rsp
    pub host_vmcb_pa: usize,
    pub vcpu: &'static mut VCpu,
    pub hv: &'static mut Hypervisor,
    pub ncpu: usize, // keep host rsp 16 bytes aligned
    pub reserved: usize,
    pub guest_vmcb: Vmcb,
    pub host_vmcb: Vmcb,
    pub host_state_area: [u8; PAGE_SIZE],
}

const_assert_eq!(size_of::<VCpu>(), (PAGE_SIZE * 6) + (PAGE_SIZE * 3));

impl VCpuGeneric for VCpu {
    fn enable(&mut self) -> Result<()> {
        // Enable SVM in EFER
        const EFER_MSR: u32 = 0xC0000080;
        const EFER_SVME: u64 = 1 << 12;

        let efer = unsafe { rdmsr(EFER_MSR) };

        unsafe { wrmsr(EFER_MSR, efer | EFER_SVME) };

        // Lock VM_CR if not already locked
        let vmcr = unsafe { rdmsr(0xC0010114) };

        if (vmcr & 0b1000) == 0 {
            // Clear SVME_DISABLE and set SVM_LOCK
            let new_vmcr = (vmcr & !0b10000) | 0b1000;
            unsafe {
                wrmsr(0xC0010114, new_vmcr);
            }
        }

        Ok(())
    }

    #[inline(never)]
    fn setup(&mut self, hv: &mut Hypervisor, rip: u64, rsp: u64, rflags: u64) -> Result<()> {
        let mut gdt = DescriptorTablePointer::<GDTEntry>::default();
        let mut idt = DescriptorTablePointer::<IDTEntry>::default();

        unsafe {
            sgdt(&mut gdt);
            sidt(&mut idt);
        }

        let guest_vmcb_pa = virt_to_phys(&raw const self.guest_vmcb as *const () as usize);
        let host_vmcb_pa = virt_to_phys(&raw const self.host_vmcb as *const () as usize);
        let host_state_area_pa =
            virt_to_phys(&raw const self.host_state_area as *const () as usize);
        // let pml4_base_pa = virt_to_phys(self.npml4.alloc);
        let msrpm_pa = virt_to_phys(hv.msr_permissions_bitmap.alloc);

        // mandatory intercepts - SVM instructions
        self.guest_vmcb.control_area.intercept_misc2 |= Misc2Intercept::InterceptVmrun as u32;
        self.guest_vmcb.control_area.intercept_misc2 |= Misc2Intercept::InterceptVmload as u32;
        self.guest_vmcb.control_area.intercept_misc2 |= Misc2Intercept::InterceptVmsave as u32;

        self.guest_vmcb.control_area.intercept_misc2 |= Misc2Intercept::InterceptStgi as u32;
        self.guest_vmcb.control_area.intercept_misc2 |= Misc2Intercept::InterceptClgi as u32;
        self.guest_vmcb.control_area.intercept_misc2 |= Misc2Intercept::InterceptSkinit as u32;

        // Intercept CPUID - hypervisors typically want to hide/changes CPUID values
        self.guest_vmcb.control_area.intercept_misc1 |= Misc1Intercept::InterceptCpuid as u32;

        // Intercept HLT to prevent guest from halting with interrupts disabled
        // self.guest_vmcb.control_area.intercept_misc1 |= Misc1Intercept::InterceptHlt as u32;

        // Intercept INVD/WBINVD for cache coherency
        // self.guest_vmcb.control_area.intercept_misc1 |= Misc1Intercept::InterceptInvd as u32;
        // self.guest_vmcb.control_area.intercept_misc2 |= Misc2Intercept::InterceptWbinvd as u32;

        // Intercept shutdown to detect triple faults
        // self.guest_vmcb.control_area.intercept_misc1 |= Misc1Intercept::InterceptShutdown as u32;

        // MSR interception
        self.guest_vmcb.control_area.intercept_misc1 |= Misc1Intercept::InterceptMsrProt as u32;
        self.guest_vmcb.control_area.msrpm_base_pa = msrpm_pa as _;

        // guest address space id (ASID)
        self.guest_vmcb.control_area.guest_asid = 1;

        // TLB control - flush TLB on VMRUN for this ASID
        self.guest_vmcb.control_area.tlb_control = 1;

        // enable guest NPT (nested page tables)
        self.guest_vmcb.control_area.np_enable |= 1;
        self.guest_vmcb.control_area.ncr3 = hv.pml4(PageTableIndex::Primary).0 as _;

        // Initialize virtual interrupt control (VINTR)
        // V_INTR_MASKING=1 allows the guest to control interrupt masking via EFLAGS.IF
        // self.guest_vmcb.control_area.vintr = 1 << 25; // V_INTR_MASKING

        // load initial guest state based on current state
        self.guest_vmcb.state_save_area.gdtr.base = gdt.base as u64;
        self.guest_vmcb.state_save_area.gdtr.limit = gdt.limit as u32;
        self.guest_vmcb.state_save_area.idtr.base = idt.base as u64;
        self.guest_vmcb.state_save_area.idtr.limit = idt.limit as u32;

        // setup all segments we saved earlier
        let cs = cs().bits();
        let ds = ds().bits();
        let es = es().bits();
        let ss = ss().bits();

        self.guest_vmcb.state_save_area.cs.limit = unsafe { lsl(cs) };
        self.guest_vmcb.state_save_area.ds.limit = unsafe { lsl(ds) };
        self.guest_vmcb.state_save_area.es.limit = unsafe { lsl(es) };
        self.guest_vmcb.state_save_area.ss.limit = unsafe { lsl(ss) };

        self.guest_vmcb.state_save_area.cs.selector = cs;
        self.guest_vmcb.state_save_area.ds.selector = ds;
        self.guest_vmcb.state_save_area.es.selector = es;
        self.guest_vmcb.state_save_area.ss.selector = ss;

        self.guest_vmcb.state_save_area.cs.attribute.value =
            segment_access_rights(cs, gdt.base as usize);
        self.guest_vmcb.state_save_area.ds.attribute.value =
            segment_access_rights(ds, gdt.base as usize);
        self.guest_vmcb.state_save_area.es.attribute.value =
            segment_access_rights(es, gdt.base as usize);
        self.guest_vmcb.state_save_area.ss.attribute.value =
            segment_access_rights(ss, gdt.base as usize);

        self.guest_vmcb.state_save_area.cr0 = unsafe { cr0().bits() as _ };
        self.guest_vmcb.state_save_area.cr2 = unsafe { cr2() as _ };
        self.guest_vmcb.state_save_area.cr3 = unsafe { cr3() as _ };
        self.guest_vmcb.state_save_area.cr4 = unsafe { cr4().bits() as _ };

        // vcpu.guest_vmcb.state_save_area.rax = rax;
        self.guest_vmcb.state_save_area.rsp = rsp as _;
        self.guest_vmcb.state_save_area.rip = rip as _;
        // EFLAGS bit 1 is always 1 in x86 architecture
        self.guest_vmcb.state_save_area.rflags = rflags as _;

        self.guest_vmcb.state_save_area.gpat = unsafe { rdmsr(IA32_PAT) };
        // Guest EFER should NOT have SVME bit set - that would allow guest to use SVM
        // which causes #VMEXIT instead of #UD for SVM instructions
        self.guest_vmcb.state_save_area.efer = unsafe { rdmsr(IA32_EFER) };
        self.guest_vmcb.state_save_area.star = unsafe { rdmsr(IA32_STAR) };
        self.guest_vmcb.state_save_area.lstar = unsafe { rdmsr(IA32_LSTAR) };
        self.guest_vmcb.state_save_area.cstar = unsafe { rdmsr(IA32_CSTAR) };

        // these are restored to the processor right before vmexit using vmload,
        // so that the guest can continue it's execution with the saved state
        unsafe {
            vmsave(guest_vmcb_pa as _);
        }

        // store data for the host to use
        self.reserved = usize::MAX;
        self.ncpu = current_processor_number() as usize;
        self.hv = unsafe { (hv as *mut Hypervisor).as_mut_unchecked() };
        self.vcpu = unsafe { (self as *mut VCpu).as_mut_unchecked() };
        self.host_vmcb_pa = host_vmcb_pa;
        self.guest_vmcb_pa = guest_vmcb_pa;

        // set an address of the host state area to VM_HSAVE:PA MSR.
        // the processor saves some of the current state on vmrun and loads them on vmexit
        // see "VM_HSAVE_PA MSR (C001_0117h)".
        unsafe {
            wrmsr(0xC0010117, host_state_area_pa as _);
        }

        // save the current state to the vmcb for the host to be loaded after vmexit
        unsafe {
            vmsave(host_vmcb_pa as _);
            vmenter(&mut self.guest_vmcb_pa);
        }

        Ok(())
    }

    fn advance_rip(&mut self) -> Result<()> {
        self.guest_vmcb.state_save_area.rip = self.guest_vmcb.control_area.next_rip;
        Ok(())
    }

    fn inject_ud(&mut self) -> Result<()> {
        self.guest_vmcb.control_area.inject_ud();
        Ok(())
    }

    fn inject_gp(&mut self) -> Result<()> {
        self.guest_vmcb.control_area.inject_gp();
        Ok(())
    }

    fn inject_pf(&mut self, error_code: u32) -> Result<()> {
        self.guest_vmcb.control_area.inject_pf(error_code);
        Ok(())
    }

    fn inject_db(&mut self) -> Result<()> {
        self.guest_vmcb.control_area.inject_db();
        Ok(())
    }

    fn inject_bp(&mut self) -> Result<()> {
        // Inject #GP(vector = 13, type = 3 = exception) with no error code.
        // See "#BP - Breakpoint Exception (Vector 3)".
        self.guest_vmcb.control_area._inject_bp();
        // Advance the guest RIP. When #BP is delivered, RIP must points to the
        // next instruction.
        self.advance_rip()
    }

    fn inject_external_interrupt(&mut self, vector: u8) -> Result<()> {
        self.guest_vmcb
            .control_area
            .inject_external_interrupt(vector);
        Ok(())
    }

    fn inject_nmi(&mut self) -> Result<()> {
        self.guest_vmcb.control_area.inject_nmi();
        Ok(())
    }

    fn flush_tlb(&mut self) -> Result<()> {
        self.guest_vmcb.control_area.flush_tlb();
        Ok(())
    }
}

const KTRAP_FRAME_SIZE: usize = size_of::<KTrapFrame>();

pub unsafe extern "system" fn handle_vmexit(
    vcpu: &mut VCpu,
    guest_registers: &mut GuestRegisters,
) -> bool {
    unsafe {
        vmload(vcpu.host_vmcb_pa as _);
    }

    let mut backup_irql: u64 = 0;
    let mut should_exit = false;

    // raise irql
    unsafe {
        asm!(
            "mov {backup_irql:r}, cr8",
            "cmp {backup_irql:r}, 2",
            "jge 2f",
            "mov rax, 2",
            "mov cr8, rax",
            "2:",
            backup_irql = out(reg) backup_irql
        );
    }

    // the guest's rax is overwritten by the hosts on vmexit
    // and saved in the vmcb instead
    guest_registers.rax = vcpu.guest_vmcb.state_save_area.rax;

    // update the _KTRAP_FRAME struct values in hypervisor stack,
    // so that windbg can reconstruct the guests stack frame
    vcpu.trap_frame.mach.rsp = vcpu.guest_vmcb.state_save_area.rsp as _;
    vcpu.trap_frame.mach.rip = vcpu.guest_vmcb.control_area.next_rip as _;

    let exit_code = vcpu.guest_vmcb.control_area.exit_code as i32;
    let exit_info1 = vcpu.guest_vmcb.control_area.exit_info1;
    let exit_info2 = vcpu.guest_vmcb.control_area.exit_info2;

    let vmexit_type = match exit_code {
        // Invalid VM exit - hardware error (next_rip is valid)
        x if x == VmExit::Invalid as i32 => VmExitType::IncrementRIP,
        x if x == VmExit::Cpuid as i32 => {
            let mut cpuid = cpuid!(guest_registers.rax as u32, guest_registers.rcx as u32);

            if guest_registers.rax == 0x5e5a4e00 {
                cpuid.eax = 1;
                cpuid.ebx = 0;
                cpuid.ecx = 0;
                cpuid.edx = 0;
            } else if guest_registers.rax == 0x8000000A {
                // SVM features - report limited nested virt support
                // EAX: SVM revision (keep original)
                // EBX: Number of ASIDs (keep original but may need adjustment for nested)
                // EDX: SVM feature flags - we should report what we actually support
                //       Bit 0: Nested paging (keep)
                //       Bit 1: LBR virtualization (keep)
                //       Bit 2: SVM-Lock (clear - guest can't use)
                //       Bit 3: NRIP Save (keep)
                //       Bit 4: MSR based TSC (keep)
                //       Bit 5: VMCB Clean (keep)
                //       Bit 6: Flush by ASID (keep)
                //       Bit 7: Decode assists (keep)
                //       Bit 8: Reserved
                //       Bit 9: SSK (clear - not supported)
                //       Bit 10: SEV (clear - not supported)
                //       Bit 11: SEV-ES (clear - not supported)
                cpuid.edx &= !((1 << 2) | (1 << 9) | (1 << 10) | (1 << 11));
            }
            // Hide SVM capability from guests - prevents nested hypervisors from loading
            else if guest_registers.rax == 0x80000001 {
                cpuid.ecx &= !(1 << 2); // Clear SVM bit (bit 2 of ECX)
            }

            guest_registers.rax = cpuid.eax as u64;
            guest_registers.rbx = cpuid.ebx as u64;
            guest_registers.rcx = cpuid.ecx as u64;
            guest_registers.rdx = cpuid.edx as u64;

            VmExitType::IncrementRIP
        }

        // Common instructions - next_rip points to instruction AFTER the intercepted one
        x if x == VmExit::Rdtsc as i32
            || x == VmExit::Rdtscp as i32
            || x == VmExit::Rdpmc as i32
            || x == VmExit::Pushf as i32
            || x == VmExit::Popf as i32
            || x == VmExit::Hlt as i32
            || x == VmExit::Invd as i32
            || x == VmExit::Wbinvd as i32
            || x == VmExit::Pause as i32
            || x == VmExit::Monitor as i32
            || x == VmExit::Mwait as i32
            || x == VmExit::MwaitConditional as i32
            || x == VmExit::Xsetbv as i32
            || x == VmExit::Rsm as i32
            || x == VmExit::Rdpru as i32
            || x == VmExit::Iret as i32
            || x == VmExit::Swint as i32
            || x == VmExit::Invlpg as i32
            || x == VmExit::Invlpga as i32 =>
        {
            VmExitType::IncrementRIP
        }

        // MSR access - next_rip is valid
        x if x == VmExit::Msr as i32 => VmExitType::IncrementRIP,

        // I/O instructions - next_rip is valid
        x if x == VmExit::Ioio as i32 => VmExitType::IncrementRIP,

        // CR reads - next_rip is valid
        x if (VmExit::Cr0Read as i32..=VmExit::Cr15Read as i32).contains(&x) => {
            VmExitType::IncrementRIP
        }

        // CR writes - next_rip is valid
        x if (VmExit::Cr0Write as i32..=VmExit::Cr15Write as i32).contains(&x)
            || (VmExit::Cr0WriteTrap as i32..=VmExit::Cr15WriteTrap as i32).contains(&x)
            || x == VmExit::Cr0SelWrite as i32 =>
        {
            VmExitType::IncrementRIP
        }

        // DR reads/writes - next_rip is valid
        x if (VmExit::Dr0Read as i32..=VmExit::Dr15Read as i32).contains(&x)
            || (VmExit::Dr0Write as i32..=VmExit::Dr15Write as i32).contains(&x) =>
        {
            VmExitType::IncrementRIP
        }

        // VM instructions - next_rip is valid
        x if x == VmExit::Vmrun as i32
            || x == VmExit::Vmcall as i32
            || x == VmExit::Vmload as i32
            || x == VmExit::Vmsave as i32
            || x == VmExit::Sigi as i32
            || x == VmExit::Clgi as i32
            || x == VmExit::Skinit as i32 =>
        {
            vcpu.inject_ud();
            VmExitType::Continue
        }

        // Task switch - next_rip is valid
        x if x == VmExit::TaskSwitch as i32 => VmExitType::IncrementRIP,

        // Descriptor table accesses - next_rip is valid
        x if x == VmExit::IdtrRead as i32
            || x == VmExit::GdtrRead as i32
            || x == VmExit::LdtrRead as i32
            || x == VmExit::TrRead as i32
            || x == VmExit::IdtrWrite as i32
            || x == VmExit::GftrWrite as i32
            || x == VmExit::LdtrWrite as i32
            || x == VmExit::TrWrite as i32 =>
        {
            VmExitType::IncrementRIP
        }

        // External interrupts - need to inject back to guest
        x if x == VmExit::Intr as i32 => {
            // exit_int_info contains the interrupt that caused the exit
            // Format: vector[7:0], type[10:8], v[12], etc.
            let int_info = vcpu.guest_vmcb.control_area.exit_int_info;

            // If valid, inject it back to the guest
            if int_info & (1 << 12) != 0 {
                vcpu.guest_vmcb.control_area.event_inj = int_info;
            }

            // RIP stays the same - the interrupt will be delivered after VMRUN
            VmExitType::Continue
        }

        // NMI - Non-maskable interrupt
        x if x == VmExit::Nmi as i32 => {
            // NMI should be injected back
            let int_info = vcpu.guest_vmcb.control_area.exit_int_info;
            if int_info & (1 << 12) != 0 {
                vcpu.guest_vmcb.control_area.event_inj = int_info;
            }

            VmExitType::Continue
        }

        // Nested Page Fault (NPF) - next_rip points to FAULTING instruction
        // We CANNOT just advance RIP - we need to fix the underlying issue
        x if x == VmExit::Npf as i32 => {
            // Capture vmroot CR3 early
            let vmroot_cr3 = unsafe { cr3() };

            // DEBUG: Log NPF address to see what's being accessed
            unsafe {
                cr3_write(vcpu.guest_vmcb.state_save_area.cr3);
            }

            // page not present
            if exit_info1 & 0x1 == 0 {
                let fault_gpa = exit_info2;

                let _ = vcpu.hv.assign_pt(
                    vcpu.guest_vmcb.control_area.ncr3 as _,
                    fault_gpa as usize & !(PAGE_SIZE_2MB - 1), // Align to page
                    // fault_gpa as usize & (PAGE_SIZE - 1), // Align to page
                    true,
                    true,
                    true,
                    true,
                );

                vcpu.flush_tlb();
            }

            unsafe {
                cr3_write(vmroot_cr3);
            }

            // DO NOT advance RIP - let the guest retry the faulting instruction
            // If the mapping was successful, it should work now
            VmExitType::Continue
        }

        // Exceptions (0x40-0x5F) - next_rip points to FAULTING instruction
        // These should generally be injected back to the guest
        x if (0x40..=0x5F).contains(&x) => {
            let exception_vector = (x - 0x40) as u8;

            // Inject the exception back into the guest
            // EVENTINJ format: vector[7:0], type[10:8], ev[11], v[12], errorcode[63:32]
            let mut eventinj: u64 = exception_vector as u64;
            eventinj |= 3 << 8; // Type 3 = exception
            eventinj |= 1 << 12; // Valid bit

            // For page faults (#PF, vector 14), include the error code
            if exception_vector == 14 {
                // For NPF, exit_info1 has the error code
                eventinj |= exit_info1 << 32;
            }

            vcpu.guest_vmcb.control_area.event_inj = eventinj;

            // DO NOT advance RIP - the exception handler will be executed
            VmExitType::Continue
        }

        // Shutdown - guest issued a triple fault or shutdown
        x if x == VmExit::Shutdown as i32 => {
            // This is fatal - exit virtualization
            VmExitType::ExitHypervisor
        }

        // Unhandled exit - crash to debug
        _ => unsafe {
            core::mem::transmute::<
                _,
                unsafe extern "system" fn(u32, usize, usize, usize, usize) -> !,
            >(Module::nt().base + crate::offsets::ntoskrnl::KeBugCheckEx)(
                0xE2,
                vcpu.guest_vmcb.control_area.exit_code as _,
                exit_info1 as _,
                exit_info2 as _,
                vcpu.guest_vmcb.state_save_area.rip as _,
            );
        },
    };

    unsafe {
        asm!(
            "cmp {backup_irql:r}, 2",
            "jge 2f",
            "mov cr8, {backup_irql:r}",
            "2:",
            backup_irql = in(reg) backup_irql
        );
    }

    if vmexit_type == VmExitType::ExitHypervisor {
        unsafe {
            cr3_write(vcpu.guest_vmcb.state_save_area.cr3);

            // load guest state
            vmload(virt_to_phys(&raw const vcpu.guest_vmcb as *const _ as usize) as _);

            // set the global interrupt flag (GIF), but still disable interrupts by
            // clearing IF. GIF must be set to return to the normal execution, but
            // interruptions are unwanted untill SVM is disabled as it would
            // execute random kernel-code in the host context.
            asm!("cli");
            stgi();

            // disable svm and restore the guest rflags
            // this may enable interrupts
            wrmsr(IA32_EFER, rdmsr(IA32_EFER) & !(1 << 12));

            write_flags(vcpu.guest_vmcb.state_save_area.rflags);
        }

        //  RBX     : address to return
        //  RCX     : stack pointer to restore
        //  EDX:EAX : address of per processor data to be freed by the caller
        guest_registers.rax = (vcpu as *mut _ as u64) & (u32::MAX as u64);
        guest_registers.rbx = vcpu.guest_vmcb.control_area.next_rip;
        guest_registers.rcx = vcpu.guest_vmcb.state_save_area.rsp;
        guest_registers.rdx = (vcpu as *mut _ as u64) >> 32;

        return true;
    } else if vmexit_type == VmExitType::IncrementRIP {
        vcpu.advance_rip();
    }

    // update rax
    vcpu.guest_vmcb.state_save_area.rax = guest_registers.rax;

    false
}

#[unsafe(link_section = ".text")]
#[unsafe(naked)]
pub unsafe extern "system" fn vmenter(guest_vmcb_pa_ptr: &mut usize) {
    naked_asm!(
        // update stack pointer with host RSP
        "mov rsp, rcx",
        "3:",
        // load guest VMCB
        "mov rax, [rsp]", // guest_vmcb_pa
        "vmload rax",
        "vmrun rax",
        "vmsave rax",
        // allocate trap frame (KTRAP_FRAME_SIZE assumed const)
        "sub rsp, {0}",
        // --- PUSHAQ ---
        "push rax",
        "push rcx",
        "push rdx",
        "push rbx",
        "push -1",
        "push rbp",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // prepare parameters for handle_vmexit
        "mov rdx, rsp",                  // guest GPRs
        "mov rcx, [rsp + 8 * 18 + {0}]", // virtual CPU ptr
        // allocate space for volatile XMM registers
        "sub rsp, 0x80",
        "movaps [rsp + 0x20], xmm0",
        "movaps [rsp + 0x30], xmm1",
        "movaps [rsp + 0x40], xmm2",
        "movaps [rsp + 0x50], xmm3",
        "movaps [rsp + 0x60], xmm4",
        "movaps [rsp + 0x70], xmm5",
        // call vmexit handler
        "call {1}",
        // restore XMM registers
        "movaps xmm5, [rsp + 0x70]",
        "movaps xmm4, [rsp + 0x60]",
        "movaps xmm3, [rsp + 0x50]",
        "movaps xmm2, [rsp + 0x40]",
        "movaps xmm1, [rsp + 0x30]",
        "movaps xmm0, [rsp + 0x20]",
        "add rsp, 0x80",
        // check if handle_vmexit was successful (AL=0 continue, AL!=0 exit)
        "test al, al",
        // --- POPAQ ---
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",
        "pop rbx", // one duplicate for alignment
        "pop rdx",
        "pop rcx",
        "pop rax",
        // check if we should exit
        "jnz 2f",
        "add rsp, {0}",
        "jmp 3b",
        "2:", // vmexit
        "mov rsp, rcx",
        "jmp rbx",
        const KTRAP_FRAME_SIZE,
        sym handle_vmexit,
    );
}
