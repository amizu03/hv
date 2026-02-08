use alloc::string::{String, ToString};
use core::{
    arch::asm,
    fmt::{Display, Formatter},
    marker::PhantomData,
    mem::{transmute, transmute_copy},
    slice,
    sync::atomic::{AtomicUsize, Ordering},
};
use fmtools::fmt;
use static_assertions::const_assert;
use x86::dtables::{lidt, DescriptorTablePointer};

use crate::{hash::hash, offsets};

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;
pub const PAGE_WRITECOMBINE: u32 = 0x400;
pub const PAGE_ENCLAVE_THREAD_CONTROL: u32 = 0x80000000;
pub const PAGE_REVERT_TO_FILE_MAP: u32 = 0x80000000;
pub const PAGE_TARGETS_NO_UPDATE: u32 = 0x40000000;
pub const PAGE_TARGETS_INVALID: u32 = 0x40000000;
pub const PAGE_ENCLAVE_UNVALIDATED: u32 = 0x20000000;
pub const PAGE_ENCLAVE_DECOMMIT: u32 = 0x10000000;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_DECOMMIT: u32 = 0x4000;
pub const MEM_RELEASE: u32 = 0x8000;
pub const MEM_FREE: u32 = 0x10000;
pub const MEM_PRIVATE: u32 = 0x20000;
pub const MEM_MAPPED: u32 = 0x40000;
pub const MEM_IMAGE: u32 = 0x1000000;
pub const MEM_RESET: u32 = 0x80000;
pub const MEM_TOP_DOWN: u32 = 0x100000;
pub const MEM_WRITE_WATCH: u32 = 0x200000;
pub const MEM_PHYSICAL: u32 = 0x400000;
pub const MEM_ROTATE: u32 = 0x800000;
pub const MEM_DIFFERENT_IMAGE_BASE_OK: u32 = 0x800000;
pub const MEM_RESET_UNDO: u32 = 0x1000000;
pub const MEM_LARGE_PAGES: u32 = 0x20000000;
pub const MEM_4MB_PAGES: u32 = 0x80000000;
pub const MEM_64K_PAGES: u32 = MEM_LARGE_PAGES | MEM_PHYSICAL;

unsafe extern "C" {
    #[link_name = "llvm.returnaddress"]
    pub fn return_address(a: i32) -> *const usize;
    #[link_name = "llvm.addressofreturnaddress"]
    pub fn address_of_return_address() -> *mut usize;
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct MachineFrame {
    pub rip: usize,
    pub seg_cs: usize,
    pub eflags: usize,
    pub rsp: usize,
    pub seg_ss: usize,
}

const_assert!(size_of::<MachineFrame>() == 0x28);

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KTrapFrame {
    pub p1home: usize, // 0x0
    pub p2home: usize, // 0x8
    pub p3home: usize, // 0x10
    pub p4home: usize, // 0x18
    pub p5: usize,     // 0x20

    // Union 1 (PreviousMode or InterruptRetpolineState)
    pub previous_mode: u8, // 0x28
    // pub interrupt_retpoline_state: u8, // 0x28
    pub previous_irql: u8, // 0x29

    // Union 2 (FaultIndicator or NmiMsrIbrs)
    // pub fault_indicator: u8, // 0x2a
    pub nmi_msr_ibrs: u8, // 0x2a

    pub exception_active: u8, // 0x2b
    pub mxcsr: u32,           // 0x2c

    pub rax: usize, // 0x30
    pub rcx: usize, // 0x38
    pub rdx: usize, // 0x40
    pub r8: usize,  // 0x48
    pub r9: usize,  // 0x50
    pub r10: usize, // 0x58
    pub r11: usize, // 0x60

    // Union 3 (GsBase or GsSwap)
    pub gs: usize, // 0x68
    // pub gs_swap: u64, // 0x68

    // XMM registers
    pub xmm0: f128, // 0x70
    pub xmm1: f128, // 0x80
    pub xmm2: f128, // 0x90
    pub xmm3: f128, // 0xa0
    pub xmm4: f128, // 0xb0
    pub xmm5: f128, // 0xc0

    // Union 4 (FaultAddress or ContextRecord)
    // pub fault_address: u64,  // 0xd0
    pub context_record: u64, // 0xd0

    // Union 5 (Dr0-Dr7 or ShadowStackFrame)
    pub dr0: usize, // 0xd8
    pub dr1: usize, // 0xe0
    pub dr2: usize, // 0xe8
    pub dr3: usize, // 0xf0
    pub dr6: usize, // 0xf8
    pub dr7: usize, // 0x100

    // Shadow Stack Frame and spare
    // pub shadow_stack_frame: u64, // 0xd8
    // pub spare: [u64; 5],         // 0xe0
    pub debug_control: usize,           // 0x108
    pub last_branch_to_rip: usize,      // 0x110
    pub last_branch_from_rip: usize,    // 0x118
    pub last_exception_to_rip: usize,   // 0x120
    pub last_exception_from_rip: usize, // 0x128

    pub seg_ds: u16, // 0x130
    pub seg_es: u16, // 0x132
    pub seg_fs: u16, // 0x134
    pub seg_gs: u16, // 0x136

    pub trap_frame: usize, // 0x138

    // Union 6 (NmiPreviousSpecCtrl or Rbx)
    // pub nmi_previous_spec_ctrl: u32,     // 0x140
    // pub nmi_previous_spec_ctrl_pad: u32, // 0x144
    pub rbx: usize, // 0x140

    pub rdi: usize, // 0x148
    pub rsi: usize, // 0x150
    pub rbp: usize, // 0x158

    // Union 7 (ErrorCode or ExceptionFrame)
    pub error_code: usize, // 0x160
    // pub exception_frame: u64, // 0x160
    pub mach: MachineFrame, // 0x168
}

const_assert!(size_of::<KTrapFrame>() == 0x190);

impl KTrapFrame {
    pub fn home(&mut self) -> &mut [usize; 5] {
        unsafe { transmute(&mut self.p1home) }
    }
    pub fn regs(&mut self) -> &mut [usize; 7] {
        unsafe { transmute(&mut self.rax) }
    }
    pub fn dregs(&mut self) -> &mut [usize; 6] {
        unsafe { transmute(&mut self.dr0) }
    }
    pub fn reserved_regs(&mut self) -> &mut [usize; 4] {
        unsafe { transmute(&mut self.rbx) }
    }
    pub fn branches(&mut self) -> &mut [usize; 4] {
        unsafe { transmute(&mut self.last_branch_to_rip) }
    }
    pub fn xmm(&mut self) -> &mut [f128; 6] {
        unsafe { transmute(&mut self.xmm0) }
    }
}

const_assert!(size_of::<KTrapFrame>() == 0x190);

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct PhysMemRange {
    pub start: usize,
    pub size: usize,
}

// Converts VA in current address space to the PTE VA
pub fn address_to_pte(va: usize) -> *mut usize {
    let pte_table_base = unsafe {
        ((Module::nt().base + offsets::ntoskrnl::sigs::PteTableBase) as *const usize)
            .read_unaligned()
    };

    // (((va >> 9) & 0x7ffffffff8).wrapping_sub(0x98000000000)) as *mut u64
    ((va >> 9) & 0x7FFFFFFFF8).wrapping_add(pte_table_base) as *mut usize
}

// Converts PTE address to VA in current address space
pub fn virtual_address_mapped_by_pte(pte: *const usize) -> usize {
    let pte_table_base = unsafe {
        ((Module::nt().base + offsets::ntoskrnl::sigs::PteTableBase) as *const usize)
            .read_unaligned()
    };

    ((((pte as usize as isize) - (pte_table_base as isize)) << 25) >> 16) as usize
}

// Gets the PFN entry pointer of a PFN in the PFN database (should return *mut MMPFN)
#[inline(always)]
pub fn pfn_to_pfn_entry_address(pfn: usize) -> usize {
    let mm_pfn_database = (Module::nt().base + offsets::ntoskrnl::MmPfnDatabase) as *const usize;
    let mm_pfn_database = unsafe { *mm_pfn_database };

    /* sigs::MM_PFN_DATABASE */
    mm_pfn_database + 0x30 /*sizeof(MMPFN)*/ * pfn
}

#[inline(always)]
pub fn phys_to_virt(physical_address: usize) -> usize {
    unsafe {
        let pte_table_base = unsafe {
            ((Module::nt().base + offsets::ntoskrnl::sigs::PteTableBase) as *const usize)
                .read_unaligned()
        };
        let pte_table_base_block = unsafe {
            ((Module::nt().base + offsets::ntoskrnl::sigs::PteTableBaseBlock) as *const usize)
                .read_unaligned()
        };

        let v1 = physical_address >> 12;
        let mut v2 = v1 + v1 * 2;

        v2 += v2;

        let v3 = *((pte_table_base_block + v2 * 8) as *const usize) << 0x19;

        let v4 = pte_table_base << 0x19;

        (((v3 - v4) as isize) >> 0x10) as usize + (physical_address & 0xFFF)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MemoryType {
    Uncacheable = 0,
    WriteCombining = 1,
    WriteThrough = 4,
    WriteProtected = 5,
    WriteBack = 6,
}

#[inline(always)]
pub fn initialize_pte(
    pfn: usize,
    usermode_or_supervisor: bool,
    writable: bool,
    executable: bool,
    large_page: bool,
    // memory_type: Option<MemoryType>,
) -> usize {
    let mut pte = 0usize;

    // set protection
    if writable {
        pte |= 1 << 1;
    }

    if !executable {
        pte |= 1 << 63;
    }

    if usermode_or_supervisor {
        pte |= 1 << 2;
    }

    if large_page {
        pte |= 1 << 7;
    }

    // Memory type (bits 5:3)
    // if let Some(mt) = memory_type {
    //     pte |= (mt as usize) << 3;
    // }

    // set pfn
    pte |= pfn << 12;

    // set valid
    pte |= 1;

    pte
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct RtlBitmap {
    pub size: u32,
    pub buffer: usize,
}

#[inline(always)]
pub fn rtl_set_bits(bmp: &mut RtlBitmap, offset: usize, count: usize) {
    unsafe {
        let rtl_set_all_bits = transmute::<
            _,
            unsafe extern "system" fn(&mut RtlBitmap, usize, usize),
        >(Module::nt().base + offsets::ntoskrnl::RtlSetBits);

        rtl_set_all_bits(bmp, offset, count);
    }
}

#[inline(always)]
pub fn rtl_set_all_bits(bmp: &mut RtlBitmap, offset: usize, count: usize) {
    unsafe {
        let rtl_set_all_bits = transmute::<
            _,
            unsafe extern "system" fn(&mut RtlBitmap, usize, usize),
        >(Module::nt().base + offsets::ntoskrnl::RtlSetAllBits);

        rtl_set_all_bits(bmp, offset, count);
    }
}

#[inline(always)]
pub fn rtl_initialize_bitmap(bmp: &mut RtlBitmap, msr_permissions: *mut u32, size: usize) {
    unsafe {
        let rtl_initialize_bitmap =
            transmute::<_, unsafe extern "system" fn(&mut RtlBitmap, *mut u32, usize)>(
                Module::nt().base + offsets::ntoskrnl::RtlInitializeBitMap,
            );

        rtl_initialize_bitmap(bmp, msr_permissions, size);
    }
}

#[inline(always)]
pub fn rtl_clear_all_bits(bmp: &mut RtlBitmap) {
    unsafe {
        let rtl_clear_all_bits = transmute::<_, unsafe extern "system" fn(&mut RtlBitmap)>(
            Module::nt().base + offsets::ntoskrnl::RtlClearAllBits,
        );

        rtl_clear_all_bits(bmp);
    }
}

#[inline(always)]
pub fn is_address_valid(virt_address: usize) -> bool {
    unsafe {
        let mm_is_address_valid = transmute::<_, unsafe extern "system" fn(usize) -> bool>(
            Module::nt().base + offsets::ntoskrnl::MmIsAddressValid,
        );

        mm_is_address_valid(virt_address)
    }
}

#[inline(always)]
pub fn virt_to_phys(virt_address: usize) -> usize {
    unsafe {
        let ke_entered_debugger =
            (Module::nt().base + offsets::ntoskrnl::KdEnteredDebugger) as *mut u32;
        let mm_get_physical_address = transmute::<_, unsafe extern "system" fn(usize) -> usize>(
            Module::nt().base + offsets::ntoskrnl::MmGetPhysicalAddress,
        );

        let backup_ke_entered_debugger = *ke_entered_debugger;
        // return early in MiQueuePinDriverAddressLog
        *ke_entered_debugger = 0x1;
        let pa = mm_get_physical_address(virt_address);
        *ke_entered_debugger = backup_ke_entered_debugger;
        pa
    }
}

pub fn phys_mem_ranges() -> *const PhysMemRange {
    unsafe {
        let mm_get_physical_memory_ranges =
            transmute::<_, unsafe extern "system" fn() -> *const PhysMemRange>(
                Module::nt().base + offsets::ntoskrnl::MmGetPhysicalMemoryRanges,
            );

        mm_get_physical_memory_ranges()
    }
}

#[repr(transparent)]
#[derive(Default, Debug)]
pub struct IndependentPages<const N: usize> {
    pub alloc: usize,
}

impl<const N: usize> IndependentPages<N> {
    pub fn free(&mut self) {
        unsafe {
            transmute::<_, unsafe extern "system" fn(usize, usize)>(
                Module::nt().base + offsets::ntoskrnl::MmFreeIndependentPages,
            )(self.alloc, N << PAGE_SHIFT);

            self.alloc = 0;
        }
    }

    pub fn zero(&self) {
        unsafe {
            core::ptr::write_bytes(self.alloc as *mut u8, 0, N << PAGE_SHIFT);
        }
    }

    pub fn leak<T>(mut self) -> &'static mut T {
        let ret = self.alloc;
        self.alloc = 0;
        unsafe { transmute(ret) }
    }

    /// Try to allocate pages, returning a zero alloc on failure instead of aborting
    #[inline(always)]
    pub fn new(write: bool, execute: bool) -> Self {
        let alloc = unsafe {
            transmute::<_, unsafe extern "system" fn(usize, usize, usize, usize) -> usize>(
                Module::nt().base + offsets::ntoskrnl::MmAllocateIndependentPagesEx,
            )(N << PAGE_SHIFT, usize::MAX, 0, 0)
        };

        // Don't abort - let caller check for allocation failure
        if alloc == 0 {
            return Self { alloc: 0 };
        }

        unsafe {
            transmute::<_, unsafe extern "system" fn(usize, usize, u32, usize) -> *mut u8>(
                Module::nt().base + offsets::ntoskrnl::MmSetPageProtection,
            )(
                alloc,
                N << PAGE_SHIFT,
                if write {
                    if execute {
                        PAGE_EXECUTE_READWRITE
                    } else {
                        PAGE_READWRITE
                    }
                } else {
                    PAGE_READONLY
                },
                0,
            );
        }

        Self { alloc }
    }

    /// Check if allocation succeeded
    pub fn is_valid(&self) -> bool {
        self.alloc != 0
    }
}

impl<const N: usize> Drop for IndependentPages<N> {
    fn drop(&mut self) {
        if self.alloc != 0 {
            unsafe {
                transmute::<_, unsafe extern "system" fn(usize, usize)>(
                    Module::nt().base + offsets::ntoskrnl::MmFreeIndependentPages,
                )(self.alloc, N << PAGE_SHIFT);
            }
        }
    }
}

#[inline(always)]
pub fn free_independent_pages(base: usize, size: usize) -> isize {
    unsafe {
        transmute::<_, unsafe extern "system" fn(usize, usize) -> isize>(
            Module::nt().base + offsets::ntoskrnl::MmFreeIndependentPages,
        )(base, size)
    }
}

#[inline(always)]
pub fn set_system_affinity_thread(affinity: usize) -> usize {
    unsafe {
        let f = transmute::<_, unsafe extern "system" fn(usize) -> usize>(
            Module::nt().base + offsets::ntoskrnl::KeSetSystemAffinityThreadEx,
        );

        f(affinity)
    }
}

#[inline(always)]
pub fn set_system_group_affinity_thread(
    affinity: &mut GroupAffinity,
    previous_affinity: &mut GroupAffinity,
) {
    unsafe {
        let f = transmute::<_, unsafe extern "system" fn(&mut GroupAffinity, &mut GroupAffinity)>(
            Module::nt().base + offsets::ntoskrnl::KeSetSystemGroupAffinityThread,
        );

        f(affinity, previous_affinity);
    }
}

#[inline(always)]
pub fn revert_to_user_affinity_thread(affinity: usize) {
    unsafe {
        let f = transmute::<_, unsafe extern "system" fn(usize)>(
            Module::nt().base + offsets::ntoskrnl::KeRevertToUserAffinityThreadEx,
        );

        f(affinity);
    }
}

#[inline(always)]
pub fn revert_to_user_group_affinity_thread(affinity: &mut GroupAffinity) {
    unsafe {
        let f = transmute::<_, unsafe extern "system" fn(&mut GroupAffinity)>(
            Module::nt().base + offsets::ntoskrnl::KeRevertToUserGroupAffinityThread,
        );

        f(affinity);
    }
}

#[inline(always)]
pub fn processor_from_index(num: usize) -> Option<ProcessorNumber> {
    unsafe {
        let mut nproc = ProcessorNumber::default();
        let f = transmute::<_, unsafe extern "system" fn(usize, &mut ProcessorNumber) -> isize>(
            Module::nt().base + offsets::ntoskrnl::KeGetProcessorNumberFromIndex,
        );

        if f(num, &mut nproc) != 0 {
            None
        } else {
            Some(nproc)
        }
    }
}

#[inline(always)]
pub fn ke_yield_execution() {
    unsafe {
        let f = transmute::<_, unsafe extern "system" fn(i32)>(
            Module::nt().base + offsets::ntoskrnl::KeYieldExecution,
        );

        f(0);
    }
}

#[inline(always)]
pub fn current_processor_number() -> u32 {
    unsafe {
        let f = transmute::<_, unsafe extern "system" fn(usize) -> u32>(
            Module::nt().base + offsets::ntoskrnl::KeGetCurrentProcessorNumberEx,
        );

        f(0)
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct XsaveFormat {
    pub control_word: u16,
    pub status_word: u16,
    pub tag_word: u8,
    pub reserved1: u8,
    pub error_opcode: u16,
    pub error_offset: u32,
    pub error_selector: u16,
    pub reserved2: u16,
    pub data_offset: u32,
    pub data_selector: u16,
    pub reserved3: u16,
    pub mx_csr: u32,
    pub mx_csr_mask: u32,
    pub float_registers: [f128; 8],
    pub xmm_registers: [f128; 16],
    pub reserved4: [u8; 96],
}
const_assert!(size_of::<XsaveFormat>() == 512);

#[repr(C)]
#[derive(Copy, Clone)]
pub union ContextFltSave {
    pub flt_save: XsaveFormat,
    // pub s: ContextFltSaveInner,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct ContextFltSaveInner {
    pub header: [f128; 2],
    pub legacy: [f128; 8],
    pub xmm0: f128,
    pub xmm1: f128,
    pub xmm2: f128,
    pub xmm3: f128,
    pub xmm4: f128,
    pub xmm5: f128,
    pub xmm6: f128,
    pub xmm7: f128,
    pub xmm8: f128,
    pub xmm9: f128,
    pub xmm10: f128,
    pub xmm11: f128,
    pub xmm12: f128,
    pub xmm13: f128,
    pub xmm14: f128,
    pub xmm15: f128,
}
const_assert!(size_of::<ContextFltSaveInner>() == 0x1A0);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Context {
    pub p1_home: u64,                 // 0x00
    pub p2_home: u64,                 // 0x08
    pub p3_home: u64,                 // 0x10
    pub p4_home: u64,                 // 0x18
    pub p5_home: u64,                 // 0x20
    pub p6_home: u64,                 // 0x28
    pub context_flags: u32,           // 0x30
    pub mx_csr: u32,                  // 0x34
    pub seg_cs: u16,                  // 0x38
    pub seg_ds: u16,                  // 0x3A
    pub seg_es: u16,                  // 0x3C
    pub seg_fs: u16,                  // 0x3E
    pub seg_gs: u16,                  // 0x40
    pub seg_ss: u16,                  // 0x42
    pub eflags: u32,                  // 0x44
    pub dr0: u64,                     // 0x48
    pub dr1: u64,                     // 0x50
    pub dr2: u64,                     // 0x58
    pub dr3: u64,                     // 0x60
    pub dr6: u64,                     // 0x68
    pub dr7: u64,                     // 0x70
    pub rax: u64,                     // 0x78
    pub rcx: u64,                     // 0x80
    pub rdx: u64,                     // 0x88
    pub rbx: u64,                     // 0x90
    pub rsp: u64,                     // 0x98
    pub rbp: u64,                     // 0xA0
    pub rsi: u64,                     // 0xA8
    pub rdi: u64,                     // 0xB0
    pub r8: u64,                      // 0xB8
    pub r9: u64,                      // 0xC0
    pub r10: u64,                     // 0xC8
    pub r11: u64,                     // 0xD0
    pub r12: u64,                     // 0xD8
    pub r13: u64,                     // 0xE0
    pub r14: u64,                     // 0xE8
    pub r15: u64,                     // 0xF0
    pub rip: u64,                     // 0xF8
    pub flt_save: XsaveFormat,        // 0x100
    pub vector_register: [f128; 26],  // 0x300
    pub vector_control: u64,          // 0x4A0
    pub debug_control: u64,           // 0x4A8
    pub last_branch_to_rip: u64,      // 0x4B0
    pub last_branch_from_rip: u64,    // 0x4B8
    pub last_exception_to_rip: u64,   // 0x4C0
    pub last_exception_from_rip: u64, // 0x4C8
}

impl Default for Context {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

const_assert!(size_of::<Context>() == 0x4D0);

impl Context {
    #[inline(always)]
    pub fn capture(&mut self) {
        unsafe {
            let rtl_capture_context = transmute::<_, unsafe extern "system" fn(&mut Self)>(
                Module::nt().base + offsets::ntoskrnl::RtlCaptureContext,
            );

            rtl_capture_context(self);
        }
    }
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct ProcessorNumber {
    pub group: u16,
    pub number: u8,
    pub reserved: u8,
}

#[repr(C, align(0x10))]
#[derive(Default, Copy, Clone)]
pub struct GroupAffinity {
    pub mask: usize,
    pub group: u16,
    pub reserved: [u16; 3],
}

#[inline(always)]
pub fn page_align(x: usize) -> usize {
    x & !0xFFF
}

pub extern "system" fn create_thread(func: *const (), ctx: usize) -> usize {
    unsafe {
        let mut backup_irql: u32 = 0;

        unsafe {
            asm!(
                "mov {backup_irql:r}, cr8",
                "xor rax, rax",
                "mov cr8, rax",
                backup_irql = out(reg) backup_irql
            );
        }

        let f = transmute::<
            _,
            unsafe extern "system" fn(&mut usize, usize, usize, usize, usize, *const (), usize),
        >(Module::nt().base + offsets::ntoskrnl::PsCreateSystemThread);

        let mut thread_handle: usize = 0;
        f(
            &mut thread_handle,
            0xF0000 | 0x100000 | 0xFFFF,
            0,
            0,
            0,
            func,
            ctx,
        );

        unsafe {
            asm!("mov cr8, {backup_irql:r}", backup_irql = in(reg) backup_irql);
        }

        thread_handle
    }
}

pub fn active_processor_count() -> u32 {
    unsafe {
        ((Module::nt().base + offsets::ntoskrnl::KeNumberProcessors) as *const u32).read_unaligned()
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct Module<'a> {
    pub base: usize,
    _lifetime: PhantomData<&'a ()>,
}

#[inline(always)]
pub fn time() -> u64 {
    unsafe { *(0xFFFFF78000000014 as *const u64) }
}

#[repr(C)]
#[derive(Debug)]
pub struct ListEntry<'a, T, const CONTAINING_RECORD_OFFSET: usize> {
    pub flink: *mut ListEntry<'a, T, CONTAINING_RECORD_OFFSET>,
    pub blink: *mut ListEntry<'a, T, CONTAINING_RECORD_OFFSET>,
    _phantom: PhantomData<&'a T>,
}

pub struct ListIterator<'a, T, const CONTAINING_RECORD_OFFSET: usize> {
    list_head: *const ListEntry<'a, T, CONTAINING_RECORD_OFFSET>,
    current: *const ListEntry<'a, T, CONTAINING_RECORD_OFFSET>,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T, const CONTAINING_RECORD_OFFSET: usize> IntoIterator
    for &ListEntry<'a, T, CONTAINING_RECORD_OFFSET>
{
    type Item = &'a T;
    type IntoIter = ListIterator<'a, Self::Item, CONTAINING_RECORD_OFFSET>;

    fn into_iter(self) -> Self::IntoIter {
        unsafe {
            Self::IntoIter {
                list_head: transmute(self as *const _),
                current: transmute(self as *const _),
                _phantom: PhantomData,
            }
        }
    }
}

impl<'a, T, const CONTAINING_RECORD_OFFSET: usize> Iterator
    for ListIterator<'a, T, CONTAINING_RECORD_OFFSET>
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.current = unsafe { (*self.current).flink };

        // reached end of list (loopback to head)
        if self.current.is_null() || self.current == self.list_head {
            None
        } else {
            Some(unsafe {
                transmute_copy::<usize, T>(&(self.current.addr() - CONTAINING_RECORD_OFFSET))
            })
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KLdrEntry<'a> {
    pad: [u8; 0x30],
    pub dll_base: usize,
    pub entry_point: usize,
    pub size_of_image: u32,
    pub full_dll_name: UnicodeString<'a>,
    pub base_dll_name: UnicodeString<'a>,
    pub flags: u32,
    pub load_count: u16,
    pub signature_flags: u16,
    pub section_pointer: usize,
    pub check_sum: u32,
    pad1: [u8; 0x20],
    pub time_date_stamp: u32,
}

pub type ApcState = [u8; 0x30];

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UnicodeString<'a> {
    pub length: u16,         // 0x0
    pub maximum_length: u16, // 0x2
    pub buffer: *const u16,  // 0x8
    _lifetime: PhantomData<&'a ()>,
}

impl UnicodeString<'_> {
    #[inline(always)]
    #[optimize(speed)]
    pub fn as_slice(&self) -> Option<&[u16]> {
        if self.buffer.is_null() || self.length == 0 {
            None
        } else {
            Some(unsafe {
                core::slice::from_raw_parts(
                    self.buffer as *const u16,
                    self.length as usize / core::mem::size_of::<u16>(),
                )
            })
        }
    }

    #[inline(always)]
    #[optimize(speed)]
    pub unsafe fn free(self) {
        let buffer_ptr = self.buffer;

        if buffer_ptr.is_null() {
            return;
        }

        for b in self.buffer as usize..(self.buffer as usize + self.maximum_length as usize) {
            unsafe { *(b as *mut u8) = 0 };
        }

        unsafe {
            transmute::<_, unsafe extern "system" fn(*mut u8, u32)>(
                Module::nt().base + offsets::ntoskrnl::ExFreePoolWithTag,
            )(buffer_ptr as _, 0)
        };
    }

    #[inline(always)]
    #[optimize(speed)]
    fn wide_to_lower(wide_char: u16) -> u16 {
        if wide_char >= 97 && wide_char <= 122 {
            wide_char - 32
        } else {
            wide_char
        }
    }

    #[inline(always)]
    #[optimize(speed)]
    pub fn contains(&self, other: &UnicodeString, case_insensitive: bool) -> bool {
        let this = match self.as_slice() {
            Some(x) => x,
            None => return false,
        };

        let other = match other.as_slice() {
            Some(x) => x,
            None => return false,
        };

        for i in 0..this.len() {
            for j in 0..other.len() {
                if i + j >= this.len() {
                    return false;
                }

                let lower1 = if case_insensitive {
                    Self::wide_to_lower(this[i + j])
                } else {
                    this[i + j]
                };

                let lower2 = if case_insensitive {
                    Self::wide_to_lower(other[j])
                } else {
                    other[j]
                };

                if lower1 != lower2 {
                    break;
                }

                if j == other.len() - 1 {
                    return true;
                }
            }
        }

        false
    }
}

impl<'a> From<&'a [u16]> for UnicodeString<'a> {
    fn from(value: &[u16]) -> Self {
        let len_bytes = size_of_val(value) as u16;

        Self {
            length: len_bytes,
            maximum_length: len_bytes,
            buffer: value.as_ptr(),
            _lifetime: PhantomData,
        }
    }
}

impl<'a, const N: usize> From<&'a [u16; N]> for UnicodeString<'a> {
    fn from(value: &'a [u16; N]) -> Self {
        Self {
            length: N as u16 * 2,
            maximum_length: N as u16 * 2,
            buffer: value.as_ptr(),
            _lifetime: PhantomData,
        }
    }
}

impl Display for UnicodeString<'_> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        let view =
            unsafe { slice::from_raw_parts(self.buffer, self.length as usize / size_of::<u16>()) };
        if let Ok(s) = String::from_utf16(view) {
            f.write_str(&s)
        } else {
            f.write_str(&fmt!("Invalid UTF-16 string: 0x"{self.buffer as usize:X}).to_string())
        }
    }
}

#[macro_export]
macro_rules! ucs16 {
    ($s: expr) => {{
        let ws = obfstr::obfwide!($s);
        $crate::wdk::UnicodeString::from(&ws[..])
    }};
}

const_assert!(size_of::<UnicodeString>() == 0x10);

pub const PTES_PER_PAGE: usize = 0x200;
pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SIZE: usize = (1 << PAGE_SHIFT); // same as 0x1000
pub const PAGE_SIZE_2MB: usize = 0x200000;
pub const PAGE_SIZE_1GB: usize = 0x40000000;
pub const PFN_MASK: usize = 0xFFFFFFFFFFF000;
pub const LARGE_PFN_MASK: usize = 0xFFFFFFE00000;
pub const HUGE_PFN_MASK: usize = 0xFFFFC0000000;

#[derive(Debug)]
pub struct HeaderView<'a> {
    pub dos: *const u8,
    pub nt: *const u8,
    pub optional64: *const u8,
    pub _phantom: PhantomData<&'a ()>,
}

#[repr(C)] // Ensures the layout is compatible with C structs
pub struct ImageSectionHeader {
    pub name: [u8; 8],               // 0x0
    pub physical_address: u32,       // 0x8
    pub virtual_address: u32,        // 0xc
    pub size_of_raw_data: u32,       // 0x10
    pub pointer_to_raw_data: u32,    // 0x14
    pub pointer_to_relocations: u32, // 0x18
    pub pointer_to_linenumbers: u32, // 0x1c
    pub number_of_relocations: u16,  // 0x20
    pub number_of_linenumbers: u16,  // 0x22
    pub characteristics: u32,        // 0x24
}

impl<'a> HeaderView<'a> {
    pub fn size_of_optional_header(&self) -> u16 {
        unsafe { (self.nt.add(0x4 + 0x10) as *const u16).read_unaligned() }
    }

    pub fn number_of_sections(&self) -> u16 {
        unsafe { (self.nt.add(0x4 + 0x2) as *const u16).read_unaligned() }
    }

    pub fn sections(&self) -> &[ImageSectionHeader] {
        unsafe {
            let ptr = self.nt.add(0x18 + self.size_of_optional_header() as usize);

            core::slice::from_raw_parts(
                ptr as *const ImageSectionHeader,
                self.number_of_sections() as usize,
            )
        }
    }

    pub fn entry_point(&self) -> usize {
        self.dos as usize
            + unsafe { (self.optional64.add(0x10) as *const u32).read_unaligned() as usize }
    }

    pub fn size_of_code(&self) -> usize {
        unsafe { (self.optional64.add(0x4) as *const u32).read_unaligned() as usize }
    }

    pub fn base_of_code(&self) -> usize {
        self.dos as usize
            + unsafe { (self.optional64.add(0x14) as *const u32).read_unaligned() as usize }
    }

    pub fn code(&self) -> &'a [u8] {
        unsafe { slice::from_raw_parts(self.base_of_code() as *const u8, self.size_of_code()) }
    }
}

static NT: AtomicUsize = AtomicUsize::new(0);

impl Module<'_> {
    #[inline(always)]
    pub fn list() -> ListIterator<'static, &'static KLdrEntry<'static>, 0x0> {
        unsafe {
            transmute::<_, &ListEntry<KLdrEntry, 0x0>>(
                Module::nt().base + offsets::ntoskrnl::PsLoadedModuleList,
            )
            .into_iter()
        }
    }

    #[inline(always)]
    pub fn by_name<'a, UCS: Into<UnicodeString<'a>>>(name: UCS) -> Option<Module<'a>> {
        let name = name.into();
        let m = Self::list().find(|m| m.base_dll_name.contains(&name, true))?;
        Some(Module {
            base: m.dll_base,
            _lifetime: PhantomData,
        })
    }

    #[inline(always)]
    pub fn by_hash<'a>(name_hash: u32) -> Option<Module<'a>> {
        let m = Self::list().find(|m| {
            m.base_dll_name.as_slice().map_or(false, |x| {
                hash(unsafe { core::slice::from_raw_parts(x.as_ptr() as *const u8, x.len() * 2) })
                    == name_hash
            })
        })?;

        Some(Module {
            base: m.dll_base,
            _lifetime: PhantomData,
        })
    }

    #[inline(always)]
    pub fn init() {
        if offsets::modules::NTOSKRNL == 0 {
            NT.store(Self::find_nt().base, Ordering::Relaxed);
        }
    }

    #[inline(always)]
    pub fn nt() -> Module<'static> {
        Module {
            base: if offsets::modules::NTOSKRNL != 0 {
                offsets::modules::NTOSKRNL
            } else {
                NT.load(Ordering::Relaxed)
            },
            _lifetime: PhantomData,
        }
    }

    // finds kernel base address using syscall handler MSR
    // on release builds, can hardcode to some const containing the kernel base, so that
    // addresses are baked-in at compile time
    #[inline(always)]
    pub fn find_nt() -> Module<'static> {
        let mut address_in_text_section = unsafe { x86::msr::rdmsr(0xC0000082) as usize };
        // goldberg_stmts! {
        unsafe {
            const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
            const PAGELK: u64 = 0x4B4C45474150;
            const MEGABYTE: usize = 1 << 20;
            const MEGABYTE2: usize = MEGABYTE * 2;

            // let mut address_in_text_section = syscall_handler();
            let gs_offset = ((address_in_text_section + 0x8) as *const u32).read_unaligned();
            let syscall_has_shadow = gs_offset > PAGE_SIZE as u32;

            // KiSystemCall64Shadow	is in KVASCODE section,
            // so we search for next available function in .text
            // note that this should also work on KiSystemCall64 as well since the same instruction sequence is in there
            if syscall_has_shadow {
                // search forward for instructions:
                // lfence
                // call .text:KiFlushBhbDuringTrapEntryOrExit

                for x in address_in_text_section..address_in_text_section + 0x400 {
                    if (x as *const u32).read_unaligned() == 0xE8E8AE0F
                        || (x as *const u32).read_unaligned() == 0xE8057400
                        || (x as *const u32).read_unaligned() == 0xE9000000
                    {
                        let rva = ((x + 0x4) as *const i32).read_unaligned();
                        address_in_text_section = (x + 0x8).wrapping_add_signed(rva as _);
                        break;
                    }
                }
            }

            // align address to 2MB boundary (kernel is 2MB address-aligned)
            address_in_text_section &= !(MEGABYTE2 - 1);

            loop {
                if *(address_in_text_section as *const u16) == IMAGE_DOS_SIGNATURE {
                    for x in (address_in_text_section..address_in_text_section + 0x400).step_by(0x8)
                    {
                        if *(x as *const u64) == PAGELK {
                            return Module {
                                base: address_in_text_section,
                                _lifetime: PhantomData,
                            };
                        }
                    }
                }

                address_in_text_section -= MEGABYTE2;
            }
        }
    }

    pub fn headers(&self) -> Option<HeaderView<'_>> {
        unsafe {
            let dos = self.base as *const u8;

            if (dos as *const u16).read_unaligned() != 0x5A4D {
                return None;
            }

            let e_lfanew = (dos.add(0x3C) as *const u32).read_unaligned() as usize;

            if (dos.add(e_lfanew) as *const u16).read_unaligned() != 0x4550
                || (dos.add(e_lfanew + 0x4) as *const u16).read_unaligned() != 0x8664
            {
                return None;
            }

            let nt = dos.add(e_lfanew);
            let optional64 = nt.add(0x18);

            if (optional64 as *const u16).read_unaligned() != 0x20B {
                return None;
            }

            Some(HeaderView {
                dos,
                nt,
                optional64,
                _phantom: PhantomData,
            })
        }
    }

    pub fn ki_system_service_copy(&self) -> Option<&[u8]> {
        let last_pair = self
            .headers()?
            .code()
            .into_iter()
            .array_chunks::<4>()
            .array_chunks::<2>()
            .scan(0, |state, x| {
                // instructions have same mov prefix
                if *x[0][0] == 0x48 && *x[1][0] == 0x48
                // instructions both have same mov offset
                && *x[0][3] == *x[1][3]
                {
                    // Increment match count, found an instruction pair
                    *state += 1;
                } else {
                    // reset search
                    *state = 0;
                }
                Some((*state, x))
            })
            // KiSystemServiceCopyStart has 14 frames total
            .find(|&(hits, _)| hits >= 14)?; // Stop once 3 hits are reached

        let end = last_pair.1[1].as_ptr() as usize + last_pair.1[1].len();
        let len_bytes = (last_pair.0 * 2) * 0x4;
        let start = end - len_bytes;

        Some(unsafe { slice::from_raw_parts(start as *const u8, len_bytes) })
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct GDTEntry {
    pub limit_low: u16,    // 0x0
    pub base_low: u16,     // 0x2
    pub base_middle: u8,   // 0x4
    pub flags1: u8,        // 0x5
    pub flags2: u8,        // 0x6
    pub base_high: u8,     // 0x7
    pub base_upper: u32,   // 0x8
    pub must_be_zero: u32, // 0xC
}

impl GDTEntry {
    /// Returns the full 64-bit handler address encoded in the base fields.
    #[inline(always)]
    pub fn handler(&self) -> usize {
        let mut addr: u64 = 0;
        addr |= self.base_low as u64;
        addr |= (self.base_middle as u64) << 16;
        addr |= (self.base_high as u64) << 24;
        addr |= (self.base_upper as u64) << 32;
        addr as usize
    }

    /// Sets a new handler address and returns the old one.
    #[inline(always)]
    pub fn swap_handler(&mut self, new_addr: usize) -> usize {
        let old = self.handler();

        let addr = new_addr as u64;
        self.base_low = (addr & 0xFFFF) as u16;
        self.base_middle = ((addr >> 16) & 0xFF) as u8;
        self.base_high = ((addr >> 24) & 0xFF) as u8;
        self.base_upper = ((addr >> 32) & 0xFFFFFFFF) as u32;

        old
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct IDTEntry {
    pub offset_low: u16,  // bits 0–15
    pub selector: u16,    // code segment selector
    pub ist: u8,          // IST (bits 0–2)
    pub type_attr: u8,    // gate type, DPL, P
    pub offset_mid: u16,  // bits 16–31
    pub offset_high: u32, // bits 32–63
    pub reserved: u32,    // zero
}

impl IDTEntry {
    #[inline(always)]
    pub fn handler(&self) -> usize {
        (self.offset_low as usize)
            | ((self.offset_mid as usize) << 16)
            | ((self.offset_high as usize) << 32)
    }

    #[inline(always)]
    pub fn swap_handler(&mut self, new_addr: usize) -> usize {
        let old = self.handler();

        self.offset_low = (new_addr & 0xFFFF) as u16;
        self.offset_mid = ((new_addr >> 16) & 0xFFFF) as u16;
        self.offset_high = ((new_addr >> 32) & 0xFFFFFFFF) as u32;

        old
    }
}

pub fn abort() -> ! {
    unsafe {
        const RESET_PORT: u16 = 0x64;
        const RESET_COMMAND: u8 = 0xFE;

        // disable interrupts
        asm!("cli");

        // pulse cpu reset line
        asm!(
            "out dx, al",
            in("dx") RESET_PORT,
            in("al") RESET_COMMAND,
        );

        // trigger a triple fault
        // without handler to cause a triple fault (forces cpu reset)
        lidt(&DescriptorTablePointer::<IDTEntry>::default());

        asm!(
            // trigger breakpoint
            "int3",
            // create a divide by 0 fault
            "xor rdx, rdx",
            "div rdx",
        );

        // halt core if reset doesnt happen immediately
        loop {
            asm!("hlt");
        }
    }
}

#[inline(always)]
pub unsafe fn lsl(selector: u16) -> u32 {
    let mut limit: u32;

    unsafe {
        asm!(
            "lsl {limit:e}, {selector:e}",
            limit = out(reg) limit,
            selector = in(reg) selector,
            options(nostack, preserves_flags),
        );
    }

    limit
}

/// General Segment Descriptor (64-bit)
///
/// A segment descriptor is a data structure in a GDT or LDT that provides the processor with the size and location of a
/// segment, as well as access control and status information. Segment descriptors are typically created by compilers,
/// linkers, loaders, or the operating system or executive, but not application programs.
///
/// See Intel SDM Vol. 3A, Section 3.4.5 (Segment Descriptors)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SegmentDescriptor64 {
    /// Segment limit field (15:00)
    ///
    /// Specifies the size of the segment. The processor puts together the two segment limit fields to form a 20-bit value.
    pub segment_limit_low: u16,

    /// Base address field (15:00)
    ///
    /// Defines the location of byte 0 of the segment within the 4-GByte linear address space.
    pub base_address_low: u16,
    /// Access flags and upper bits of base/limit
    pub access: u32,
    /// Base address field (32:63)
    pub base_address_upper: u32,
    /// This field must be set to zero.
    pub must_be_zero: u32,
}

const RPL_MASK: u16 = 3;

pub fn segment_access_rights(segment_selector: u16, gdt_base: usize) -> u16 {
    let v2 = unsafe {
        ((gdt_base + 8 * (segment_selector as usize >> 3)) as *const u64).read_unaligned() >> 0x20
    };

    ((v2 >> 8) & 0xF
        | (16
            * ((v2 >> 12) & 1
                | (2 * ((v2 >> 13) & 3
                    | (4 * ((v2 >> 15) & 1
                        | (2 * ((v2 >> 20) & 1
                            | (2 * ((v2 >> 21) & 1
                                | (2 * ((v2 >> 22) & 1 | (2 * ((v2 >> 23) & 1)))))))))))))))
        as u16
}

pub fn segment_base(segment_selector: u16, gdt_base: usize) -> u64 {
    let ss = unsafe {
        ((gdt_base + 8 * (segment_selector as usize >> 3)) as *const SegmentDescriptor64)
            .read_unaligned()
    };

    let base_address_middle = ((ss.access >> 0) & 0xFF);
    let descriptor_type = ((ss.access >> 12) & 0x01);
    let base_address_high = ((ss.access >> 24) & 0xFF);

    let mut base_address = (ss.base_address_low as u64)
        | ((base_address_middle as u64) << 16)
        | ((base_address_high as u64) << 24);

    const SEGMENT_DESCRIPTOR_TYPE_SYSTEM: u32 = 0;

    if descriptor_type == SEGMENT_DESCRIPTOR_TYPE_SYSTEM {
        base_address |= (ss.base_address_upper as u64) << 32;
    }

    base_address
}

#[inline(always)]
pub unsafe fn write_flags(value: u64) {
    unsafe {
        asm!(
            "push {0}",
            "popfq",
            in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

#[inline(always)]
pub fn rip() -> usize {
    let out_rip: usize;

    unsafe {
        asm!("lea {0}, [rip]", out(reg) out_rip);
    }

    out_rip
}

#[inline(always)]
pub fn rsp() -> usize {
    let mut out_rsp: usize;

    unsafe {
        asm!("mov {0}, rsp", out(reg) out_rsp);
    }

    out_rsp
}

#[inline(always)]
pub fn flags() -> usize {
    let mut flags: usize;

    unsafe {
        asm!("pushf; pop {}", out(reg) flags);
    }

    flags
}
