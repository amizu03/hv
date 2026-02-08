pub mod compatibility;

use core::{
    array,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

#[cfg(feature = "amd")]
use crate::amd;
#[cfg(feature = "intel")]
use crate::intel;

use crate::{dbg, hypervisor::compatibility::Platform, prelude::*, println};

#[cfg(feature = "amd")]
pub type VCpu = amd::vcpu::VCpu;
#[cfg(feature = "intel")]
pub type VCpu = intel::vcpu::VCpu;

pub static mut EXECUTING_VCPU: usize = 0;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct GuestRegisters {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
}

pub struct Hypervisor {
    pub ncpus: usize,
    pub apic_bar: usize,
    pub phys_mem_ranges: [PhysMemRange; 12],
    pub phys_mem_ranges_len: usize,
    pub pages_buffer: IndependentPages<128>,
    pub pages_buffer_cursor: AtomicUsize,
    pub pml4: [(usize, IndependentPages<1>); PageTableIndex::Count as usize],
    pub msr_permissions_bitmap: IndependentPages<2>,
}

#[derive(Copy, Clone)]
#[repr(usize)]
pub enum PageTableIndex {
    Primary,
    #[cfg(feature = "amd")]
    Shadow,
    Count,
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum VmExitType {
    ExitHypervisor,
    IncrementRIP,
    Continue,
}

pub trait VCpuGeneric {
    fn enable(&mut self) -> Result<()>;
    fn setup(&mut self, hv: &mut Hypervisor, rip: u64, rsp: u64, rflags: u64) -> Result<()>;

    fn advance_rip(&mut self) -> Result<()>;
    fn inject_ud(&mut self) -> Result<()>;
    fn inject_gp(&mut self) -> Result<()>;
    fn inject_pf(&mut self, error_code: u32) -> Result<()>;
    fn inject_db(&mut self) -> Result<()>;
    fn inject_bp(&mut self) -> Result<()>;
    fn inject_external_interrupt(&mut self, vector: u8) -> Result<()>;

    fn inject_nmi(&mut self) -> Result<()>;

    fn flush_tlb(&mut self) -> Result<()>;
}

static VIRTUALIZED_BITSET: AtomicU64 = AtomicU64::new(0);

#[inline(always)]
pub fn is_virtualized() -> bool {
    let ncpu = current_processor_number();
    let bit = 1 << (ncpu as u64);

    VIRTUALIZED_BITSET.load(Ordering::Relaxed) & bit != 0
}

#[inline(always)]
pub fn set_virtualized() {
    let ncpu = current_processor_number();
    let bit = 1 << (ncpu as u64);

    VIRTUALIZED_BITSET.fetch_or(bit, Ordering::Relaxed);
}

impl Hypervisor {
    pub fn pml4_mut(&mut self, index: PageTableIndex) -> &mut (usize, IndependentPages<1>) {
        &mut self.pml4[index as usize]
    }

    pub fn pml4(&self, index: PageTableIndex) -> &(usize, IndependentPages<1>) {
        &self.pml4[index as usize]
    }

    pub fn alloc_page(&self) -> Result<usize> {
        let pages = self.pages_buffer.alloc;

        unsafe {
            // Atomically fetch and increment the cursor
            let cursor = self.pages_buffer_cursor.fetch_add(1, Ordering::SeqCst);

            if cursor >= PTES_PER_PAGE * 128 {
                // Try to restore the cursor (best effort)
                self.pages_buffer_cursor
                    .store(PTES_PER_PAGE * 128, Ordering::SeqCst);
                return Err(HypervisorError::OutOfMemory);
            }

            let entry = ((self.pages_buffer.alloc + cursor * size_of::<usize>()) as *const usize)
                .read_unaligned();

            Ok(entry)
        }
    }

    pub fn alloc_pt(
        &self,
        supervisor: bool,
        writeable: bool,
        executable: bool,
        large_page: bool,
    ) -> Result<(usize, usize)> {
        let va = self.alloc_page()?;
        let pa = virt_to_phys(va);
        let pfn = pa >> PAGE_SHIFT;

        Ok((
            va,
            initialize_pte(pfn, supervisor, writeable, executable, large_page),
        ))
    }

    /// Assign a page table entry using 2MB large pages when possible
    pub fn assign_pt(
        &self,
        npml4: usize,
        pa: usize,
        supervisor: bool,
        writeable: bool,
        executable: bool,
        large_page: bool,
    ) -> Result<usize> {
        let pml4 = phys_to_virt(npml4) as *mut [usize; 0x200];

        let pml4_index = (pa >> 39) & 0x1FF;
        let pdpt_index = (pa >> 30) & 0x1FF;
        let pd_index = (pa >> 21) & 0x1FF;

        #[cfg(feature = "amd")]
        let supervisor = true;
        #[cfg(feature = "intel")]
        let supervisor = false;

        // Get or create PDPT
        let pml4e = unsafe { &mut (*pml4)[pml4_index] };
        let pdpt;

        if *pml4e & 0x1 == 0 {
            let (va, pte) = self.alloc_pt(supervisor, true, true, false)?;
            *pml4e = pte;
            pdpt = va as *mut usize;
        } else {
            let pfn = (*pml4e >> PAGE_SHIFT) & 0xFFFFFFFFF;
            let va = phys_to_virt(pfn << PAGE_SHIFT);
            pdpt = va as *mut usize;
        }

        // Get or create PD
        let pdpte = unsafe { &mut *pdpt.add(pdpt_index) };
        let pd;

        if *pdpte & 0x1 == 0 {
            let (va, mut pte) = self.alloc_pt(supervisor, true, true, false)?;
            *pdpte = pte;
            pd = va as *mut usize;
        } else {
            let pfn = (*pdpte >> PAGE_SHIFT) & 0xFFFFFFFFF;
            let va = phys_to_virt(pfn << PAGE_SHIFT);
            pd = va as *mut usize;
        }

        // For 2MB large pages, set the entry directly at PD level
        let pde = unsafe { &mut *pd.add(pd_index) };

        if large_page {
            // Use 2MB large page
            *pde = initialize_pte(pa >> PAGE_SHIFT, supervisor, writeable, executable, true);
            Ok(*pde)
        } else {
            // Use 4KB pages - need PT level
            let pt;
            let pt_index = (pa >> 12) & 0x1FF;

            if *pde & 0x1 == 0 {
                let (va, pte) = self.alloc_pt(supervisor, true, true, false)?;
                *pde = pte;
                pt = va as *mut usize;
            } else {
                // Check if this was previously a large page
                if *pde & (1 << 7) != 0 {
                    // Was a large page, need to split it
                    return Err(HypervisorError::PageSplitRequired);
                }

                let pfn = (*pde >> PAGE_SHIFT) & 0xFFFFFFFFF;
                let va = phys_to_virt(pfn << PAGE_SHIFT);
                pt = va as *mut usize;
            }

            let pte = unsafe { &mut *pt.add(pt_index) };
            *pte = initialize_pte(pa >> PAGE_SHIFT, supervisor, writeable, executable, false);
            Ok(*pte)
        }
    }

    /// Build page tables with memory limit and large page support
    pub fn build_pts(
        &self,
        npml4: *mut [usize; 0x200],
        supervisor: bool,
        writeable: bool,
        executable: bool,
    ) -> Result<usize> {
        let ncr3 = virt_to_phys(npml4.addr());
        let ranges = self.phys_mem_ranges;

        let mut total_mapped: usize = 0;

        for range in &ranges[..self.phys_mem_ranges_len] {
            // Validate range
            if range.start == 0 || range.size == 0 {
                continue;
            }

            // Fall back to 4KB pages for non-aligned regions
            let pfn_start = range.start & LARGE_PFN_MASK;
            let pfn_end = (range.start + range.size + (PAGE_SIZE_2MB - 1)) & LARGE_PFN_MASK;
            // let pfn_start = range.start & PFN_MASK;
            // let pfn_end = (range.start + range.size + (PAGE_SIZE - 1)) & PFN_MASK;

            for pfn in (pfn_start..pfn_end).step_by(PAGE_SIZE_2MB) {
                // for pfn in (pfn_start..pfn_end).step_by(PAGE_SIZE) {
                self.assign_pt(ncr3, pfn, supervisor, writeable, executable, true)?;
                // self.assign_pt(ncr3, pfn, supervisor, writeable, executable, false)?;
            }
        }

        // Map APIC BAR
        if self.apic_bar != 0 {
            self.assign_pt(
                ncr3,
                self.apic_bar,
                supervisor,
                writeable,
                executable,
                false,
            )?;
        }

        Ok(ncr3)
    }

    #[inline(never)]
    #[optimize(speed)]
    pub fn virtualize_cpu(&mut self) -> Result<()> {
        let ncpu = current_processor_number();

        const VCPU_SIZE: usize = size_of::<VCpu>();
        let vcpu = IndependentPages::<VCPU_SIZE>::new(true, false);
        vcpu.zero();
        let vcpu = vcpu.leak::<VCpu>();

        let flags = flags();
        let rsp = rsp();
        let rip = rip();

        if !is_virtualized() {
            set_virtualized();

            vcpu.enable()?;
            vcpu.setup(self, rip as _, rsp as _, flags as _)?;

            abort();
        }

        // This point is only reached if virtualization fails or exits
        // Normally vcpu.setup -> vmenter never returns
        Ok(())
    }

    /// Entry point for per-CPU virtualization threads
    extern "system" fn virtualize_cpus(&mut self) {
        let nproc = active_processor_count() as usize;

        // unsafe {
        //     EXECUTING_VCPU = self as *mut _ as usize;
        // }

        // Create a separate thread for each CPU
        for i in 0..nproc {
            let original_affinity = set_system_affinity_thread(1 << i);

            // ke_yield_execution();

            if let Err(e) = self.virtualize_cpu() {
                revert_to_user_affinity_thread(original_affinity);
            }

            revert_to_user_affinity_thread(original_affinity);
        }
    }

    pub fn virtualize(&mut self) {
        create_thread(Self::virtualize_cpus as *const (), self as *mut _ as usize);
    }

    fn build_msr_permissions_bitmap() -> IndependentPages<2> {
        let msr_permissions_bitmap = IndependentPages::<2>::new(true, false);

        msr_permissions_bitmap.zero();

        let mut bmp = RtlBitmap::default();
        rtl_initialize_bitmap(
            &mut bmp,
            msr_permissions_bitmap.alloc as _,
            8 * 2 * PAGE_SIZE,
        );

        const BITS_PER_MSR: usize = 2;
        const CHAR_BIT: usize = 8;
        const BITMAP_VECTOR_SIZE: usize = 0x800 * CHAR_BIT; // 0x4000

        rtl_clear_all_bits(&mut bmp);

        // // write access interception for EFER MSR
        // let mut set_bits = |msr: u32, read: bool, write: bool| {
        //     let mut offset = 0;

        //     if msr as u32 <= 0x00001FFF {
        //         // update the bit in the low bitmap
        //         offset = msr as usize * BITS_PER_MSR;
        //     } else if msr as u32 >= 0xC0000000 && msr as u32 <= 0xC0001FFF {
        //         // update the bit in the high bitmap
        //         offset = BITMAP_VECTOR_SIZE + (msr as usize - 0xC0000000) * BITS_PER_MSR;
        //     }

        //     if write {
        //         rtl_set_bits(&mut bmp, offset + 1, 1);
        //     }

        //     if read {
        //         rtl_set_bits(&mut bmp, offset, 1);
        //     }
        // };

        msr_permissions_bitmap
    }

    pub fn new() -> Result<Self> {
        let ranges = phys_mem_ranges();
        let mut phys_mem_ranges = [PhysMemRange::default(); 12];
        let mut phys_mem_ranges_len = 0;

        // Read physical memory ranges with validation
        while phys_mem_ranges_len < phys_mem_ranges.len() {
            let phys = unsafe { ranges.add(phys_mem_ranges_len).read_unaligned() };

            // Validate the range
            if phys.start == 0 && phys.size == 0 {
                break;
            }

            phys_mem_ranges[phys_mem_ranges_len] = phys;
            phys_mem_ranges_len += 1;
        }

        // Allocate pages buffer
        let pages_buffer = IndependentPages::new(true, false);

        pages_buffer.zero();

        // Pre-allocate pages for the buffer using 4KB pages
        // Only allocate what we actually need instead of 128 * 512 pages
        for i in 0..128 {
            let page = IndependentPages::<PTES_PER_PAGE>::new(true, false);

            page.zero();

            for j in 0..PTES_PER_PAGE {
                let ptr = page.alloc + (j * PAGE_SIZE);

                unsafe {
                    (pages_buffer.alloc as *mut usize)
                        .add(i * PTES_PER_PAGE)
                        .add(j)
                        .write(ptr);
                }
            }

            // Leak the page so it doesn't get freed
            page.leak::<u8>();
        }

        const NUM_PML4: usize = PageTableIndex::Count as usize;
        let pml4 = array::from_fn::<_, NUM_PML4, _>(|i| {
            let x = IndependentPages::new(true, true);

            (0, x)
        });

        let msr_permissions_bitmap = Self::build_msr_permissions_bitmap();

        let ncpus = active_processor_count() as usize;
        let apic_bar = unsafe { rdmsr(0x1B) as usize } & 0xFFFFFF000;

        let mut x = Self {
            ncpus,
            phys_mem_ranges,
            phys_mem_ranges_len,
            pages_buffer,
            pages_buffer_cursor: AtomicUsize::new(0),
            apic_bar,
            pml4,
            msr_permissions_bitmap,
        };

        #[cfg(feature = "amd")]
        let supervisor = true;
        #[cfg(feature = "intel")]
        let supervisor = false;

        // Build page tables
        for i in 0..PageTableIndex::Count as usize {
            let pml4_va = x.pml4[i].1.alloc;

            let mut executable = true;

            #[cfg(feature = "amd")]
            if i == PageTableIndex::Shadow as usize {
                executable = false;
            }

            x.pml4[i].0 = x.build_pts(pml4_va as _, supervisor, true, executable)?;

            #[cfg(feature = "intel")]
            {
                // Represents the EPT page walk length for Intel VT-x, specifically for a 4-level page walk.
                // The value is 3 (encoded as '3 << 3' in EPTP) because the EPTP encoding requires "number of levels minus one".
                const EPT_PAGE_WALK_LENGTH_4: usize = 3 << 3;

                // Represents the memory type setting for Write-Back (WB) in the EPTP.
                const EPT_MEMORY_TYPE_WB: usize = MemoryType::WriteBack as usize;

                // Construct the EPTP with the page walk length and memory type for WB.
                x.pml4[i].0 |= EPT_PAGE_WALK_LENGTH_4 | EPT_MEMORY_TYPE_WB;
            }
        }

        Ok(x)
    }
}
