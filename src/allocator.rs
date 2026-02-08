use core::{
    alloc::{GlobalAlloc, Layout},
    mem::transmute,
};

use crate::{offsets, wdk::Module};

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

pub struct KernelAllocator;

macro_rules! rand_letter {
    () => {
        (if obfstr::random!(bool) { b'a' } else { b'A' }) + (obfstr::random!(u8) % (b'Z' - b'A'))
    };
}

// randomize allocation pool tag for build
pub const POOL_TAG: u32 = u32::from_ne_bytes([
    rand_letter!(),
    rand_letter!(),
    rand_letter!(),
    rand_letter!(),
]);

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            transmute::<_, unsafe extern "system" fn(u64, usize, u32) -> *mut u8>(
                Module::nt().base + offsets::ntoskrnl::ExAllocatePool2,
            )(0x40, layout.size(), POOL_TAG)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            transmute::<_, unsafe extern "system" fn(*mut u8, u32)>(
                Module::nt().base + offsets::ntoskrnl::ExFreePoolWithTag,
            )(ptr, 0);
        }
    }
}

#[unsafe(no_mangle)]
#[used]
#[allow(non_upper_case_globals)]
pub static _fltused: i32 = 0;

pub fn dbg_print(message: &str) {
    unsafe {
        const DPFLTR_IHVDRIVER_ID: u32 = 77;
        const DPFLTR_ERROR_LEVEL: u32 = 1;

        transmute::<_, unsafe extern "system" fn(u32, u32, *const u8, ...)>(
            Module::nt().base + offsets::ntoskrnl::DbgPrintEx,
        )(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, message.as_ptr());
    }
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::allocator::dbg_print(obfstr::obfstr!("\n\0"))
    };
    ($($arg:tt)*) => {{
        use alloc::string::ToString;

        $crate::allocator::dbg_print(&fmtools::fmt!($($arg)*"\n\0").to_string());
    }};
}

#[macro_export]
macro_rules! dbg {
    () => {
        $crate::println!("["{file!()}":"{line!()}":"{column!()}"]")
    };
    ($val:expr $(,)?) => {
        match $val {
            tmp => {
                $crate::println!("["{file!()}":"{line!()}":"{column!()}"] "{stringify!($val)}" = "{&tmp:#X?});
                tmp
            }
        }
    };
    ($($val:expr),+ $(,)?) => {
        ($($crate::dbg!($val)),+,)
    };
}
