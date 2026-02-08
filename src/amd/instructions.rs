use crate::prelude::*;

#[inline(always)]
pub unsafe fn vmsave(vmcb_pa: u64) {
    unsafe {
        asm!(
            "vmsave",
            in("rax") vmcb_pa,
            options(nostack, preserves_flags),
        );
    }
}

#[inline(always)]
pub unsafe fn vmload(vmcb_pa: u64) {
    unsafe {
        asm!(
            "vmload",
            in("rax") vmcb_pa,
            options(nostack, preserves_flags),
        );
    }
}

#[inline(always)]
pub unsafe fn stgi() {
    unsafe {
        asm!("stgi", options(nomem, nostack, preserves_flags));
    }
}
