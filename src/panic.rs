use core::panic::PanicInfo;

use crate::wdk::abort;

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    abort();
}
