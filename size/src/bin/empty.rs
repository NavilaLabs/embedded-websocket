//! The runtime without the library, subtracted from the other probes.
#![no_std]
#![no_main]

use size_probes as _;

#[cortex_m_rt::entry]
fn main() -> ! {
    loop {}
}
