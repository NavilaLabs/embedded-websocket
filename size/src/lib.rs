//! What the probes share: a panic handler and streams whose data the optimizer cannot predict,
//! so it keeps all code that handles it.
#![no_std]

use core::{
    future::Future,
    hint::black_box,
    pin::pin,
    task::{Context, Poll, Waker},
};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// A stream that reads unknown bytes and discards what is written.
pub struct Stream;

impl embedded_io::ErrorType for Stream {
    type Error = embedded_io::ErrorKind;
}

impl embedded_io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        for byte in buf.iter_mut() {
            *byte = black_box(0);
        }
        Ok(black_box(buf.len()))
    }
}

impl embedded_io::Write for Stream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(black_box(buf).len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl embedded_io_async::Read for Stream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        embedded_io::Read::read(self, buf)
    }
}

impl embedded_io_async::Write for Stream {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        embedded_io::Write::write(self, buf)
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// A random number generator whose numbers the optimizer cannot predict.
pub struct Random;

impl rand_core::TryRng for Random {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(black_box(0))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(black_box(0))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dest.iter_mut() {
            *byte = black_box(0);
        }
        Ok(())
    }
}

// The probes only measure code size, so the numbers do not need to be secure.
impl rand_core::TryCryptoRng for Random {}

/// Polls `future` once, which is enough to keep its code in the firmware.
pub fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
    pin!(future).poll(&mut Context::from_waker(Waker::noop()))
}
