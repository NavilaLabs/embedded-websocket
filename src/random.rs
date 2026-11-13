use core::convert::Infallible;

use rand_core::TryRng;

/// A random number generator that always returns zero, for servers.
///
/// Servers do not mask frames, so they need no random numbers. Clients must mask frames with a
/// random key (RFC 6455 section 5.3), so use a real random number generator for them. It does not
/// need to be cryptographically strong.
#[derive(Default)]
pub struct EmptyRng {}

impl EmptyRng {
    /// Creates the random number generator.
    pub fn new() -> EmptyRng {
        EmptyRng {}
    }
}

impl TryRng for EmptyRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Infallible> {
        Ok(())
    }
}
