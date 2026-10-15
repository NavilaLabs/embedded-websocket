use core::convert::Infallible;

use rand_core::TryRng;

// Clients need a proper random number generator to generate a mask key
// However, server websockets do not require this and the payload is not masked
// EmptyRng is used for servers. In theory, you can use it for clients but you may run into
// proxy server caching issues so it is advisable to use a proper random number generator.
// Note that data masking does not require a cryptographically strong random number because
// the key is sent with the payload anyway

#[derive(Default)]
pub struct EmptyRng {}

impl EmptyRng {
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
