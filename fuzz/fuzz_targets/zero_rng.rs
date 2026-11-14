//! A generator for the client that makes its masking keys and handshake keys zero, so the
//! targets are deterministic. A real client needs unpredictable keys.

pub struct ZeroRng;

impl rand_core::TryRng for ZeroRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        dest.fill(0);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for ZeroRng {}
