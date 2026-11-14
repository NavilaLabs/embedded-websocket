//! Holds one static per public type whose symbol size is the size of that type on the target,
//! which `llvm-nm --print-size` reads back.
#![no_std]
#![no_main]

use core::mem::size_of;

use embedded_io_websocket::{
    asynch, blocking, EmptyRng, FramerState, ReadChunk, ReadResult, WebSocketClient,
    WebSocketServer,
};
use size_probes::Stream;

type Shared = asynch::Shared<'static, Stream, EmptyRng, embedded_io_websocket::Server>;
type Lock = asynch::LocalMutex<Shared>;

macro_rules! sizes {
    ($($name:ident: $type:ty),* $(,)?) => {
        $(
            #[used]
            #[no_mangle]
            static $name: [u8; size_of::<$type>()] = [0; size_of::<$type>()];
        )*
    };
}

sizes! {
    SIZE_OF_FRAMER_STATE: FramerState,
    SIZE_OF_WEBSOCKET_CLIENT: WebSocketClient<EmptyRng>,
    SIZE_OF_WEBSOCKET_SERVER: WebSocketServer,
    SIZE_OF_BLOCKING_FRAMER: blocking::Framer<'static, EmptyRng, embedded_io_websocket::Server>,
    SIZE_OF_ASYNC_FRAMER: asynch::Framer<'static, EmptyRng, embedded_io_websocket::Server>,
    SIZE_OF_SHARED_IN_LOCAL_MUTEX: Lock,
    SIZE_OF_READER: asynch::Reader<'static, Stream, Lock>,
    SIZE_OF_WRITER: asynch::Writer<'static, Lock>,
    SIZE_OF_READ_RESULT: ReadResult<'static>,
    SIZE_OF_READ_CHUNK: ReadChunk<'static>,
}

#[cortex_m_rt::entry]
fn main() -> ! {
    loop {}
}
