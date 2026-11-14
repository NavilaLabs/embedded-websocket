//! Joins a WiFi network, sends one message to a `wss://` echo server, and then serves a `ws://`
//! echo server on port 80.
//!
//! Configure it at build time with environment variables:
//!
//! * `WIFI_SSID` and `WIFI_PASSWORD`: the network to join.
//! * `WSS_HOST` and `WSS_PATH`: the `wss://` server, for example `echo.websocket.org` and `/`.
//! * `WSS_CA_DER`: path to the DER encoded certificate of the authority that signed the server
//!   certificate. Only ECDSA P-256 and P-384 certificates are supported. Without it, the example
//!   skips the `wss://` client.
#![no_std]
#![no_main]

use cyw43::{aligned_bytes, JoinOptions};
use cyw43_pio::{PioSpi, DEFAULT_CLOCK_DIVIDER};
use defmt::{info, unwrap, warn, Debug2Format};
use embassy_common::{serve_echo, wss_echo, Buffers, WssTarget};
use embassy_executor::Spawner;
use embassy_net::{dns::DnsQueryType, tcp::TcpSocket, Config, Stack, StackResources};
use embassy_rp::{
    bind_interrupts,
    clocks::RoscRng,
    dma,
    gpio::{Level, Output},
    peripherals::{DMA_CH0, PIO0},
    pio::{InterruptHandler, Pio},
};
use embassy_time::Duration;
use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => InterruptHandler<PIO0>;
    DMA_IRQ_0 => dma::InterruptHandler<DMA_CH0>;
});

const WIFI_SSID: &str = match option_env!("WIFI_SSID") {
    Some(ssid) => ssid,
    None => "",
};
const WIFI_PASSWORD: &str = match option_env!("WIFI_PASSWORD") {
    Some(password) => password,
    None => "",
};
const WSS_HOST: &str = match option_env!("WSS_HOST") {
    Some(host) => host,
    None => "echo.websocket.org",
};
const WSS_PATH: &str = match option_env!("WSS_PATH") {
    Some(path) => path,
    None => "/",
};
const WSS_CA_DER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ca.der"));

// One TLS record is up to 16640 bytes; the messages this example sends are much smaller.
const TLS_READ_LEN: usize = 16640;
const TLS_WRITE_LEN: usize = 4096;

#[embassy_executor::task]
async fn cyw43_task(
    runner: cyw43::Runner<'static, cyw43::SpiBus<Output<'static>, PioSpi<'static, PIO0, 0>>>,
) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, cyw43::NetDriver<'static>>) -> ! {
    runner.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    let fw = aligned_bytes!("../firmware/43439A0.bin");
    let clm = aligned_bytes!("../firmware/43439A0_clm.bin");
    let nvram = aligned_bytes!("../firmware/nvram_rp2040.bin");

    let pwr = Output::new(p.PIN_23, Level::Low);
    let cs = Output::new(p.PIN_25, Level::High);
    let mut pio = Pio::new(p.PIO0, Irqs);
    let spi = PioSpi::new(
        &mut pio.common,
        pio.sm0,
        DEFAULT_CLOCK_DIVIDER,
        pio.irq0,
        cs,
        p.PIN_24,
        p.PIN_29,
        dma::Channel::new(p.DMA_CH0, Irqs),
    );

    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let (net_device, mut control, runner) =
        cyw43::new(STATE.init(cyw43::State::new()), pwr, spi, fw, nvram).await;
    spawner.spawn(unwrap!(cyw43_task(runner)));
    control.init(clm).await;

    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    let (stack, runner) = embassy_net::new(
        net_device,
        Config::dhcpv4(Default::default()),
        RESOURCES.init(StackResources::new()),
        RoscRng.next_u64(),
    );
    spawner.spawn(unwrap!(net_task(runner)));

    while let Err(error) = control
        .join(WIFI_SSID, JoinOptions::new(WIFI_PASSWORD.as_bytes()))
        .await
    {
        warn!("joining {} failed: {:?}", WIFI_SSID, error);
    }
    stack.wait_config_up().await;
    info!("network is up");

    if WSS_CA_DER.is_empty() {
        info!("WSS_CA_DER was not set at build time, skipping the wss:// client");
    } else {
        wss_client(stack).await;
    }
    echo_server(stack).await
}

async fn wss_client(stack: Stack<'static>) {
    static TLS_READ: StaticCell<[u8; TLS_READ_LEN]> = StaticCell::new();
    static TLS_WRITE: StaticCell<[u8; TLS_WRITE_LEN]> = StaticCell::new();
    static BUFFERS: StaticCell<Buffers> = StaticCell::new();
    let tls_read = TLS_READ.init([0; TLS_READ_LEN]);
    let tls_write = TLS_WRITE.init([0; TLS_WRITE_LEN]);
    let buffers = BUFFERS.init(Buffers::new());

    let Some(address) = stack
        .dns_query(WSS_HOST, DnsQueryType::A)
        .await
        .ok()
        .and_then(|addresses| addresses.first().copied())
    else {
        warn!("cannot resolve {}", WSS_HOST);
        return;
    };
    let (mut rx, mut tx) = ([0; 4096], [0; 4096]);
    let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
    socket.set_timeout(Some(Duration::from_secs(10)));
    if let Err(error) = socket.connect((address, 443)).await {
        warn!("connecting to {} failed: {:?}", WSS_HOST, error);
        return;
    }

    let target = WssTarget {
        host: WSS_HOST,
        path: WSS_PATH,
        ca_der: WSS_CA_DER,
    };
    // the ring oscillator of the RP2040 is its only entropy source; embassy-rp treats it as
    // cryptographically secure, a hardened product should add an external source
    let tls_rng = RoscRng;
    let masking_rng = ChaCha8Rng::seed_from_u64(RoscRng.next_u64());
    let result = wss_echo(
        socket,
        &target,
        tls_read,
        tls_write,
        tls_rng,
        masking_rng,
        buffers,
        "hello from a Pico W",
    )
    .await;
    match result {
        Ok(echo) => info!("wss:// echo: {}", echo),
        Err(error) => warn!("wss:// client failed: {:?}", Debug2Format(&error)),
    }
}

async fn echo_server(stack: Stack<'static>) -> ! {
    let (mut rx, mut tx) = ([0; 2048], [0; 2048]);
    let mut buffers = Buffers::new();
    loop {
        let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
        socket.set_timeout(Some(Duration::from_secs(60)));
        info!("ws:// echo server listening on port 80");
        if let Err(error) = socket.accept(80).await {
            warn!("accept failed: {:?}", error);
            continue;
        }
        if let Err(error) = serve_echo(&mut socket, &mut buffers).await {
            warn!("echo connection failed: {:?}", error);
        }
    }
}
