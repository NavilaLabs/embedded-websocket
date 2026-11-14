//! Joins a WiFi network, sends one message to a `wss://` echo server, and then serves a `ws://`
//! echo server on port 80.
//!
//! Configure it at build time with environment variables:
//!
//! * `WIFI_SSID` and `WIFI_PASSWORD`: the WPA2 network to join.
//! * `WSS_HOST` and `WSS_PATH`: the `wss://` server, for example `echo.websocket.org` and `/`.
//! * `WSS_SERVER_KEY_DER`: path to the public key of the `wss://` server as DER encoded
//!   SubjectPublicKeyInfo, which must be an ECDSA P-256 key. The client trusts only a server
//!   that proves it holds the matching private key. Without it, the example skips the `wss://`
//!   client.
#![no_std]
#![no_main]

use embassy_common::{serve_echo, wss_echo, Buffers, WssTarget};
use embassy_executor::Spawner;
use embassy_net::{dns::DnsQueryType, tcp::TcpSocket, Runner, Stack, StackResources};
use embassy_time::{Duration, Timer};
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    ram,
    rng::{Rng, Trng, TrngSource},
    timer::timg::TimerGroup,
};
use esp_println::println;
use esp_radio::wifi::{
    sta::StationConfig, AuthenticationMethodConfig, Config, ControllerConfig, Interface,
    WifiController,
};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

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
const WSS_SERVER_KEY_DER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/server-key.der"));

// One TLS record is up to 16640 bytes; the messages this example sends are much smaller.
const TLS_READ_LEN: usize = 16640;
const TLS_WRITE_LEN: usize = 4096;

#[esp_hal::main]
async fn main(spawner: Spawner) -> ! {
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    // the WiFi driver allocates
    esp_alloc::heap_allocator!(#[ram(reclaimed)] size: 64 * 1024);
    esp_rtos::start(
        TimerGroup::new(peripherals.TIMG0).timer0,
        peripherals.FROM_CPU_INTR0,
    );

    // keeps the entropy source on, so `Trng` is cryptographically secure for TLS
    let _entropy = TrngSource::new(peripherals.RNG, peripherals.ADC1);

    let station = Config::Station(
        StationConfig::default()
            .with_ssid(WIFI_SSID.try_into().unwrap())
            .with_authentication(AuthenticationMethodConfig::Wpa2Personal(
                WIFI_PASSWORD.try_into().unwrap(),
            )),
    );
    let controller = WifiController::new(
        peripherals.WIFI,
        ControllerConfig::default().with_initial_config(station),
    )
    .unwrap();

    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    let rng = Rng::new();
    let (stack, runner) = embassy_net::new(
        Interface::station(),
        embassy_net::Config::dhcpv4(Default::default()),
        RESOURCES.init(StackResources::new()),
        u64::from(rng.random()) << 32 | u64::from(rng.random()),
    );
    spawner.spawn(connection(controller).unwrap());
    spawner.spawn(net_task(runner).unwrap());
    stack.wait_config_up().await;
    println!("network is up");

    if WSS_SERVER_KEY_DER.is_empty() {
        println!("WSS_SERVER_KEY_DER was not set at build time, skipping the wss:// client");
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
        println!("cannot resolve {}", WSS_HOST);
        return;
    };
    let (mut rx, mut tx) = ([0; 4096], [0; 4096]);
    let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
    socket.set_timeout(Some(Duration::from_secs(10)));
    if let Err(error) = socket.connect((address, 443)).await {
        println!("connecting to {} failed: {:?}", WSS_HOST, error);
        return;
    }

    let target = WssTarget {
        host: WSS_HOST,
        path: WSS_PATH,
        server_key_der: WSS_SERVER_KEY_DER,
    };
    let tls_rng = Trng::try_new().unwrap();
    let result = wss_echo(
        socket,
        &target,
        tls_read,
        tls_write,
        tls_rng,
        Rng::new(),
        buffers,
        "hello from an ESP32-C3",
    )
    .await;
    match result {
        Ok(echo) => println!("wss:// echo: {}", echo),
        Err(error) => println!("wss:// client failed: {:?}", error),
    }
}

async fn echo_server(stack: Stack<'static>) -> ! {
    let (mut rx, mut tx) = ([0; 2048], [0; 2048]);
    let mut buffers = Buffers::new();
    loop {
        let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
        socket.set_timeout(Some(Duration::from_secs(60)));
        println!("ws:// echo server listening on port 80");
        if let Err(error) = socket.accept(80).await {
            println!("accept failed: {:?}", error);
            continue;
        }
        if let Err(error) = serve_echo(&mut socket, &mut buffers).await {
            println!("echo connection failed: {:?}", error);
        }
    }
}

#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    loop {
        match controller.connect_async().await {
            Ok(_) => {
                let _ = controller.wait_for_disconnect_async().await;
                println!("WiFi disconnected");
            }
            Err(error) => println!("connecting to {} failed: {:?}", WIFI_SSID, error),
        }
        Timer::after(Duration::from_secs(5)).await
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, Interface>) {
    runner.run().await
}
