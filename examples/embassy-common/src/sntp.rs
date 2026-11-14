//! A minimal SNTP client (RFC 4330) that sets the [`NetworkClock`].
//!
//! SNTP is not authenticated: an attacker on the network path can send any time and so make an
//! expired certificate look valid. The client only accepts an answer to its own request.

use core::sync::atomic::{AtomicU32, Ordering};

use embassy_net::{
    dns::DnsQueryType,
    udp::{PacketMetadata, UdpSocket},
    Stack,
};
use embassy_time::{with_timeout, Duration, Instant};
use embedded_tls::TlsClock;

const MESSAGE_LEN: usize = 48;
const NTP_PORT: u16 = 123;
// seconds from 1900-01-01, where NTP time starts, to 1970-01-01
const NTP_TO_UNIX_SECONDS: u64 = 2_208_988_800;

/// A failure to get the time from a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The name of the server cannot be resolved.
    Dns,
    /// The request cannot be sent.
    Network,
    /// No valid answer arrived in time.
    Timeout,
}

/// The time the TLS verifier checks certificate dates against, once [`sync_clock`] or
/// [`NetworkClock::set`] set it.
pub struct NetworkClock;

// Seconds since the Unix epoch at the uptime 0 of embassy-time; 0 while the clock is not set.
// 32 bits suffice until 2106, and atomic loads and stores of 32 bits work on every target.
static UNIX_SECONDS_AT_BOOT: AtomicU32 = AtomicU32::new(0);

impl NetworkClock {
    /// Sets the current time in seconds since the Unix epoch.
    pub fn set(unix_seconds: u64) {
        let at_boot = unix_seconds.saturating_sub(Instant::now().as_secs());
        let at_boot = u32::try_from(at_boot).unwrap_or(u32::MAX).max(1);
        UNIX_SECONDS_AT_BOOT.store(at_boot, Ordering::Relaxed);
    }
}

impl TlsClock for NetworkClock {
    fn now() -> Option<u64> {
        match UNIX_SECONDS_AT_BOOT.load(Ordering::Relaxed) {
            0 => None,
            at_boot => Some(u64::from(at_boot) + Instant::now().as_secs()),
        }
    }
}

/// Returns a request whose transmit timestamp is `nonce`, which the server sends back.
pub fn request(nonce: [u8; 8]) -> [u8; MESSAGE_LEN] {
    let mut request = [0; MESSAGE_LEN];
    request[0] = 0b00_100_011; // no leap warning, version 4, client
    request[40..48].copy_from_slice(&nonce);
    request
}

/// Returns the time in seconds since the Unix epoch from a `response` to the request carrying
/// `nonce`, or `None` if it is not a valid answer to that request.
pub fn unix_time(response: &[u8], nonce: [u8; 8]) -> Option<u64> {
    let response = response.get(..MESSAGE_LEN)?;
    let leap = response[0] >> 6;
    let version = (response[0] >> 3) & 0b111;
    let mode = response[0] & 0b111;
    let stratum = response[1];
    let is_answer = leap != 3
        && (3..=4).contains(&version)
        && mode == 4
        && (1..=15).contains(&stratum)
        && response[24..32] == nonce
        && response[40..48] != [0; 8];
    if !is_answer {
        return None;
    }
    let seconds = u32::from_be_bytes(response[40..44].try_into().ok()?);
    // RFC 4330 section 3: a cleared top bit means the era that starts in 2036
    let ntp_seconds = if seconds & 0x8000_0000 == 0 {
        u64::from(seconds) + (1 << 32)
    } else {
        u64::from(seconds)
    };
    Some(ntp_seconds - NTP_TO_UNIX_SECONDS)
}

/// Asks `server` for the time and sets the [`NetworkClock`].
///
/// `nonce` must be random; the answer must carry it, so a sender that did not see the request
/// cannot set the time.
///
/// # Errors
///
/// * [`Error::Dns`] if `server` cannot be resolved.
/// * [`Error::Network`] if the request cannot be sent.
/// * [`Error::Timeout`] if no valid answer from `server` arrives within five seconds.
pub async fn sync_clock(stack: Stack<'_>, server: &str, nonce: [u8; 8]) -> Result<(), Error> {
    let address = stack
        .dns_query(server, DnsQueryType::A)
        .await
        .ok()
        .and_then(|addresses| addresses.first().copied())
        .ok_or(Error::Dns)?;

    let (mut rx_meta, mut tx_meta) = ([PacketMetadata::EMPTY; 2], [PacketMetadata::EMPTY; 1]);
    let (mut rx, mut tx) = ([0; 2 * MESSAGE_LEN], [0; MESSAGE_LEN]);
    let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx, &mut tx_meta, &mut tx);
    // a random local port, so a blind attacker has to guess it as well
    let local_port = 49152 + u16::from_be_bytes([nonce[0], nonce[1]]) % 16384;
    socket.bind(local_port).map_err(|_| Error::Network)?;
    socket
        .send_to(&request(nonce), (address, NTP_PORT))
        .await
        .map_err(|_| Error::Network)?;

    let answer = async {
        let mut response = [0; MESSAGE_LEN];
        loop {
            let Ok((len, meta)) = socket.recv_from(&mut response).await else {
                continue;
            };
            if meta.endpoint.addr != address || meta.endpoint.port != NTP_PORT {
                continue;
            }
            if let Some(time) = unix_time(&response[..len], nonce) {
                return time;
            }
        }
    };
    let time = with_timeout(Duration::from_secs(5), answer)
        .await
        .map_err(|_| Error::Timeout)?;
    NetworkClock::set(time);
    Ok(())
}
