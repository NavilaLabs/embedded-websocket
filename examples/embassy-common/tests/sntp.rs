//! The SNTP messages and the clock that the TLS verifier reads.

use embassy_common::{sntp, NetworkClock};
use embedded_tls::TlsClock;

const NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
// 2026-01-01T00:00:00Z as NTP seconds, which count from 1900
const NTP_SECONDS: u32 = 3_976_214_400;
const UNIX_SECONDS: u64 = 1_767_225_600;

fn response() -> [u8; 48] {
    let mut response = [0; 48];
    response[0] = 0b00_100_100; // no leap warning, version 4, server
    response[1] = 2; // stratum
    response[24..32].copy_from_slice(&NONCE);
    response[40..44].copy_from_slice(&NTP_SECONDS.to_be_bytes());
    response
}

#[test]
fn request_is_a_client_message_carrying_the_nonce() {
    let request = sntp::request(NONCE);
    assert_eq!(request.len(), 48);
    assert_eq!(request[0], 0b00_100_011);
    assert_eq!(request[40..48], NONCE);
}

#[test]
fn response_gives_the_unix_time() {
    assert_eq!(sntp::unix_time(&response(), NONCE), Some(UNIX_SECONDS));
}

#[test]
fn response_that_does_not_answer_the_request_is_refused() {
    let mut cases = Vec::new();
    let mut other_nonce = response();
    other_nonce[24] ^= 1;
    cases.push(("another nonce", other_nonce.to_vec()));
    let mut client_mode = response();
    client_mode[0] = 0b00_100_011;
    cases.push(("not from a server", client_mode.to_vec()));
    let mut unsynchronized = response();
    unsynchronized[0] |= 0b11_000_000;
    cases.push(("unsynchronized server", unsynchronized.to_vec()));
    let mut kiss_of_death = response();
    kiss_of_death[1] = 0;
    cases.push(("kiss of death", kiss_of_death.to_vec()));
    let mut no_time = response();
    no_time[40..48].fill(0);
    cases.push(("no transmit time", no_time.to_vec()));
    cases.push(("too short", response()[..47].to_vec()));
    for (case, response) in cases {
        assert_eq!(sntp::unix_time(&response, NONCE), None, "{case}");
    }
}

#[test]
fn network_clock_has_no_time_until_it_is_set() {
    assert_eq!(NetworkClock::now(), None);
    NetworkClock::set(UNIX_SECONDS);
    let now = NetworkClock::now().unwrap();
    assert!((UNIX_SECONDS..UNIX_SECONDS + 5).contains(&now), "{now}");
}

#[test]
fn time_after_the_ntp_rollover_in_2036_is_read_in_the_next_era() {
    // 2040-01-01T00:00:00Z: NTP seconds wrapped around on 2036-02-07
    let mut after_rollover = response();
    after_rollover[40..44].copy_from_slice(&123_010_304u32.to_be_bytes());
    assert_eq!(sntp::unix_time(&after_rollover, NONCE), Some(2_208_988_800));
}
