//! Every URL the parser accepts is one the `url` crate, which follows the WHATWG URL standard of
//! browsers, also accepts, with the same scheme, host, port and, where it does not normalize
//! them, path and query.
#![no_main]

use std::net::Ipv6Addr;

use embedded_io_websocket::WebSocketUrl;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    let Ok(ours) = WebSocketUrl::parse(input) else {
        return;
    };
    // labels of internationalized names are passed on without checking their punycode, which
    // the url crate decodes and may reject
    let has_a_label = ours
        .host()
        .split('.')
        .any(|label| label.len() >= 4 && label[..4].eq_ignore_ascii_case("xn--"));
    let theirs = match url::Url::parse(input) {
        Ok(theirs) => theirs,
        Err(url::ParseError::IdnaError) if has_a_label => return,
        Err(error) => panic!("the url crate rejects it: {error}"),
    };

    assert_eq!(ours.is_secure(), matches!(theirs.scheme(), "wss" | "https"));
    assert_eq!(Some(ours.port()), theirs.port_or_known_default());
    match theirs.host().expect("a host") {
        url::Host::Domain(domain) => assert_eq!(domain, ours.host().to_ascii_lowercase()),
        url::Host::Ipv4(address) => assert_eq!(ours.host().parse(), Ok(address)),
        url::Host::Ipv6(address) => assert_eq!(ours.host().parse::<Ipv6Addr>(), Ok(address)),
    }
    assert!(!theirs.has_authority() || theirs.username().is_empty());

    // the url crate removes dot segments, also percent encoded ones, and percent encodes `'` in
    // queries
    let resource = ours.options().path;
    let has_dot = resource.contains('.') || resource.to_ascii_lowercase().contains("%2e");
    if !has_dot && !resource.contains('\'') {
        let mut expected = theirs.path().to_owned();
        if let Some(query) = theirs.query() {
            expected.push('?');
            expected.push_str(query);
        }
        let sent = if resource.starts_with('/') {
            resource.to_owned()
        } else {
            format!("/{resource}")
        };
        assert_eq!(sent, expected);
    }
});
