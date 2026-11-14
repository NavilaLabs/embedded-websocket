//! Places the public key of the wss:// server where the build finds it.

use std::{env, fs, path::PathBuf};

fn main() {
    // without a server key the example skips the wss:// client
    println!("cargo:rerun-if-env-changed=WSS_SERVER_KEY_DER");
    let server_key = match env::var_os("WSS_SERVER_KEY_DER") {
        Some(path) => {
            println!("cargo:rerun-if-changed={}", path.to_string_lossy());
            fs::read(&path).expect("WSS_SERVER_KEY_DER names a readable DER file")
        }
        None => Vec::new(),
    };
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out.join("server-key.der"), server_key).unwrap();
}
