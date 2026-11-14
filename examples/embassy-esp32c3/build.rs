//! Places the root certificate of the wss:// server where the build finds it.

use std::{env, fs, path::PathBuf};

fn main() {
    // without a root certificate the example skips the wss:// client
    println!("cargo:rerun-if-env-changed=WSS_CA_DER");
    let ca = match env::var_os("WSS_CA_DER") {
        Some(path) => {
            println!("cargo:rerun-if-changed={}", path.to_string_lossy());
            fs::read(&path).expect("WSS_CA_DER names a readable DER file")
        }
        None => Vec::new(),
    };
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out.join("ca.der"), ca).unwrap();
}
