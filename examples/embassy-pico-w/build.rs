//! Places `memory.x` and the certificate authority of the wss:// server where the build finds
//! them.

use std::{env, fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out.join("memory.x"), include_bytes!("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");

    // without a certificate authority the example skips the wss:// client
    println!("cargo:rerun-if-env-changed=WSS_CA_DER");
    let ca = match env::var_os("WSS_CA_DER") {
        Some(path) => {
            println!("cargo:rerun-if-changed={}", path.to_string_lossy());
            fs::read(&path).expect("WSS_CA_DER names a readable DER file")
        }
        None => Vec::new(),
    };
    fs::write(out.join("ca.der"), ca).unwrap();

    let firmware = PathBuf::from("firmware");
    for file in ["43439A0.bin", "43439A0_clm.bin", "nvram_rp2040.bin"] {
        assert!(
            firmware.join(file).exists(),
            "firmware/{file} is missing, run ./fetch-firmware.sh"
        );
    }
    println!("cargo:rerun-if-changed=firmware");

    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tlink-rp.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");
}
