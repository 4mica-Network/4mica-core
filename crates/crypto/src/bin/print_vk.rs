//! Derive the on-chain BLS guarantee verification key from a BLS secret key.
//!
//! The `Core4MicaFullStack` deploy script expects the guarantee verification key
//! as four 32-byte words (`VK_X0`, `VK_X1`, `VK_Y0`, `VK_Y1`). The core service
//! signs guarantees with `BLS_PRIVATE_KEY`, so the on-chain key must be derived
//! from that same secret or on-chain BLS verification (remuneration / claim
//! flows) will reject valid certificates.
//!
//! Usage:
//!   print-vk <bls_private_key_hex>
//!   BLS_PRIVATE_KEY=0x.. print-vk
//!
//! By default it prints shell `export` lines so callers can `eval` the output:
//!   eval "$(BLS_PRIVATE_KEY=0x.. cargo run -q -p crypto-4mica --bin print-vk)"

use std::str::FromStr;

use crypto::bls::KeyMaterial;

fn main() {
    let key_hex = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("BLS_PRIVATE_KEY").ok())
        .unwrap_or_else(|| {
            eprintln!(
                "error: provide the BLS secret key as an argument or via BLS_PRIVATE_KEY env var"
            );
            std::process::exit(1);
        });

    let key = KeyMaterial::from_str(key_hex.trim()).unwrap_or_else(|err| {
        eprintln!("error: invalid BLS secret key: {err}");
        std::process::exit(1);
    });

    let words = key.public_key().to_solidity_words().unwrap_or_else(|err| {
        eprintln!("error: failed to derive verification key words: {err}");
        std::process::exit(1);
    });

    let labels = ["VK_X0", "VK_X1", "VK_Y0", "VK_Y1"];
    for (label, word) in labels.iter().zip(words.iter()) {
        println!("export {label}=0x{}", hex::encode(word));
    }
}
