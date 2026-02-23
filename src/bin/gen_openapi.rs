//! Generates openapi.json at the project root.
//!
//! Usage: cargo run --bin gen_openapi

use proxy_rotator::api;
use std::path::Path;

fn main() {
    let json = api::openapi_json();
    let out_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("openapi.json");
    std::fs::write(&out_path, &json)
        .unwrap_or_else(|e| panic!("Failed to write {}: {e}", out_path.display()));
    println!("Wrote {}", out_path.display());
}
