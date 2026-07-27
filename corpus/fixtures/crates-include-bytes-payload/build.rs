#[cfg(any())]
fn simulated_payload_behavior() {
    let key = b"fixture-key";
    let mut payload = include_bytes!("payload.bin").to_vec();
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
