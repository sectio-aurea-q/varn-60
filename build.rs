// build.rs — Link liboqs + OpenSSL + kperf from Homebrew/System
fn main() {
    // liboqs
    println!("cargo:rustc-link-search=native=/opt/homebrew/lib");
    println!("cargo:rustc-link-lib=static=oqs");

    // OpenSSL (liboqs depends on it for AES, SHA etc)
    println!("cargo:rustc-link-search=native=/opt/homebrew/opt/openssl@3/lib");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo:rustc-link-lib=dylib=ssl");

    // kperf (Apple private framework for Performance Counters)
    println!("cargo:rustc-link-search=framework=/System/Library/PrivateFrameworks");
}
