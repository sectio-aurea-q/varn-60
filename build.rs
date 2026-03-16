fn main() {
    println!("cargo:rustc-link-search=native=/opt/homebrew/lib");
    println!("cargo:rustc-link-lib=static=oqs");
    println!("cargo:rustc-link-search=native=/opt/homebrew/opt/openssl@3/lib");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo:rustc-link-lib=dylib=ssl");
}
