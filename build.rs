use std::env;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(ossl111)");
    println!("cargo:rustc-check-cfg=cfg(libressl340)");

    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();

        if version >= 0x1010_1000 {
            println!("cargo:rustc-cfg=ossl111");
        }
    }

    if let Ok(v) = env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&v, 16).unwrap();

        if version >= 0x3040_0000 {
            println!("cargo:rustc-cfg=libressl340");
        }
    }
}
