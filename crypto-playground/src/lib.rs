#![flux::opts(scrape_quals = "true")]

flux_rs::defs! {
    qualifier Le10(v: int) { v <= 10 }
    qualifier Le8(v: int) { v <= 8 }
    qualifier Le5(v: int) { v <= 5 }
    qualifier Lt16(n: int) { n < 16 }
    qualifier Sum(len: int, i:int, n: int) { len + i == n }
}

pub mod aes;
// pub mod awslc;
pub mod bn;
pub mod ghash;
pub mod md5;
pub mod sha1;
pub mod sha256;
mod utils;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
// TODO(alevy): This should be computed as in AWS-LC's 'crypto/fipsmodule/cpucap'
// Setting to 0 assumes no special crypto instructions (NEON, AES, PMULL, SHA1, SHA256, SHA512, SHA3, CPUID)
#[no_mangle]
pub static OPENSSL_armcap_P: usize = 0;

extern crate flux_alloc;
extern crate flux_core;
