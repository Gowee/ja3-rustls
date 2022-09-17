/// [RFC8701](https://www.rfc-editor.org/rfc/rfc8701.html) GREASE values
use crate::utils::rand_in;

/// These values, when interpreted as big-endian u8 tuples, are reserved GREASE values for cipher
/// suites and Application-Layer Protocol Negotiation (ALPN).
/// When interpreted as u16, are reserved GREASE values for extensions, named groups,
/// signature algorithms, and versions:
pub const GREASE_U16_BE: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];
/// These values are reserved as GREASE values for PskKeyExchangeModes:
pub const GREASE_U8: [u8; 8] = [0x0B, 0x2A, 0x49, 0x68, 0x87, 0xA6, 0xC5, 0xE4];

#[inline(always)]
pub fn is_grease_u16_be(v: u16) -> bool {
    v & 0x0F0F == 0x0A0A
}

#[inline(always)]
pub fn is_grease_u8(v: u8) -> bool {
    GREASE_U8.iter().any(|&vv| v == vv)
}

/// Generate a random GREASE value.
///
/// It is based on an insecure RNG unless the `rand` crate feature is activated.
pub fn grease_u16_be() -> u16 {
    GREASE_U16_BE[rand_in::<0, 16>()]
}

/// Generate a random GREASE value.
///
/// It is based on an insecure RNG unless the `rand` crate feature is activated.
pub fn grease_u8() -> u8 {
    GREASE_U8[rand_in::<0, 8>()]
}

/// Try to rewrite a GREASE value with a randomly generated one iff it is actally GREASE.
/// Otherwise, the value is retuned as is.
///
/// It is based on an insecure RNG unless the `rand` crate feature is activated.
#[inline(always)]
pub fn try_regrease_u16_be(v: u16) -> u16 {
    if is_grease_u16_be(v) {
        grease_u16_be()
    } else {
        v
    }
}

/// Try to rewrite a GREASE value with a randomly generated one iff it is actally GREASE.
/// Otherwise, the value is retuned as is.
///
/// It is based on an insecure RNG unless the `rand` crate feature is activated.
#[inline(always)]
pub fn try_regrease_u8(v: u8) -> u8 {
    if is_grease_u8(v) {
        grease_u8()
    } else {
        v
    }
}
