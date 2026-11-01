//! A ten-line hex codec so `registry.sig`/manifest hmac/generation-counter
//! tags can be stored as readable text without pulling in the `hex` crate
//! for one function's worth of use — same minimal-dependency reasoning as
//! ADR-039's path resolution and ADR-040's epoch timestamps.

pub fn encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").expect("writing to a String cannot fail");
    }
    out
}

pub fn decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let bytes = [0u8, 1, 254, 255, 16, 17];
        let mut full = [0u8; 32];
        full[..6].copy_from_slice(&bytes);
        assert_eq!(decode_32(&encode(&full)).unwrap(), full);
    }

    #[test]
    fn wrong_length_is_none() {
        assert_eq!(decode_32("ab"), None);
    }

    #[test]
    fn non_hex_is_none() {
        assert_eq!(decode_32(&"z".repeat(64)), None);
    }
}
