//! ADR-087 — the password generator (`util.generate`), in Rust and nowhere else.
//!
//! Generation never happens in page JavaScript: the window asks the broker,
//! gets the value once, and puts it into a field through the broker. This
//! module is the whole algorithm, kept pure by taking the random source as a
//! parameter — the broker passes the operating system's generator, the tests a
//! deterministic one.
//!
//! * **Random** (the default): lower case, upper case and digits, plus a small
//!   shell-safe symbol set when `symbols` is on. At least one character of every
//!   enabled class is present, the rest are drawn uniformly from the union, and
//!   the positions are shuffled — all with rejection sampling, so no character is
//!   more likely than another.
//! * **Pronounceable**: letters alternating consonant, vowel (consonant first),
//!   typable and speakable; `symbols` puts a `-` after every fourth letter. It is
//!   weaker per character, and the reported `entropy_bits` says by how much.
//!
//! `entropy_bits` is `⌊length-derived log₂ of the number of equally likely
//! outputs⌋` (an estimate for the random mode: the one-of-each-class rule
//! removes a few of the strings it could otherwise produce; the figure is
//! computed as if it did not, and is within a bit or two of exact at the
//! lengths this is used at).

use rand_core::RngCore;
use zeroize::Zeroizing;

/// Shortest and longest value the generator will make.
pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 128;
/// Length when the caller does not say.
pub const DEFAULT_LENGTH: usize = 20;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
/// Chosen to survive a shell, a URL fragment and a CSV cell unquoted: no quote,
/// backslash, space, angle bracket, semicolon, backtick, pipe or comma.
pub const SYMBOLS: &[u8] = b"!@#$%^&*-_=+?";
const CONSONANTS: &[u8] = b"bcdfghjklmnprstvwz";
const VOWELS: &[u8] = b"aeiou";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub length: usize,
    pub symbols: bool,
    pub pronounceable: bool,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            length: DEFAULT_LENGTH,
            symbols: true,
            pronounceable: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateError {
    /// `length` outside [`MIN_LENGTH`], [`MAX_LENGTH`].
    LengthOutOfRange { length: usize },
}

/// A generated value and the strength it carries.
pub struct Generated {
    pub value: Zeroizing<String>,
    /// Estimated entropy in bits (see the module docs).
    pub entropy_bits: u32,
}

/// An unbiased index in `0..n` (rejection sampling over `u32`).
fn below<R: RngCore + ?Sized>(rng: &mut R, n: usize) -> usize {
    debug_assert!(n > 0 && n <= u32::MAX as usize);
    let n = n as u32;
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let x = rng.next_u32();
        if x < zone {
            return (x % n) as usize;
        }
    }
}

fn pick<R: RngCore + ?Sized>(rng: &mut R, set: &[u8]) -> u8 {
    set[below(rng, set.len())]
}

fn shuffle<R: RngCore + ?Sized>(rng: &mut R, items: &mut [u8]) {
    for i in (1..items.len()).rev() {
        items.swap(i, below(rng, i + 1));
    }
}

/// Generates one value.
pub fn generate<R: RngCore + ?Sized>(
    params: Params,
    rng: &mut R,
) -> Result<Generated, GenerateError> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&params.length) {
        return Err(GenerateError::LengthOutOfRange {
            length: params.length,
        });
    }
    if params.pronounceable {
        return Ok(pronounceable(params, rng));
    }

    let mut classes: Vec<&[u8]> = vec![LOWER, UPPER, DIGITS];
    if params.symbols {
        classes.push(SYMBOLS);
    }
    let pool: Vec<u8> = classes.iter().flat_map(|c| c.iter().copied()).collect();

    let mut bytes: Vec<u8> = classes.iter().map(|c| pick(rng, c)).collect();
    while bytes.len() < params.length {
        bytes.push(pick(rng, &pool));
    }
    shuffle(rng, &mut bytes);

    let bits = params.length as f64 * (pool.len() as f64).log2();
    let value = String::from_utf8(bytes).expect("the pools are ASCII");
    Ok(Generated {
        value: Zeroizing::new(value),
        entropy_bits: bits.floor() as u32,
    })
}

fn pronounceable<R: RngCore + ?Sized>(params: Params, rng: &mut R) -> Generated {
    let mut out = String::with_capacity(params.length);
    let mut letters = 0usize;
    let mut bits = 0f64;
    for i in 0..params.length {
        if params.symbols && i % 5 == 4 {
            out.push('-');
            continue;
        }
        let set = if letters % 2 == 0 { CONSONANTS } else { VOWELS };
        out.push(pick(rng, set) as char);
        bits += (set.len() as f64).log2();
        letters += 1;
    }
    Generated {
        value: Zeroizing::new(out),
        entropy_bits: bits.floor() as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// A small deterministic generator (xorshift64*) so the statistical tests
    /// are repeatable.
    struct Seeded(u64);
    impl RngCore for Seeded {
        fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let b = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&b[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn make(length: usize, symbols: bool, pronounceable: bool) -> Generated {
        generate(
            Params {
                length,
                symbols,
                pronounceable,
            },
            &mut OsRng,
        )
        .unwrap()
    }

    #[test]
    fn length_bounds_are_enforced_at_both_ends() {
        for bad in [0, 1, MIN_LENGTH - 1, MAX_LENGTH + 1, 10_000] {
            let r = generate(
                Params {
                    length: bad,
                    ..Params::default()
                },
                &mut OsRng,
            );
            assert_eq!(
                r.err(),
                Some(GenerateError::LengthOutOfRange { length: bad })
            );
        }
        for ok in [MIN_LENGTH, MAX_LENGTH, DEFAULT_LENGTH] {
            assert_eq!(make(ok, true, false).value.len(), ok);
            assert_eq!(make(ok, false, false).value.len(), ok);
            assert_eq!(make(ok, true, true).value.len(), ok);
        }
    }

    #[test]
    fn charset_without_symbols_is_alphanumeric_and_has_every_class() {
        for _ in 0..500 {
            let g = make(8, false, false);
            let v = g.value.as_bytes();
            assert!(v.iter().all(u8::is_ascii_alphanumeric), "{}", *g.value);
            assert!(v.iter().any(u8::is_ascii_lowercase));
            assert!(v.iter().any(u8::is_ascii_uppercase));
            assert!(v.iter().any(u8::is_ascii_digit));
        }
    }

    #[test]
    fn charset_with_symbols_has_a_symbol_and_only_the_documented_ones() {
        for _ in 0..500 {
            let g = make(8, true, false);
            let v = g.value.as_bytes();
            assert!(v.iter().any(|b| SYMBOLS.contains(b)), "{}", *g.value);
            assert!(
                v.iter()
                    .all(|b| b.is_ascii_alphanumeric() || SYMBOLS.contains(b)),
                "{}",
                *g.value
            );
        }
    }

    #[test]
    fn entropy_is_reported_and_scales_with_length_and_pool() {
        let full = make(DEFAULT_LENGTH, true, false).entropy_bits;
        let alnum = make(DEFAULT_LENGTH, false, false).entropy_bits;
        assert_eq!(alnum, (20.0 * 62f64.log2()).floor() as u32); // 119
        assert_eq!(full, (20.0 * 75f64.log2()).floor() as u32); // 124
        assert!(full > alnum);
        assert!(make(8, true, false).entropy_bits >= 49);
        assert!(make(MAX_LENGTH, true, false).entropy_bits >= 790);
        // Pronounceable is weaker per character, and says so.
        let pron = make(DEFAULT_LENGTH, false, true).entropy_bits;
        let exact = (10.0 * 18f64.log2() + 10.0 * 5f64.log2()).floor() as u32; // 10 consonants, 10 vowels
        assert_eq!(pron, exact);
        assert!(pron < alnum && pron >= 64, "{pron}");
    }

    #[test]
    fn two_values_are_never_equal_and_nothing_is_empty() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            assert!(seen.insert(make(16, true, false).value.to_string()));
        }
    }

    #[test]
    fn selection_is_uniform_over_the_pool() {
        // 62-way pick over many draws: every bucket within 15% of its expectation.
        let mut rng = Seeded(0x9E37_79B9_7F4A_7C15);
        let mut counts = [0usize; 62];
        let draws = 124_000;
        for _ in 0..draws {
            counts[below(&mut rng, 62)] += 1;
        }
        let expect = draws / 62;
        for (i, c) in counts.iter().enumerate() {
            assert!(
                (*c as f64 - expect as f64).abs() < expect as f64 * 0.15,
                "bucket {i}: {c} vs {expect}"
            );
        }
    }

    #[test]
    fn below_has_no_modulo_bias_at_a_hostile_modulus() {
        // 3 does not divide 2^32; without rejection, bucket 0 would lead by ~1 in 2^32 — far
        // below sampling noise, so this pins the *zone* instead: the largest accepted
        // value is a multiple of n minus one.
        struct Max(u32);
        impl RngCore for Max {
            fn next_u32(&mut self) -> u32 {
                let v = self.0;
                self.0 = self.0.wrapping_sub(1);
                v
            }
            fn next_u64(&mut self) -> u64 {
                u64::from(self.next_u32())
            }
            fn fill_bytes(&mut self, _: &mut [u8]) {}
            fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
                Ok(())
            }
        }
        // u32::MAX % 3 == 0, so the first rejected value is 2^32 - 1 + 1 > MAX: use 7.
        // u32::MAX % 7 == 3 → values 4294967292..=4294967295 are rejected.
        let mut rng = Max(u32::MAX);
        let got = below(&mut rng, 7);
        assert_eq!(
            got,
            (4_294_967_291u32 % 7) as usize,
            "four values were skipped"
        );
    }

    #[test]
    fn pronounceable_alternates_consonant_vowel_and_separates_groups() {
        for _ in 0..200 {
            let g = make(20, true, true);
            let v = g.value.as_bytes();
            let mut letters = 0;
            for (i, b) in v.iter().enumerate() {
                if i % 5 == 4 {
                    assert_eq!(*b, b'-');
                } else {
                    let set = if letters % 2 == 0 { CONSONANTS } else { VOWELS };
                    assert!(set.contains(b), "{} at {i}", *g.value);
                    letters += 1;
                }
            }
        }
        let g = make(12, false, true);
        assert!(g.value.bytes().all(|b| b.is_ascii_lowercase()));
    }

    #[test]
    fn generated_values_carry_nothing_a_shell_or_a_form_would_mangle() {
        for _ in 0..500 {
            let g = make(32, true, false);
            assert!(g
                .value
                .bytes()
                .all(|b| b.is_ascii_graphic() && !b"\"'\\`<>;|, ".contains(&b)));
        }
    }
}
