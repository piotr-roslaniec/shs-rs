//! SHA-256 implementation based on FIPS 180-4 specification.
//!
//! This module provides a Rust implementation of the SHA-256 cryptographic hash function
//! as defined in the Federal Information Processing Standards (FIPS) Publication 180-4.
//!
//! # References
//!
//! - [FIPS 180-4 Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
//!
//! # Examples
//!
//! ```
//! use shs_rs::sha256::sha256;
//!
//! let message = b"Hello, world!";
//! let digest = sha256(message);
//! println!("SHA-256 digest: {:x?}", digest);
//! ```

use subtle::{ConditionallySelectable, ConstantTimeEq};

/// Rotate right (circular right shift) operation.
///
/// See: FIPS 180-4, 3.2
///
/// # Parameters
///
/// - `x`: `W`-bit word.
const fn rotr<const N: u32>(x: u32) -> u32 { x.rotate_right(N) }

/// Shift right operation.
///
/// See: FIPS 180-4, 3.2
///
/// # Parameters
///
/// - `n`: An integer with `0 <= n < 32`.
const fn shr<const N: u32>(x: u32) -> u32 { x.wrapping_shr(N) }

/// See: FIPS 180-4, 4.1.2

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }

const fn csigma0(x: u32) -> u32 { rotr::<2>(x) ^ rotr::<13>(x) ^ rotr::<22>(x) }

const fn csigma1(x: u32) -> u32 { rotr::<6>(x) ^ rotr::<11>(x) ^ rotr::<25>(x) }

const fn sigma0(x: u32) -> u32 { rotr::<7>(x) ^ rotr::<18>(x) ^ shr::<3>(x) }

const fn sigma1(x: u32) -> u32 { rotr::<17>(x) ^ rotr::<19>(x) ^ shr::<10>(x) }

/// `WORDS_K`, also known as "round constants",  represent the first thirty-two bits of the
/// fractional parts of the cube roots of the first sixty-four prime numbers.
///
/// See: FIPS 180-4, 4.2.2
const WORDS_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Pad a message into a multiple of 512 bits.
///
/// See: FIPS 180-4, 5.1.1
///
/// # Parameters
///
/// - `message`: A message to pad.
///
/// # Returns
///
/// A padded message ready to be transformed.
fn padding(message: &[u8]) -> Vec<u8> {
    let l_bits = message.len() * 8;

    // Pre-allocate the maximum possible size to avoid potential timing attacks based on allocation
    // Maximum padding (512 bits) + 64-bit length
    let max_padding = 64 + 8;
    let mut padded = Vec::with_capacity(message.len() + max_padding);

    padded.extend_from_slice(message);

    // Append "1" bit to the end of message
    padded.push(0x80);

    // Calculate k bits in constant time
    // We want: (l_bits + 1 + k) % 512 = 448
    // So: k = (448 - (l_bits + 1) % 512) % 512
    // But we need to handle the case where l_bits + 1 > 448
    let k_bits = {
        let mut k = 0u32;
        for i in 0..512u32 {
            let condition = ((512 + 448 - (l_bits as u32 + 1 + i) % 512) % 512).ct_eq(&0);
            k = u32::conditional_select(&k, &i, condition);
        }
        k
    };
    let k = k_bits / 8;

    // Append k zeros
    padded.extend(vec![0u8; k as usize]);

    // Append l as a 64-bit big-endian integer
    padded.extend_from_slice(&(l_bits as u64).to_be_bytes());

    debug_assert_eq!(padded.len() % 64, 0, "Padding did not result in a multiple of 512 bits");

    padded
}

/// Initial hash value.
///
/// See: FIPS 180-4, 5.3.3
pub const IHV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 Hash Computation
///
/// See: FIPS 180-4, 6.2.2
///
/// # Parameters
///
/// - `blocks` - A message to compute digest over, already divided into 512-bit blocks.
///
/// # Returns
///
/// A 256-bit digest of `blocks`.
pub fn compute_hash(initial_state: [u32; 8], blocks: &[&[u8]]) -> [u8; 32] {
    // SHA-256 Preprocessing
    let mut hash_value = initial_state;

    // Process every message block M_i
    for block in blocks.iter() {
        let mut w = [0u32; 64];

        // Prepare message schedule
        for t in 0..16 {
            // Divide a 512-bit block into sixteen 32-bit words
            // See: FIPS 180-4, 6.2.2
            w[t] = u32::from_be_bytes([
                block[4 * t],
                block[4 * t + 1],
                block[4 * t + 2],
                block[4 * t + 3],
            ]);
        }
        // Remaining 48 words
        for t in 16..64 {
            w[t] = sigma1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(sigma0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        // Hash computation
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            hash_value[0],
            hash_value[1],
            hash_value[2],
            hash_value[3],
            hash_value[4],
            hash_value[5],
            hash_value[6],
            hash_value[7],
        );

        let mut temp_1;
        let mut temp_2;
        for t in 0..64 {
            temp_1 = h
                .wrapping_add(csigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(WORDS_K[t])
                .wrapping_add(w[t]);
            temp_2 = csigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp_1);
            d = c;
            c = b;
            b = a;
            a = temp_1.wrapping_add(temp_2);
        }

        // Compute intermediate hash values
        hash_value[0] = hash_value[0].wrapping_add(a);
        hash_value[1] = hash_value[1].wrapping_add(b);
        hash_value[2] = hash_value[2].wrapping_add(c);
        hash_value[3] = hash_value[3].wrapping_add(d);
        hash_value[4] = hash_value[4].wrapping_add(e);
        hash_value[5] = hash_value[5].wrapping_add(f);
        hash_value[6] = hash_value[6].wrapping_add(g);
        hash_value[7] = hash_value[7].wrapping_add(h);
    }

    // Final digest
    let mut result = [0u8; 32];
    for (i, &word) in hash_value.iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    result
}

/// Compute SHA-256 digest of a message.
///
/// # Parameters
///
/// - `message`: Input message to hash.
///
/// # Returns
///
/// 256-bit digest of the `message`.
///
/// # Examples
///
/// ```
/// use shs_rs::sha256::sha256;
/// let message = b"Hello, world!";
/// let digest = sha256(message);
/// println!("SHA-256 digest: {:x?}", digest);
/// ```
pub fn sha256(message: &[u8]) -> [u8; 32] {
    let padded = padding(message);
    // Divide the message into 512-bit blocks: FIPS 180-4, 5.2.1
    let blocks: Vec<&[u8]> = padded.chunks_exact(64).collect();
    compute_hash(IHV, &blocks)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rotr() {
        assert_eq!(rotr::<0>(0x12345678), 0x12345678);
        assert_eq!(rotr::<4>(0x12345678), 0x81234567);
        assert_eq!(rotr::<8>(0x12345678), 0x78123456);
        assert_eq!(rotr::<16>(0x12345678), 0x56781234);
        assert_eq!(rotr::<24>(0x12345678), 0x34567812);
        assert_eq!(rotr::<31>(0x12345678), 0x2468acf0);
    }

    #[test]
    fn test_padding() {
        // (input, expected_output)
        let test_vectors = [
            (vec![0x61], [vec![0x61, 0x80], vec![0; 61], vec![8]].concat()),
            (vec![0x61, 0x62], [vec![0x61, 0x62, 0x80], vec![0; 60], vec![16]].concat()),
            (
                [vec![0x61, 0x62], vec![0; 64]].concat(),
                [vec![0x61, 0x62], vec![0; 64], vec![128], vec![0; 59], vec![2, 16]].concat(),
            ),
        ];

        for (input, expected) in test_vectors.into_iter() {
            let input = input.clone();
            let output = padding(&input);
            assert_eq!(output.len() % 64, 0);
            assert_eq!(output.len(), expected.len());
            assert_eq!(output.to_vec(), expected);
        }
    }

    #[test]
    fn test_initial_hash_values() {
        // Checks whether `IHV` vector contains correct values as per FIPS.

        // The first 8 prime numbers
        let primes: [u32; 8] = [2, 3, 5, 7, 11, 13, 17, 19];
        let generated_ihv: Vec<u32> = primes
            .into_iter()
            .map(|prime| {
                // Calculate the square root and its fractional part
                let sqrt_fractional = (prime as f64).sqrt() - (prime as f64).sqrt().floor();
                // Convert the fractional part to a 32-bit word
                (sqrt_fractional * (1_u64 << 32) as f64) as u32
            })
            .collect();
        let generated_ihv: [u32; 8] = generated_ihv.try_into().unwrap();

        assert_eq!(IHV, generated_ihv);
    }

    #[test]
    fn test_words_k() {
        // Checks whether `WORDS_K` vector contains correct values as per FIPS.

        // The first 64 prime numbers
        let primes: [u32; 64] = [
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
            89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
            181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
            277, 281, 283, 293, 307, 311,
        ];
        let generated_words_k: Vec<u32> = primes
            .into_iter()
            .map(|prime| {
                // Compute the cube root of the prime and subtract the integer part
                let cube_root_fractional = (prime as f64).cbrt() - (prime as f64).cbrt().floor();
                // Convert the fractional part to a 32-bit word
                (cube_root_fractional * (1_u64 << 32) as f64) as u32
            })
            .collect();
        let generated_words_k: [u32; 64] = generated_words_k.try_into().unwrap();

        assert_eq!(WORDS_K, generated_words_k);
    }

    #[test]
    fn test_sha256() {
        let test_cases = [
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];

        for (input, expected) in test_cases.iter() {
            let result = sha256(input.as_bytes());
            assert_eq!(hex::encode(result), *expected);
        }
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn test_sha256_vectors() {
        let test_vectors = [
            (
                "NIST.1",
                "616263",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            ),
            (
                "NIST.2",
                "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
            ),
            (
                "EMPTY",
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
        ];

        for (name, input, expected) in test_vectors.iter() {
            let input_bytes = hex_to_bytes(input);
            let result = sha256(&input_bytes);
            assert_eq!(hex::encode(result), *expected, "Test vector '{}' failed", name);
        }
    }
}
