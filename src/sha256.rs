/// Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

/// Word size
const W: u32 = 32;

/// Rotate right (circular right shift) operation.
///
/// See: FIPS 180-4, 3.2
///
/// # Parameters
///
/// - `n`: An integer with `0 <= n < w`.
/// - `x`: `w`-bit word.
///
/// In our case, `w=32`.
fn rotr(n: u32, x: u32) -> u32 {
    let w = 32;
    assert!(n < w);
    // (x >> n) | (x << (w - n))
    x.wrapping_shr(n) | x.wrapping_shl(w - n)
}

/// Shift right operation.
///
/// See: FIPS 180-4, 3.2
///
/// # Parameters
///
/// - `n`: An integer with `0 <= n < w`.
/// - `x`: `w`-bit word.
///
/// In our case, `w=32`.
fn shr(n: u32, x: u32) -> u32 {
    let w = 32;
    assert!(n < w);
    x.wrapping_shr(n)
}

/// See: FIPS 180-4, 4.1.2

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn sum_0_256(x: u32) -> u32 {
    rotr(2, x) ^ rotr(13, x) ^ rotr(22, x)
}

fn sum_1_256(x: u32) -> u32 {
    rotr(6, x) ^ rotr(11, x) ^ rotr(25, x)
}

fn delta_0_256(x: u32) -> u32 {
    rotr(7, x) ^ rotr(18, x) ^ shr(3, x)
}

fn delta_1_256(x: u32) -> u32 {
    rotr(17, x) ^ rotr(19, x) ^ shr(10, x)
}

/// `WORDS` represent the first thirty-two bits of the fractional parts of the cube roots
/// of the first sixty-four prime numbers.
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

    let mut padded = message.to_vec();

    // Append "1" bit to the end of message
    padded.push(0x80);

    // Calculate k
    // We want: (l_bits + 1 + k) % 512 = 448
    // So: k = (448 - (l_bits + 1) % 512) % 512
    // But we need to handle the case where l_bits + 1 > 448
    let k_bits = (512 + 448 - (l_bits + 1) % 512) % 512;
    let k = k_bits / 8;

    // Append k zeros
    padded.extend(vec![0u8; k]);

    // Append l as a 64-bit big-endian integer
    padded.extend_from_slice(&(l_bits as u64).to_be_bytes());

    assert_eq!(padded.len() % 64, 0);

    padded
}

/// Initial hash value.
///
/// See: FIPS 180-4, 5.3.3
const IHV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Divides a padded message into 512-bit blocks.
///
/// See: FIPS 180-4, 5.2.1
///
///
/// # Parameters
///
/// - `message`: A message to be divided.
///
/// # Returns
///
/// A vector of 512-bit blocks.
fn message_to_blocks(message: &[u8]) -> Vec<Vec<u8>> {
    let blocks: Vec<Vec<u8>> = message.chunks(64).map(|chunk| chunk.to_vec()).collect();
    // We only need to check last chunk
    assert_eq!(blocks.last().map(|b| b.len()).unwrap_or(0), 64);
    blocks
}

/// Divides a 512-bit block into sixteen 32-bit words.
///
/// See: FIPS 180-4, 6.2.2
///
fn block_to_words(block: &[u8]) -> Vec<u32> {
    assert_eq!(block.len() % 4, 0);
    block
        .chunks(4)
        .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}

// SHA-256 Hash Computation
// See: FIPS 180-4, 6.2.2
fn compute_hash(blocks: &[Vec<u8>]) -> Vec<u8> {
    // SHA-256 Preprocessing
    let mut hash_value = Vec::with_capacity(blocks.len());
    hash_value.push(IHV);

    // Process every message block M_i
    for (index_i, block_m_i) in blocks.iter().enumerate() {
        // Prepare message schedule
        // First 16 words
        let mut message_schedule_w = block_to_words(block_m_i);
        // Remaining 48 words
        for index_t in 16..64 {
            let w_t = delta_1_256(message_schedule_w[index_t - 2])
                .wrapping_add(message_schedule_w[index_t - 7])
                .wrapping_add(delta_0_256(message_schedule_w[index_t - 15]))
                .wrapping_add(message_schedule_w[index_t - 16]);
            message_schedule_w.push(w_t);
        }
        assert_eq!(message_schedule_w.len(), 64);
        // Hash computation
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            hash_value[index_i][0],
            hash_value[index_i][1],
            hash_value[index_i][2],
            hash_value[index_i][3],
            hash_value[index_i][4],
            hash_value[index_i][5],
            hash_value[index_i][6],
            hash_value[index_i][7],
        );

        let mut temp_1;
        let mut temp_2;
        for t in 0..64 {
            temp_1 = h
                .wrapping_add(sum_1_256(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(WORDS_K[t])
                .wrapping_add(message_schedule_w[t]);
            temp_2 = sum_0_256(a).wrapping_add(maj(a, b, c));
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
        let new_layer = [
            a.wrapping_add(hash_value[index_i][0]),
            b.wrapping_add(hash_value[index_i][1]),
            c.wrapping_add(hash_value[index_i][2]),
            d.wrapping_add(hash_value[index_i][3]),
            e.wrapping_add(hash_value[index_i][4]),
            f.wrapping_add(hash_value[index_i][5]),
            g.wrapping_add(hash_value[index_i][6]),
            h.wrapping_add(hash_value[index_i][7]),
        ];
        hash_value.push(new_layer);
    }

    // Compute digest by combining the last layer of intermediate hash values
    let mut digest = Vec::new();
    for h in hash_value[hash_value.len() - 1].into_iter() {
        digest.extend_from_slice(&h.to_be_bytes());
    }

    digest
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
pub fn sha256(message: &[u8]) -> Vec<u8> {
    let padded = padding(message);
    let blocks = message_to_blocks(&padded);
    compute_hash(&blocks)
}

#[cfg(test)]
mod test {
    use super::*;
    use sha2::Digest;

    #[test]
    fn rotr_works() {
        // (n, x, expected_output)
        let test_vectors = [
            (0, 0x12345678, 0x12345678),
            (4, 0x12345678, 0x81234567),
            (8, 0x12345678, 0x78123456),
            (16, 0x12345678, 0x56781234),
            (24, 0x12345678, 0x34567812),
            (31, 0x12345678, 0x2468acf0),
        ];

        for &(n, x, expected) in &test_vectors {
            assert_eq!(rotr(n, x), expected);
        }
    }

    #[test]
    fn padding_works() {
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
            assert_eq!(output, expected);
        }
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
            (
                "RC4.16",
                &hex::encode(rc4_keystream(16)),
                "067c531269735ca7f541fdaca8f0dc76305d3cada140f89372a410fe5eff6e4d"
            ),
        ];

        for (name, input, expected) in test_vectors.iter() {
            let input_bytes = hex_to_bytes(input);
            let result = sha256(&input_bytes);
            assert_eq!(hex::encode(result), *expected, "Test vector '{}' failed", name);
        }
    }
    use std::str::FromStr;

    #[derive(Debug)]
    struct TestVector {
        identifier: String,
        input_length: usize,
        input_data: String,
        sha256_hash: Vec<u8>,
        sha_d256_hash: Vec<u8>,
    }

    fn parse_sha_d256_test_vectors(content: &str) -> Vec<TestVector> {
        let re = regex::Regex::new(r"^:(\S+)\s+(\d+)\s+(\S+)\s+([a-f0-9]{64})\s+([a-f0-9]{64})$")
            .unwrap();
        content
            .lines()
            .filter_map(|line| {
                re.captures(line).map(|caps| {
                    let input_data = caps[3].to_string();
                    TestVector {
                        identifier: caps[1].to_string(),
                        input_length: usize::from_str(&caps[2]).unwrap(),
                        input_data,
                        sha256_hash: hex::decode(&caps[4]).unwrap(),
                        sha_d256_hash: hex::decode(&caps[5]).unwrap(),
                    }
                })
            })
            .collect()
    }

    // Simple RC4 implementation for test vector generation
    fn rc4_keystream(length: usize) -> Vec<u8> {
        let mut s: Vec<u8> = (0..=255).collect();
        let mut j: u8 = 0;
        for i in 0..256 {
            // Key is all zeros
            j = j.wrapping_add(s[i]).wrapping_add(0);
            s.swap(i, j as usize);
        }
        let mut i: u8 = 0;
        j = 0;
        let mut result = Vec::with_capacity(length);
        for _ in 0..length {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
            result.push(k);
        }
        result
    }

    #[test]
    fn sha256_test_vectors() {
        let content = include_str!("../SHAd256_Test_Vectors.txt");
        let test_vectors = parse_sha_d256_test_vectors(content);

        for test_vec in test_vectors {
            let input = match test_vec.input_data.as_str() {
                "MILLION_a" => vec![b'a'; 1_000_000],
                "RC4" => rc4_keystream(test_vec.input_length),
                _ => hex::decode(&test_vec.input_data).unwrap(),
            };

            assert_eq!(
                input.len(),
                test_vec.input_length,
                "Input length mismatch for {}",
                test_vec.identifier
            );

            let sha256_hash = sha256(&input);
            assert_eq!(
                sha256_hash, test_vec.sha256_hash,
                "SHA-256 mismatch for {}",
                test_vec.identifier
            );

            let sha_d256_hash = sha256(&sha256_hash);
            assert_eq!(
                sha_d256_hash, test_vec.sha_d256_hash,
                "SHA_d-256 mismatch for {}",
                test_vec.identifier
            );
        }
    }
}
