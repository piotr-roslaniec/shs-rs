use std::{str::FromStr, sync::Arc};

use rayon::prelude::*;
use shs_rs::sha256::sha256;

#[derive(Debug)]
pub struct TestVector {
    pub identifier:    String,
    pub input_length:  usize,
    pub input_data:    String,
    pub sha256_hash:   Vec<u8>,
    pub sha_d256_hash: Vec<u8>,
}

pub fn parse_sha_d256_test_vectors(content: &str) -> Vec<TestVector> {
    let re =
        regex::Regex::new(r"^:(\S+)\s+(\d+)\s+(\S+)\s+([a-f0-9]{64})\s+([a-f0-9]{64})$").unwrap();
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
pub fn rc4_keystream(length: usize) -> Vec<u8> {
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
#[ignore]
fn sha256_comprehensive_test_vectors() {
    let content = include_str!("../SHAd256_Test_Vectors.txt");
    let test_vectors = Arc::new(parse_sha_d256_test_vectors(content));

    let results: Vec<_> = test_vectors
        .par_iter()
        .map(|test_vec| {
            let input = match test_vec.input_data.as_str() {
                "MILLION_a" => vec![b'a'; 1_000_000],
                "RC4" => rc4_keystream(test_vec.input_length),
                _ => hex::decode(&test_vec.input_data).unwrap(),
            };

            let input_len_match = input.len() == test_vec.input_length;
            let sha256_hash = sha256(&input).to_vec();
            let sha256_match = sha256_hash == test_vec.sha256_hash;
            let sha_d256_hash = sha256(&sha256_hash).to_vec();
            let sha_d256_match = sha_d256_hash == test_vec.sha_d256_hash;

            (test_vec.identifier.clone(), input_len_match, sha256_match, sha_d256_match)
        })
        .collect();

    for (identifier, input_len_match, sha256_match, sha_d256_match) in results {
        assert!(input_len_match, "Input length mismatch for {}", identifier);
        assert!(sha256_match, "SHA-256 mismatch for {}", identifier);
        assert!(sha_d256_match, "SHA_d-256 mismatch for {}", identifier);
    }
}
