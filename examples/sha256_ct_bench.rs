use dudect_bencher::{ctbench_main_with_seeds, BenchRng, Class, CtRunner};
use rand::Rng;
use shs_rs::sha256::{compute_hash, sha256, IHV};

const ITERATIONS: u32 = 20_000;

fn rand_vec(len: usize, rng: &mut BenchRng) -> Vec<u8> {
    let mut arr = vec![0u8; len];
    rng.fill(arr.as_mut_slice());
    arr
}

fn run_scenario(runner: &mut CtRunner, rng: &mut BenchRng, len_left: usize, len_right: usize) {
    for _ in 0..ITERATIONS {
        let left = rand_vec(len_left, rng);
        let right = rand_vec(len_right, rng);

        runner.run_one(Class::Left, || {
            sha256(&left);
        });
        runner.run_one(Class::Right, || {
            sha256(&right);
        });
    }
}

fn block_boundary(runner: &mut CtRunner, rng: &mut BenchRng) { run_scenario(runner, rng, 63, 65); }

fn padding_extremes(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_scenario(runner, rng, 55, 56);
}

fn length_extremes(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_scenario(runner, rng, 1, 1000);
}

fn single_bit_difference(runner: &mut CtRunner, rng: &mut BenchRng) {
    for _ in 0..ITERATIONS {
        let left = rand_vec(64, rng);
        let mut right = left.clone();

        let byte_to_change = rng.gen_range(0..right.len());
        let bit_to_change = rng.gen_range(0..8);
        right[byte_to_change] ^= 1 << bit_to_change;

        runner.run_one(Class::Left, || {
            sha256(&left);
        });
        runner.run_one(Class::Right, || {
            sha256(&right);
        });
    }
}

fn multiple_blocks(runner: &mut CtRunner, rng: &mut BenchRng) {
    run_scenario(runner, rng, 128, 128);
}

fn padding_behavior(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Test inputs that trigger different padding behaviors
    run_scenario(runner, rng, 55, 56); // Before block boundary
    run_scenario(runner, rng, 63, 64); // Block boundary
    run_scenario(runner, rng, 119, 120); // Two block boundary
}

fn special_values_all_zeros(runner: &mut CtRunner, rng: &mut BenchRng) {
    for _ in 0..ITERATIONS {
        let special = vec![0u8; 64]; // All zeros
        let random = rand_vec(64, rng);

        runner.run_one(Class::Left, || {
            sha256(&special);
        });
        runner.run_one(Class::Right, || {
            sha256(&random);
        });
    }
}

fn special_values_all_ones(runner: &mut CtRunner, rng: &mut BenchRng) {
    for _ in 0..ITERATIONS {
        let special = vec![0xFFu8; 64]; // All ones
        let random = rand_vec(64, rng);

        runner.run_one(Class::Left, || {
            sha256(&special);
        });
        runner.run_one(Class::Right, || {
            sha256(&random);
        });
    }
}

fn special_values_alternating_bits(runner: &mut CtRunner, rng: &mut BenchRng) {
    for _ in 0..ITERATIONS {
        let special = vec![0xAAu8; 64]; // Alternating bits (10101010)
        let random = rand_vec(64, rng);

        runner.run_one(Class::Left, || {
            sha256(&special);
        });
        runner.run_one(Class::Right, || {
            sha256(&random);
        });
    }
}

fn special_values_single_one(runner: &mut CtRunner, rng: &mut BenchRng) {
    for _ in 0..ITERATIONS {
        let mut special = vec![0u8; 64];
        special[63] = 1; // Only the last bit is 1
        let random = rand_vec(64, rng);

        runner.run_one(Class::Left, || {
            sha256(&special);
        });
        runner.run_one(Class::Right, || {
            sha256(&random);
        });
    }
}

fn special_values_high_low_bytes(runner: &mut CtRunner, rng: &mut BenchRng) {
    for _ in 0..ITERATIONS {
        let mut special = vec![0u8; 64];
        for (i, byte) in special.iter_mut().enumerate().take(64) {
            *byte = if i % 2 == 0 { 0x00 } else { 0xFF };
        }
        let random = rand_vec(64, rng);

        runner.run_one(Class::Left, || {
            sha256(&special);
        });
        runner.run_one(Class::Right, || {
            sha256(&random);
        });
    }
}

fn special_values_ascending(runner: &mut CtRunner, rng: &mut BenchRng) {
    for _ in 0..ITERATIONS {
        let special: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let random = rand_vec(64, rng);

        runner.run_one(Class::Left, || {
            sha256(&special);
        });
        runner.run_one(Class::Right, || {
            sha256(&random);
        });
    }
}

fn length_dependent_timing(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Test a range of lengths to detect any length-dependent timing
    for i in 1..=64 {
        let left = rand_vec(i, rng);
        let right = rand_vec(64, rng); // Fixed length for comparison

        runner.run_one(Class::Left, || {
            sha256(&left);
        });
        runner.run_one(Class::Right, || {
            sha256(&right);
        });
    }
}

fn block_processing_consistency(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Compare single-block vs multi-block processing
    run_scenario(runner, rng, 63, 65); // Single vs two blocks
    run_scenario(runner, rng, 64, 128); // One vs two full blocks
}

fn intermediate_state_dependency(runner: &mut CtRunner, rng: &mut BenchRng) {
    for _ in 0..ITERATIONS {
        let left = rand_vec(128, rng);
        let mut right = left.clone();

        // Modify the second block, which should affect intermediate state
        for byte in right.iter_mut().skip(64).take(64) {
            *byte = rng.gen();
        }

        runner.run_one(Class::Left, || {
            sha256(&left);
        });
        runner.run_one(Class::Right, || {
            sha256(&right);
        });
    }
}

fn compression_function_test(runner: &mut CtRunner, rng: &mut BenchRng) {
    for _ in 0..ITERATIONS {
        let block1 = rand_vec(64, rng);
        let block2 = rand_vec(64, rng);

        runner.run_one(Class::Left, || {
            compute_hash(IHV, &[&block1]);
        });
        runner.run_one(Class::Right, || {
            compute_hash(IHV, &[&block2]);
        });
    }
}

fn compression_function_multiple_blocks(runner: &mut CtRunner, rng: &mut BenchRng) {
    for _ in 0..ITERATIONS {
        let blocks1 = vec![rand_vec(64, rng), rand_vec(64, rng)];
        let blocks2 = vec![rand_vec(64, rng), rand_vec(64, rng)];

        runner.run_one(Class::Left, || {
            compute_hash(IHV, &blocks1.iter().map(|b| b.as_slice()).collect::<Vec<_>>());
        });
        runner.run_one(Class::Right, || {
            compute_hash(IHV, &blocks2.iter().map(|b| b.as_slice()).collect::<Vec<_>>());
        });
    }
}

fn compression_function_special_patterns(runner: &mut CtRunner, rng: &mut BenchRng) {
    for _ in 0..ITERATIONS {
        let mut special_block = vec![0u8; 64];
        let random_block = rand_vec(64, rng);

        // Test with all zeros, all ones, and alternating bits
        for pattern in &[0x00, 0xFF, 0xAA] {
            special_block.fill(*pattern);

            runner.run_one(Class::Left, || {
                compute_hash(IHV, &[&special_block]);
            });
            runner.run_one(Class::Right, || {
                compute_hash(IHV, &[&random_block]);
            });
        }
    }
}

const SEED: Option<u64> = Some(0xdeadbeef);

ctbench_main_with_seeds!(
    (length_extremes, SEED),
    (single_bit_difference, SEED),
    (padding_behavior, SEED),
    (block_processing_consistency, SEED),
    (special_values_all_zeros, SEED),
    (special_values_all_ones, SEED),
    (special_values_alternating_bits, SEED),
    (special_values_single_one, SEED),
    (special_values_high_low_bytes, SEED),
    (special_values_ascending, SEED),
    (length_dependent_timing, SEED),
    (intermediate_state_dependency, SEED),
    (compression_function_test, SEED),
    (compression_function_multiple_blocks, SEED),
    (compression_function_special_patterns, SEED)
);
