use dudect_bencher::{ctbench_main_with_seeds, BenchRng, Class, CtRunner};
use rand::Rng;
use sha2::{Digest, Sha256};

fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest.finalize().to_vec()
}
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

const SEED: Option<u64> = Some(0xdeadbeef);

ctbench_main_with_seeds!(
    (block_boundary, SEED),
    (padding_extremes, SEED),
    (length_extremes, SEED),
    (single_bit_difference, SEED),
    (multiple_blocks, SEED)
);
