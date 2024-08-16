# shs-rs

An educational implementation of Secure Hash Standard in Rust.

Based on [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). Currently only implements SHA256.

Please don`t use this code in production, and so on.

## Test vectors

This repo contains a copy of test vectors used in unit tests.

Download test vectors by running:

```bash
wget https://www.dlitz.net/crypto/shad256-test-vectors/SHAd256_Test_Vectors.txt .
```

Long-running tests are placed in `tests/` directory and mark as `ignore`-d by default. Run them with:

```bash
cargo test --release -- --ignored
```

You can run regular unit tests with:

```bash
cargo test
```

## Benchmarks

First, install `criterion-table`:

```bash
cargo install criterion-table
```

Run all benchmarks and convert into the markdown all in one step

```bash
cargo criterion --message-format=json | criterion-table > BENCHMARKS.md
```

## Constant-time analysis

In order to run a single CT benchmark, run:

```bash
cargo +stable run --example sha256_ct_bench --release
```

In order to run CT benchmarks for all compilation targets in debug and release mode, run:

```bash
bash ./scripts/run_ct_benches.bash 
```

Check out how a reference implementation, `sha2:Sha256` performs in CT benchmarks:

```bash
cargo +stable run --example reference_sha256_ct_bench --release
```

## Evaluating CT benchmarks

See [`dudect-bencher` docs](https://github.com/rozbb/dudect-bencher/#bencher-output) for more information.

Example output:

```
bench block_boundary        ... : n == +0.031M, max t = +38.06145, max tau = +0.21517, (5/tau)^2 = 539
```

In general, we are interested in analyzing results on stable Rust toolchain compiled in `--release` mode. However,
we should inspect all results for all compilation targets etc., to make sure nothing stands out. We should
also test different `opt-level` settings, but we are skipping this for the sake of brevity.

### General information:

- `n` is the number of measurements (in millions)
- `t` is the t-statistic
- `tau` is a normalized t-statistic
- `(5/tau)^2` is an estimate of how many measurements would be needed to detect a timing leak if one exists

### Max Tau (τ)

Tau (τ) is a normalized t-statistic that measures the timing difference between two classes of inputs.

#### Guidelines:

- Aim for |τ| as close to 0 as possible
- |τ| < 1 is generally considered good
- Any |τ| > 5 should be treated as a significant concern

### (5/tau)^2

This metric estimates the number of measurements needed to detect a timing leak with high confidence.

#### Guidelines:

- Aim for (5/tau)^2 > 10^6 for critical operations
- Any value < 10^4 should be investigated
- A value of 0 or very close to 0 indicates a severe timing leak

# License

This project is licensed under the MIT License.