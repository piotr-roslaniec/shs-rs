# shs-rs

An educational implementation of Secure Hash Standard in Rust.

Based on [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). Currently only implements SHA256.

Please don't use this code in production, and so on.

## Test vectors

This repo contains a copy of test vectors used in unit tests.

Download test vectors by running:

```bash
wget https://www.dlitz.net/crypto/shad256-test-vectors/SHAd256_Test_Vectors.txt .
```

Long-running tests are placed in `tests/` directory and mark as `ignore`-d by default. Run them with:

```bash
cargo test -- --ignored
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
cargo run --example ctbench_sha256
```

In order to run CT benchmarks for all compilation targets in debug and release mode, run:

```bash
bash ./scripts/run_ct_benches.bash 
```

# License

This project is licensed under the MIT License.