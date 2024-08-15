# shs-rs

An educational implementation of Secure Hash Standard implementation in pure Rust.

Based on [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

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

# License

This project is licensed under the MIT License.