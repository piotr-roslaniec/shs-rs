# Benchmarks

## Table of Contents

- [Benchmark Results](#benchmark-results)
    - [sha256](#sha256)

## Benchmark Results

### sha256

|        | `empty`                   | `small`                          | `1KB`                           | `1MB`                               | `1000 bytes`                    |
|:-------|:--------------------------|:---------------------------------|:--------------------------------|:------------------------------------|:------------------------------- |
|        | `805.79 ns` (✅ **1.00x**) | `760.89 ns` (✅ **1.06x faster**) | `9.84 us` (❌ *12.22x slower*)   | `10.68 ms` (❌ *13256.38x slower*)   | `8.03 us` (❌ *9.96x slower*)    |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

