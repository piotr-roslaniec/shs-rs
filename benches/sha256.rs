use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shs_rs::sha256::sha256;

fn sha256_benchmark(c: &mut Criterion) {
    // Empty input
    c.bench_function("sha256/empty", |b| b.iter(|| sha256(black_box(&[]))));

    // Small input
    c.bench_function("sha256/small", |b| b.iter(|| sha256(black_box(b"Hello, world!"))));

    // Medium input (1 KB)
    let medium_input = vec![0u8; 1024];
    c.bench_function("sha256/1KB", |b| b.iter(|| sha256(black_box(&medium_input))));

    // Large input (1 MB)
    let large_input = vec![0u8; 1024 * 1024];
    c.bench_function("sha256/1MB", |b| b.iter(|| sha256(black_box(&large_input))));

    // Input that's not a multiple of 64 bytes
    let odd_input = vec![0u8; 1000];
    c.bench_function("sha256/1000 bytes", |b| b.iter(|| sha256(black_box(&odd_input))));
}

criterion_group!(benches, sha256_benchmark);
criterion_main!(benches);
