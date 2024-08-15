#!/bin/bash

DEST_DIR="ct_bench_results"

run_benchmarks() {
    local build_type=$1
    local toolchain=$2

    cargo clean
    mkdir -p "$DEST_DIR"
    local filename="${DEST_DIR}/ct_benches_${build_type// /_}_${toolchain// /_}.txt"
    cargo +${toolchain} run --example sha256_ct_bench ${build_type} | tee "$filename"
}

toolchains=(
    "stable"
    "nightly"
)

build_types=(
    "" # debug
    "--release"
)

for toolchain in "${toolchains[@]}"; do
    for build_type in "${build_types[@]}"; do
        run_benchmarks "$build_type" "$toolchain"
    done
done

echo "Benchmark results saved in directory: $DEST_DIR"