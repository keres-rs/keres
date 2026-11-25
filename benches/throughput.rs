//! Throughput benchmarks for the container chunk pipeline and the
//! single-file convenience API.

#![allow(missing_docs)] // criterion's macros generate undocumented items

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

const MIB: usize = 1024 * 1024;

fn container_pipeline(c: &mut Criterion) {
    let plaintext = vec![0xA5u8; 8 * MIB];
    let identity = "bench/entry";
    let container = keres::test_vectors::hkdf_file(&plaintext, identity);

    let mut group = c.benchmark_group("container");
    group.throughput(Throughput::Bytes(plaintext.len() as u64));

    group.bench_function("write_8MiB", |b| {
        b.iter(|| {
            black_box(keres::test_vectors::hkdf_file(&plaintext, identity));
        })
    });

    group.bench_function("read_8MiB", |b| {
        b.iter(|| {
            keres::fuzz_support::read_hkdf_file(black_box(&container), identity).unwrap();
        })
    });

    group.finish();
}

fn single_file(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.bin");
    let data = vec![0x5Au8; MIB];
    std::fs::write(&source, &data).unwrap();

    let encrypted = dir.path().join("vector.krs");
    keres::encrypt_file("benchmark password", &source, Some(&encrypted)).unwrap();

    let mut group = c.benchmark_group("single_file_1MiB");
    // Each iteration pays an Argon2id derivation; keep the sample count low.
    group.sample_size(10);
    group.throughput(Throughput::Bytes(data.len() as u64));

    group.bench_function("encrypt", |b| {
        b.iter(|| {
            let out = dir.path().join("out.krs");
            keres::encrypt_file("benchmark password", &source, Some(&out)).unwrap();
        })
    });

    group.bench_function("decrypt", |b| {
        b.iter(|| {
            let out = dir.path().join("out.bin");
            keres::decrypt_file("benchmark password", &encrypted, &out).unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, container_pipeline, single_file);
criterion_main!(benches);
