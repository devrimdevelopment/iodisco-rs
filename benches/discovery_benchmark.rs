use criterion::{black_box, criterion_group, criterion_main, Criterion};
use iodisco;

pub fn bench_device_scan(c: &mut Criterion) {
    c.bench_function("find_gpu_devices", |b| {
        b.iter(|| iodisco::find_gpu_devices())
    });
}

pub fn bench_gpu_info(c: &mut Criterion) {
    c.bench_function("get_gpu_info", |b| {
        b.iter(|| iodisco::get_gpu_info())
    });
}

criterion_group!(benches, bench_device_scan, bench_gpu_info);
criterion_main!(benches);