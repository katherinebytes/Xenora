// SPDX-License-Identifier: GPL-3.0-or-later

use std::hint::black_box;
use std::time::{Duration, Instant};
use xenora_loader::cpu::{CpuState, ExecutionResult, ExitReason, Interpreter, Register};
use xenora_loader::dbt::DbtEngine;
use xenora_loader::memory::MemoryPermissions;
use xenora_loader::pe::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, PE32_PLUS_MAGIC, ParsedPe,
};

fn build_pe(code: &[u8]) -> Vec<u8> {
    let mut pe = Vec::new();
    pe.extend_from_slice(b"MZ");
    pe.resize(0x3C, 0);
    let e_lfanew: u32 = 0x80;
    pe.extend_from_slice(&e_lfanew.to_le_bytes());
    pe.resize(0x80, 0);
    pe.extend_from_slice(b"PE\0\0");
    pe.extend_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
    let num_sections: u16 = 1;
    pe.extend_from_slice(&num_sections.to_le_bytes());
    pe.extend_from_slice(&0x67300000u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    let opt_hdr_size: u16 = 112;
    pe.extend_from_slice(&opt_hdr_size.to_le_bytes());
    pe.extend_from_slice(&0x0022u16.to_le_bytes());
    pe.extend_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
    pe.push(14);
    pe.push(0);
    pe.extend_from_slice(&(code.len() as u32).to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    let entry_point_rva: u32 = 0x1000;
    pe.extend_from_slice(&entry_point_rva.to_le_bytes());
    pe.extend_from_slice(&0x1000u32.to_le_bytes());
    let image_base: u64 = 0x0000000140000000;
    pe.extend_from_slice(&image_base.to_le_bytes());
    pe.extend_from_slice(&0x1000u32.to_le_bytes());
    pe.extend_from_slice(&0x200u32.to_le_bytes());
    pe.extend_from_slice(&6u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&6u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    let size_of_image = 0x1000 + ((code.len() as u32 + 0xfff) & !0xfff);
    pe.extend_from_slice(&size_of_image.to_le_bytes());
    pe.extend_from_slice(&0x200u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&3u16.to_le_bytes());
    pe.extend_from_slice(&0x8160u16.to_le_bytes());
    pe.extend_from_slice(&0x100000u64.to_le_bytes());
    pe.extend_from_slice(&0x1000u64.to_le_bytes());
    pe.extend_from_slice(&0x100000u64.to_le_bytes());
    pe.extend_from_slice(&0x1000u64.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    let mut sec_name = [0u8; 8];
    sec_name[..5].copy_from_slice(b".text");
    pe.extend_from_slice(&sec_name);
    pe.extend_from_slice(&(code.len() as u32).to_le_bytes());
    pe.extend_from_slice(&0x1000u32.to_le_bytes());
    let raw_size = (code.len() as u32 + 0x1ff) & !0x1ff;
    pe.extend_from_slice(&raw_size.to_le_bytes());
    pe.extend_from_slice(&0x200u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE).to_le_bytes());
    pe.resize(0x200, 0);
    pe.extend_from_slice(code);
    pe.resize(0x200 + raw_size as usize, 0);
    pe
}

const ADDS: usize = 10_000;
const INSTRUCTIONS: usize = ADDS + 2;
const BUDGET: usize = 20_000;
const STACK_TOP: u64 = 0x2000_8000;

fn check(result: ExecutionResult) {
    assert_eq!(result.exit_reason, ExitReason::Halt);
    assert_eq!(result.instructions_executed, INSTRUCTIONS);
    assert_eq!(result.final_state.get(Register::Rax), ADDS as u64);
}

fn percentile(sorted: &[Duration], fraction: f64) -> Duration {
    // Interpolate between adjacent values at rank (n - 1) * fraction.
    let rank = (sorted.len() - 1) as f64 * fraction;
    let lower = sorted[rank.floor() as usize];
    let upper = sorted[rank.ceil() as usize];
    lower + (upper - lower).mul_f64(rank.fract())
}

fn report(label: &str, samples: &mut [Duration]) {
    samples.sort_unstable();
    let median = percentile(samples, 0.50);
    let p95 = percentile(samples, 0.95);
    let p99 = percentile(samples, 0.99);
    let iqr = percentile(samples, 0.75) - percentile(samples, 0.25);
    let min = samples[0];
    let max = samples[samples.len() - 1];
    let mips = INSTRUCTIONS as f64 / median.as_secs_f64() / 1_000_000.0;
    println!(
        "{label}: {} samples, median {median:?}, min {min:?}, max {max:?}, p95 {p95:?}, p99 {p99:?}, IQR {iqr:?}, median {mips:.2} MIPS",
        samples.len()
    );
}

fn main() {
    let sample_count = std::env::var("XENORA_DBT_BENCH_SAMPLES")
        .map_or(101, |value| value.parse::<usize>().expect("sample count"));
    assert!(sample_count > 0);
    let warmup_count = std::env::var("XENORA_DBT_BENCH_WARMUP")
        .map_or(10, |value| value.parse::<usize>().expect("warmup count"));

    let mut code = vec![0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0]; // mov rax, 0
    for _ in 0..ADDS {
        code.extend_from_slice(&[0x48, 0x83, 0xC0, 0x01]); // add rax, 1
    }
    code.push(0xF4); // hlt

    let pe_bytes = build_pe(&code);
    let parsed = ParsedPe::parse(&pe_bytes).unwrap();
    let mut loaded = parsed.load_into_memory(&pe_bytes).unwrap();
    loaded
        .memory
        .map_region(0x2000_0000, 0x10000, MemoryPermissions::READ_WRITE)
        .unwrap();
    let initial_cpu = CpuState::new(loaded.entry_point, STACK_TOP);
    let mut interpreter = Vec::with_capacity(sample_count);
    let mut cold = Vec::with_capacity(sample_count);
    let mut warm = Vec::with_capacity(sample_count);
    let mut cold_metrics = None;

    for record in
        std::iter::repeat_n(false, warmup_count).chain(std::iter::repeat_n(true, sample_count))
    {
        let mut interp = Interpreter::new(initial_cpu.clone(), &mut loaded.memory, BUDGET);
        let start = Instant::now();
        let result = black_box(interp.run());
        let interpreter_time = start.elapsed();
        check(result);

        let mut dbt = DbtEngine::new(4 * 1024 * 1024).unwrap();
        let mut cpu = initial_cpu.clone();
        let start = Instant::now();
        let result = black_box(dbt.run(&mut cpu, &mut loaded.memory, BUDGET));
        let cold_time = start.elapsed();
        check(result);
        assert!(dbt.metrics.blocks_compiled > 0);
        assert_eq!(dbt.metrics.cache_hits, 0);
        assert_eq!(dbt.metrics.cache_misses, dbt.metrics.blocks_compiled);
        let metrics = dbt.metrics;

        let mut cpu = initial_cpu.clone();
        let start = Instant::now();
        let result = black_box(dbt.run(&mut cpu, &mut loaded.memory, BUDGET));
        let warm_time = start.elapsed();
        check(result);
        assert_eq!(dbt.metrics.blocks_compiled, metrics.blocks_compiled);
        assert_eq!(dbt.metrics.cache_hits, dbt.metrics.blocks_compiled);
        assert_eq!(dbt.metrics.cache_misses, dbt.metrics.blocks_compiled);

        if record {
            interpreter.push(interpreter_time);
            cold.push(cold_time);
            warm.push(warm_time);
            cold_metrics = Some(metrics);
        }
    }

    println!("{INSTRUCTIONS} guest instructions per sample, final RAX={ADDS}");
    println!("{warmup_count} warmup rounds excluded (XENORA_DBT_BENCH_WARMUP, default 10)");
    println!(
        "Cold DBT includes translation with a fresh engine; warm DBT reuses that engine's cache."
    );
    println!(
        "Percentiles describe this synthetic workload on this host; tail estimates vary with sample count."
    );
    report("Interpreter", &mut interpreter);
    report("Cold DBT", &mut cold);
    report("Warm DBT", &mut warm);
    let metrics = cold_metrics.unwrap();
    println!(
        "Cold DBT compiled {} blocks and emitted {} native bytes in {} dispatches",
        metrics.blocks_compiled, metrics.native_bytes_emitted, metrics.dbt_dispatches
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_sample_has_no_spread() {
        let samples = [Duration::from_micros(50)];
        for fraction in [0.25, 0.50, 0.75, 0.95, 0.99] {
            assert_eq!(percentile(&samples, fraction), samples[0]);
        }
    }

    #[test]
    fn percentiles_interpolate_across_even_samples() {
        let samples = [10, 20, 30, 100].map(Duration::from_micros);
        assert_eq!(percentile(&samples, 0.50), Duration::from_micros(25));
        assert_eq!(percentile(&samples, 0.95), Duration::from_nanos(89_500));
        assert_eq!(percentile(&samples, 0.99), Duration::from_nanos(97_900));
        assert_eq!(
            percentile(&samples, 0.75) - percentile(&samples, 0.25),
            Duration::from_nanos(30_000)
        );
    }

    #[test]
    fn median_uses_the_middle_of_odd_samples() {
        let samples = [10, 20, 100].map(Duration::from_micros);
        assert_eq!(percentile(&samples, 0.50), Duration::from_micros(20));
    }
}
