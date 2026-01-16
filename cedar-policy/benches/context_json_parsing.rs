/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#![allow(clippy::unwrap_used, reason = "benchmarking")]
#![allow(clippy::expect_used, reason = "benchmarking")]

//! Benchmark suite for Context JSON parsing performance and memory usage.
//!
//! This benchmark measures:
//! - Parsing performance (wall time) for various input sizes and structures
//! - Memory usage (RSS) to identify amplification issues
//!
//! For detailed heap allocation profiling, use:
//! ```bash
//! cargo bench --bench context_json_parsing --features heap-profiling
//! ```
//! This will use dhat-rs to track all heap allocations and produce detailed reports.

use std::hint::black_box;

use cedar_policy_core::entities::json::{ContextJsonParser, NullContextSchema};
use cedar_policy_core::extensions::Extensions;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde_json::json;

#[cfg(feature = "heap-profiling")]
use dhat::{Dhat, DhatAllocator};

#[cfg(feature = "heap-profiling")]
#[global_allocator]
static ALLOCATOR: DhatAllocator = DhatAllocator;

/// Generate a large context JSON with a single large string value
fn generate_large_context_string(size_mb: usize) -> serde_json::Value {
    let size_bytes = size_mb * 1024 * 1024;
    let large_string = "A".repeat(size_bytes);
    json!({
        "chunk": large_string
    })
}

/// Generate a context JSON with nested structures
fn generate_nested_context(depth: usize, width: usize) -> serde_json::Value {
    // Build nested structure from the bottom up
    let mut nested = json!({});
    for i in 0..width {
        if let Some(map) = nested.as_object_mut() {
            map.insert(format!("key_{}", i), json!("value"));
        }
    }
    
    // Build up the nesting
    for _ in 0..depth {
        let mut new_level = serde_json::Map::new();
        for i in 0..width {
            new_level.insert(format!("key_{}", i), json!("value"));
        }
        new_level.insert("nested".to_string(), nested);
        nested = serde_json::Value::Object(new_level);
    }
    
    nested
}

/// Generate a context JSON with many small attributes
fn generate_many_attributes(count: usize) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for i in 0..count {
        map.insert(format!("attr_{}", i), json!(format!("value_{}", i)));
    }
    serde_json::Value::Object(map)
}

/// Measure memory usage using RSS (Resident Set Size)
/// This works on Linux (via /proc/self/status) and macOS (via libproc)
#[cfg(target_os = "linux")]
fn get_memory_rss() -> Option<usize> {
    use std::fs;
    
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse::<usize>().ok().map(|kb| kb * 1024);
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn get_memory_rss() -> Option<usize> {
    use std::process::Command;
    
    // On macOS, use ps to get RSS
    let output = Command::new("ps")
        .args(&["-o", "rss=", "-p"])
        .arg(std::process::id().to_string())
        .output()
        .ok()?;
    
    let rss_kb = String::from_utf8(output.stdout).ok()?
        .trim()
        .parse::<usize>()
        .ok()?;
    
    Some(rss_kb * 1024) // Convert KB to bytes
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn get_memory_rss() -> Option<usize> {
    // On other systems, we can't easily get RSS
    None
}

/// Benchmark context parsing with memory measurement
/// Uses RSS (Resident Set Size) for memory tracking
/// For more detailed heap allocation tracking, use dhat-rs with --features heap-profiling
fn bench_context_parsing_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("context_json_parsing_memory");
    
    // Test different input sizes
    let sizes = vec![1, 10, 50, 100]; // MB
    
    for size_mb in sizes {
        let context_json = generate_large_context_string(size_mb);
        let json_str = serde_json::to_string(&context_json).unwrap();
        let input_size = json_str.len();
        
        group.throughput(Throughput::Bytes(input_size as u64));
        
        group.bench_function(
            BenchmarkId::new("large_string", format!("{}MB", size_mb)),
            |b| {
                let parser = ContextJsonParser::new(
                    None::<&NullContextSchema>,
                    Extensions::all_available(),
                );
                
                // Pre-allocate to get baseline memory (for future use if needed)
                let _baseline = black_box(Vec::<u8>::with_capacity(0));
                let _mem_baseline = get_memory_rss();
                
                b.iter(|| {
                    let mem_before = get_memory_rss();
                    let context = black_box(
                        parser.from_json_str(black_box(&json_str)).unwrap()
                    );
                    let mem_after = get_memory_rss();
                    
                    // Calculate memory amplification
                    if let (Some(before), Some(after)) = (mem_before, mem_after) {
                        let memory_used = after.saturating_sub(before);
                        let amplification = (memory_used as f64) / (input_size as f64);
                        
                        // Only print on first iteration to avoid spam
                        // Criterion will call this many times, so we use a static to track
                        static PRINTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                        if !PRINTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                            eprintln!(
                                "Memory measurement (first iteration): Input: {}MB ({} bytes), RSS: {}MB, Amplification: {:.2}x",
                                size_mb,
                                input_size,
                                memory_used / (1024 * 1024),
                                amplification
                            );
                        }
                    }
                    
                    black_box(context)
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark context parsing performance (time only)
fn bench_context_parsing_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("context_json_parsing_performance");
    
    // Test with nested structures
    let depths = vec![1, 5, 10, 20];
    for depth in depths {
        let context_json = generate_nested_context(depth, 10);
        let json_str = serde_json::to_string(&context_json).unwrap();
        let input_size = json_str.len();
        
        group.throughput(Throughput::Bytes(input_size as u64));
        
        group.bench_function(
            BenchmarkId::new("nested", format!("depth_{}", depth)),
            |b| {
                let parser = ContextJsonParser::new(
                    None::<&NullContextSchema>,
                    Extensions::all_available(),
                );
                
                b.iter(|| {
                    black_box(
                        parser.from_json_str(black_box(&json_str)).unwrap()
                    )
                });
            },
        );
    }
    
    // Test with many attributes
    let attribute_counts = vec![10, 100, 1000, 10000];
    for count in attribute_counts {
        let context_json = generate_many_attributes(count);
        let json_str = serde_json::to_string(&context_json).unwrap();
        let input_size = json_str.len();
        
        group.throughput(Throughput::Bytes(input_size as u64));
        
        group.bench_function(
            BenchmarkId::new("many_attributes", format!("{}", count)),
            |b| {
                let parser = ContextJsonParser::new(
                    None::<&NullContextSchema>,
                    Extensions::all_available(),
                );
                
                b.iter(|| {
                    black_box(
                        parser.from_json_str(black_box(&json_str)).unwrap()
                    )
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark using serde_json::Value directly (the code path we're optimizing)
/// This is the critical path: from_json_value() -> val_into_restricted_expr()
/// where the double parsing occurs
fn bench_context_from_json_value(c: &mut Criterion) {
    let mut group = c.benchmark_group("context_from_json_value");
    
    let sizes = vec![1, 10, 50, 100]; // MB
    
    for size_mb in sizes {
        let context_json = generate_large_context_string(size_mb);
        let input_size = serde_json::to_string(&context_json).unwrap().len();
        
        group.throughput(Throughput::Bytes(input_size as u64));
        
        group.bench_function(
            BenchmarkId::new("from_value", format!("{}MB", size_mb)),
            |b| {
                let parser = ContextJsonParser::new(
                    None::<&NullContextSchema>,
                    Extensions::all_available(),
                );
                
                // Clone once outside the loop to avoid measuring clone overhead
                let json_value = context_json.clone();
                
                b.iter(|| {
                    let mem_before = get_memory_rss();
                    let context = black_box(
                        parser.from_json_value(black_box(json_value.clone())).unwrap()
                    );
                    let mem_after = get_memory_rss();
                    
                    // Calculate memory amplification
                    if let (Some(before), Some(after)) = (mem_before, mem_after) {
                        let memory_used = after.saturating_sub(before);
                        let amplification = (memory_used as f64) / (input_size as f64);
                        
                        // Only print on first iteration
                        static PRINTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                        if !PRINTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                            eprintln!(
                                "from_json_value (first iteration): Input: {}MB ({} bytes), RSS: {}MB, Amplification: {:.2}x",
                                size_mb,
                                input_size,
                                memory_used / (1024 * 1024),
                                amplification
                            );
                        }
                    }
                    
                    black_box(context)
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_context_parsing_memory,
    bench_context_parsing_performance,
    bench_context_from_json_value
);
criterion_main!(benches);
