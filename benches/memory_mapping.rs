// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![feature(test)]

extern crate rand;
extern crate solana_rbpf;
extern crate test;

use rand::{rngs::SmallRng, Rng, SeedableRng};
use solana_rbpf::{
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    user_error::UserError,
    vm::Config,
};
use test::Bencher;

fn generate_memory_regions(
    entries: usize,
    is_writable: bool,
    mut prng: Option<&mut SmallRng>,
) -> (Vec<MemoryRegion>, u64) {
    let mut memory_regions = Vec::with_capacity(entries + 1);
    memory_regions.push(MemoryRegion::default());
    let mut offset = 0x100000000;
    for _ in 0..entries {
        let length = match &mut prng {
            Some(prng) => (*prng).gen::<u8>() as u64 + 4,
            None => 4,
        };
        let content = vec![0; length as usize];
        memory_regions.push(MemoryRegion::new_for_testing(
            &content[..],
            offset,
            0,
            is_writable,
        ));
        offset += 0x100000000;
    }
    (memory_regions, offset)
}

macro_rules! new_prng {
    ( ) => {
        SmallRng::from_seed([0; 32])
    };
}

#[bench]
fn bench_prng(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    bencher.iter(|| prng.gen::<u64>());
}

#[bench]
fn bench_gapped_randomized_access_with_1024_entries(bencher: &mut Bencher) {
    let frame_size: u64 = 2;
    let frame_count: u64 = 1024;
    let content = vec![0; (frame_size * frame_count * 2) as usize];
    let memory_regions = vec![
        MemoryRegion::default(),
        MemoryRegion::new_for_testing(&content[..], 0x100000000, frame_size, false),
    ];
    let config = Config::default();
    let memory_mapping = MemoryMapping::new::<UserError>(memory_regions, &config).unwrap();
    let mut prng = new_prng!();
    bencher.iter(|| {
        assert!(memory_mapping
            .map::<UserError>(
                AccessType::Load,
                0x100000000 + (prng.gen::<u64>() % frame_count * (frame_size * 2)),
                1
            )
            .is_ok());
    });
}

#[bench]
fn bench_randomized_access_with_0001_entry(bencher: &mut Bencher) {
    let content = vec![0; 1024 * 2];
    let memory_regions = vec![
        MemoryRegion::default(),
        MemoryRegion::new_readonly(&content[..], 0x100000000),
    ];
    let config = Config::default();
    let memory_mapping = MemoryMapping::new::<UserError>(memory_regions, &config).unwrap();
    let mut prng = new_prng!();
    bencher.iter(|| {
        let _ = memory_mapping.map::<UserError>(
            AccessType::Load,
            0x100000000 + (prng.gen::<u64>() % content.len() as u64),
            1,
        );
    });
}

#[bench]
fn bench_randomized_mapping_access_with_0004_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_regions, end_address) = generate_memory_regions(4, false, Some(&mut prng));
    let config = Config::default();
    let memory_mapping = MemoryMapping::new::<UserError>(memory_regions, &config).unwrap();
    bencher.iter(|| {
        let _ = memory_mapping.map::<UserError>(
            AccessType::Load,
            0x100000000 + (prng.gen::<u64>() % end_address),
            1,
        );
    });
}

#[bench]
fn bench_randomized_mapping_access_with_0016_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_regions, end_address) = generate_memory_regions(16, false, Some(&mut prng));
    let config = Config::default();
    let memory_mapping = MemoryMapping::new::<UserError>(memory_regions, &config).unwrap();
    bencher.iter(|| {
        let _ = memory_mapping.map::<UserError>(
            AccessType::Load,
            0x100000000 + (prng.gen::<u64>() % end_address),
            1,
        );
    });
}

#[bench]
fn bench_randomized_mapping_access_with_0064_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_regions, end_address) = generate_memory_regions(64, false, Some(&mut prng));
    let config = Config::default();
    let memory_mapping = MemoryMapping::new::<UserError>(memory_regions, &config).unwrap();
    bencher.iter(|| {
        let _ = memory_mapping.map::<UserError>(
            AccessType::Load,
            0x100000000 + (prng.gen::<u64>() % end_address),
            1,
        );
    });
}

#[bench]
fn bench_randomized_mapping_access_with_0256_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_regions, end_address) = generate_memory_regions(256, false, Some(&mut prng));
    let config = Config::default();
    let memory_mapping = MemoryMapping::new::<UserError>(memory_regions, &config).unwrap();
    bencher.iter(|| {
        let _ = memory_mapping.map::<UserError>(
            AccessType::Load,
            0x100000000 + (prng.gen::<u64>() % end_address),
            1,
        );
    });
}

#[bench]
fn bench_randomized_mapping_access_with_1024_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_regions, end_address) = generate_memory_regions(1024, false, Some(&mut prng));
    let config = Config::default();
    let memory_mapping = MemoryMapping::new::<UserError>(memory_regions, &config).unwrap();
    bencher.iter(|| {
        let _ = memory_mapping.map::<UserError>(
            AccessType::Load,
            0x100000000 + (prng.gen::<u64>() % end_address),
            1,
        );
    });
}

#[bench]
fn bench_randomized_access_with_1024_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_regions, end_address) = generate_memory_regions(1024, false, None);
    let config = Config::default();
    let memory_mapping = MemoryMapping::new::<UserError>(memory_regions, &config).unwrap();
    bencher.iter(|| {
        let _ = memory_mapping.map::<UserError>(
            AccessType::Load,
            0x100000000 + (prng.gen::<u64>() % end_address),
            1,
        );
    });
}

#[bench]
fn bench_randomized_mapping_with_1024_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_regions, _end_address) = generate_memory_regions(1024, false, Some(&mut prng));
    let config = Config::default();
    let memory_mapping = MemoryMapping::new::<UserError>(memory_regions, &config).unwrap();
    bencher.iter(|| {
        let _ = memory_mapping.map::<UserError>(AccessType::Load, 0x100000000, 1);
    });
}

#[bench]
fn bench_mapping_with_1024_entries(bencher: &mut Bencher) {
    let (memory_regions, _end_address) = generate_memory_regions(1024, false, None);
    let config = Config::default();
    let memory_mapping = MemoryMapping::new::<UserError>(memory_regions, &config).unwrap();
    bencher.iter(|| {
        assert!(memory_mapping
            .map::<UserError>(AccessType::Load, 0x100000000, 1)
            .is_ok());
    });
}
