// Copyright 2020 Solana <alexander@solana.com>
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
};
use test::Bencher;

fn generate_memory_mapping(
    entries: usize,
    is_writable: bool,
    mut prng: Option<&mut SmallRng>,
) -> (MemoryMapping, u64) {
    let mut memory_regions = Vec::with_capacity(entries);
    let mut offset = 0;
    for _ in 0..entries {
        let length = match &mut prng {
            Some(prng) => (*prng).gen::<u8>() as u64 + 4,
            None => 4,
        };
        let content = vec![0; length as usize];
        memory_regions.push(MemoryRegion::new_from_slice(
            &content[..],
            offset,
            is_writable,
        ));
        offset += length;
    }
    (MemoryMapping::new_from_regions(memory_regions), offset)
}

macro_rules! new_prng {
    ( ) => {
        SmallRng::from_seed([0; 16])
    };
}

#[bench]
fn bench_prng(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    bencher.iter(|| prng.gen::<u64>());
}

#[bench]
fn bench_randomized_mapping_access_with_0004_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_mapping, end_address) = generate_memory_mapping(4, false, Some(&mut prng));
    bencher.iter(|| {
        assert!(memory_mapping
            .map::<UserError>(AccessType::Load, prng.gen::<u64>() % end_address, 1)
            .is_ok());
    });
}

#[bench]
fn bench_randomized_mapping_access_with_0016_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_mapping, end_address) = generate_memory_mapping(16, false, Some(&mut prng));
    bencher.iter(|| {
        assert!(memory_mapping
            .map::<UserError>(AccessType::Load, prng.gen::<u64>() % end_address, 1)
            .is_ok());
    });
}

#[bench]
fn bench_randomized_mapping_access_with_0064_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_mapping, end_address) = generate_memory_mapping(64, false, Some(&mut prng));
    bencher.iter(|| {
        assert!(memory_mapping
            .map::<UserError>(AccessType::Load, prng.gen::<u64>() % end_address, 1)
            .is_ok());
    });
}

#[bench]
fn bench_randomized_mapping_access_with_0256_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_mapping, end_address) = generate_memory_mapping(256, false, Some(&mut prng));
    bencher.iter(|| {
        assert!(memory_mapping
            .map::<UserError>(AccessType::Load, prng.gen::<u64>() % end_address, 1)
            .is_ok());
    });
}

#[bench]
fn bench_randomized_mapping_access_with_1024_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_mapping, end_address) = generate_memory_mapping(1024, false, Some(&mut prng));
    bencher.iter(|| {
        assert!(memory_mapping
            .map::<UserError>(AccessType::Load, prng.gen::<u64>() % end_address, 1)
            .is_ok());
    });
}

#[bench]
fn bench_randomized_access_with_1024_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_mapping, end_address) = generate_memory_mapping(1024, false, None);
    bencher.iter(|| {
        assert!(memory_mapping
            .map::<UserError>(AccessType::Load, prng.gen::<u64>() % end_address, 1)
            .is_ok());
    });
}

#[bench]
fn bench_randomized_mapping_with_1024_entries(bencher: &mut Bencher) {
    let mut prng = new_prng!();
    let (memory_mapping, _end_address) = generate_memory_mapping(1024, false, Some(&mut prng));
    bencher.iter(|| {
        assert!(memory_mapping
            .map::<UserError>(AccessType::Load, 0, 1)
            .is_ok());
    });
}

#[bench]
fn bench_mapping_with_1024_entries(bencher: &mut Bencher) {
    let (memory_mapping, _end_address) = generate_memory_mapping(1024, false, None);
    bencher.iter(|| {
        assert!(memory_mapping
            .map::<UserError>(AccessType::Load, 0, 1)
            .is_ok());
    });
}
