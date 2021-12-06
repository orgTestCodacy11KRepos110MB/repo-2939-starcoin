// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::integer_arithmetic)]

use crate::consensus::Consensus;
use crate::difficulty::{get_next_target_helper, BlockDiffInfo};
use crate::{difficult_to_target, target_to_difficulty, CRYPTONIGHT};
use starcoin_crypto::hash::PlainCryptoHash;
use starcoin_types::block::{BlockHeader, BlockHeaderBuilder, RawBlockHeader};
use starcoin_types::U256;
use starcoin_vm_types::time::{
    duration_since_epoch, MockTimeService, TimeService, TimeServiceType,
};
use std::collections::VecDeque;

#[stest::test]
fn raw_hash_test() {
    let header = BlockHeader::random();
    let header_1 = header.clone();
    let id_1 = header_1.id();
    let raw_1: RawBlockHeader = header_1.into();
    let raw_id_1 = raw_1.crypto_hash();
    let header_2 = header.as_builder().with_nonce(42).build();
    let id_2 = header_2.id();
    let raw_2: RawBlockHeader = header_2.into();
    let raw_id_2 = raw_2.crypto_hash();
    assert_ne!(id_1, id_2);
    assert_eq!(raw_id_1, raw_id_2);
}

#[stest::test]
fn verify_header_test() {
    let header = BlockHeaderBuilder::random()
        .with_difficulty(1.into())
        .build();
    let raw_header: RawBlockHeader = header.clone().into();
    let time_service = TimeServiceType::RealTimeService.new_time_service();
    let nonce = CRYPTONIGHT.solve_consensus_nonce(
        &header.as_pow_header_blob(),
        raw_header.difficulty,
        time_service.as_ref(),
    );
    let header = header.as_builder().with_nonce(nonce).build();
    CRYPTONIGHT
        .verify_header_difficulty(header.difficulty(), &header)
        .unwrap()
}

#[stest::test]
fn test_get_next_target() {
    let time_used = simulate_blocks(15_000, 10000.into());
    assert!((time_used as i64 - 15_000).abs() <= 1000);
    let time_used = simulate_blocks(20_000, 20000.into());
    assert!((time_used as i64 - 20_000).abs() <= 1000);
    let time_used = simulate_blocks(5_000, 1000.into());
    assert!((time_used as i64 - 5_000).abs() <= 1000);
}

fn simulate_blocks(time_plan: u64, init_difficulty: U256) -> u64 {
    fn liner_hash_pow(difficulty: U256, current: u64) -> u64 {
        let ts = MockTimeService::new_with_value(current);
        let used_time = difficulty.as_u64();
        ts.sleep(used_time);
        ts.now_millis()
    }

    let mut diff = init_difficulty;
    let mut blocks = VecDeque::new();
    let mut now = duration_since_epoch().as_millis() as u64;
    for _ in 0..500 {
        let timestamp = liner_hash_pow(diff, now);
        now = timestamp;
        blocks.push_front(BlockDiffInfo::new(timestamp, difficult_to_target(diff)));
        let bf: Vec<&BlockDiffInfo> = blocks.iter().collect();
        let blocks = bf.iter().map(|&b| b.clone()).collect();
        diff = target_to_difficulty(get_next_target_helper(blocks, time_plan).unwrap());
    }
    blocks[0].timestamp - blocks[1].timestamp
}

#[stest::test]
fn test_next_target_zero_one() {
    assert!(
        get_next_target_helper(vec![], 10_000).is_err(),
        "expect get_next_target_helper error"
    );
    let target0: U256 = 10000.into();
    let next_target = get_next_target_helper(
        vec![BlockDiffInfo {
            timestamp: 0,
            target: target0,
        }],
        10_000,
    )
    .unwrap();

    assert_eq!(next_target, target0);
}

#[stest::test]
fn test_next_target_two_no_change() {
    //time used match the plan
    let time_plan = 10_000;
    let target0: U256 = 10000.into();
    let target1: U256 = 10000.into();
    let next_target = get_next_target_helper(
        vec![
            BlockDiffInfo {
                timestamp: time_plan,
                target: target1,
            },
            BlockDiffInfo {
                timestamp: 0,
                target: target0,
            },
        ],
        time_plan,
    )
    .unwrap();
    assert_eq!(next_target, target0);
}

#[stest::test]
fn test_next_target_two_increment_difficulty() {
    let time_plan = 10_000;
    let target0: U256 = 10000.into();
    let target1: U256 = 10000.into();
    let next_target = get_next_target_helper(
        vec![
            BlockDiffInfo {
                timestamp: time_plan / 2,
                target: target1,
            },
            BlockDiffInfo {
                timestamp: 0,
                target: target0,
            },
        ],
        time_plan,
    )
    .unwrap();
    assert!(next_target < target0);
}

#[stest::test]
fn test_next_target_two_reduce_difficulty() {
    let time_plan = 10_000;
    let target0: U256 = 10000.into();
    let target1: U256 = 10000.into();
    let next_target = get_next_target_helper(
        vec![
            BlockDiffInfo {
                timestamp: time_plan * 2,
                target: target1,
            },
            BlockDiffInfo {
                timestamp: 0,
                target: target0,
            },
        ],
        time_plan,
    )
    .unwrap();
    assert!(next_target > target0);
}

#[stest::test]
fn test_next_target_many_no_change() {
    let time_plan = 10_000;
    let target0: U256 = 10000.into();
    let blocks = (0..24)
        .rev()
        .map(|i| BlockDiffInfo {
            timestamp: time_plan * i,
            target: target0,
        })
        .collect::<Vec<_>>();
    let next_target = get_next_target_helper(blocks, time_plan).unwrap();
    assert_eq!(next_target, target0);
}

#[stest::test]
fn test_next_target_many_increment_difficulty() {
    let time_plan = 10_000;
    let target0: U256 = 10000.into();
    let blocks = (0..24)
        .rev()
        .map(|i| BlockDiffInfo {
            timestamp: (time_plan / 2) * i,
            target: target0,
        })
        .collect::<Vec<_>>();
    let next_target = get_next_target_helper(blocks, time_plan).unwrap();
    assert!(next_target < target0);
}

#[stest::test]
fn test_next_target_many_reduce_difficulty() {
    let time_plan = 10_000;
    let target0: U256 = 10000.into();
    let blocks = (0..24)
        .rev()
        .map(|i| BlockDiffInfo {
            timestamp: (time_plan * 2) * i,
            target: target0,
        })
        .collect::<Vec<_>>();
    let next_target = get_next_target_helper(blocks, time_plan).unwrap();
    assert!(next_target > target0);
}

#[stest::test]
fn test_next_target_increment_difficulty_compare() {
    let time_plan = 10_000;
    let target0: U256 = 10000.into();
    let blocks_1 = vec![
        BlockDiffInfo {
            timestamp: time_plan * 2,
            target: target0,
        },
        BlockDiffInfo {
            timestamp: time_plan + 5000,
            target: target0,
        },
        BlockDiffInfo {
            timestamp: 0,
            target: target0,
        },
    ];

    let blocks_2 = vec![
        BlockDiffInfo {
            timestamp: time_plan * 2,
            target: target0,
        },
        BlockDiffInfo {
            timestamp: time_plan - 5000,
            target: target0,
        },
        BlockDiffInfo {
            timestamp: 0,
            target: target0,
        },
    ];

    let next_target_1 = get_next_target_helper(blocks_1, time_plan).unwrap();
    let next_target_2 = get_next_target_helper(blocks_2, time_plan).unwrap();
    assert!(next_target_1 < next_target_2);
    assert!(next_target_1 < target0);
    assert!(next_target_2 > target0);
}
//verify_header_difficulty, calculate target:11660343, header target: 11660343, nonce: 3221282425
//Verify Nonce Error, expect target: 9930418791052389747331702421505774560256931092476487530380331351137194, got: 13177743943058275644734263735837563184445799542976421731108869862656615245537, nonce: 3221282425, extra: 00000000, diff: 11660343
#[test]
fn test_difficulty_to_target() {
    let difficulty: U256 = 11660343.into();
    let target = difficult_to_target(difficulty);
    println!("max:{}", U256::max_value());
    println!("target:{}", target);
}

//amd cpu: calculate_pow_hash blob: [5f, 9f, 98, 74, ec, 4d, ef, 41, 4b, 96, 36, 87, c4, b1, 7e, 0, 37, 71, 50, cc, 17, 5f, 5c, 6d, 6e, 41, 82, c6, cb, 43, 78, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b1, ec, 37], nonce: 3221282425, extra:[0, 0, 0, 0], pow_hash:0x1d2256b8db95f13c42759bf55eaebe9ccf10116e8550a6ec56f3a33f50fde6e1, target:9930418791052389747331702421505774560256931092476487530380331351137194, real: 13177743943058275644734263735837563184445799542976421731108869862656615245537
//normal cpu: calculate_pow_hash blob: [5f, 9f, 98, 74, ec, 4d, ef, 41, 4b, 96, 36, 87, c4, b1, 7e, 0, 37, 71, 50, cc, 17, 5f, 5c, 6d, 6e, 41, 82, c6, cb, 43, 78, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b1, ec, 37], nonce: 3221282425, extra:[0, 0, 0, 0], pow_hash:0x0000008e67af69c3c670dab325e8fc3a9dc045c6e339aa35f43b415604513742, target:9930418791052389747331702421505774560256931092476487530380331351137194, real: 3839231753559030284598885454738139221281927754995694993797275909699394
