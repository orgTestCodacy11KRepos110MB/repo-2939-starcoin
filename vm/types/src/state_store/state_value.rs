// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use starcoin_crypto::hash::{CryptoHash, CryptoHasher};
use starcoin_crypto::HashValue;

#[derive(
Clone,
Debug,
Default,
CryptoHasher,
Eq,
PartialEq,
Serialize,
Deserialize,
Ord,
PartialOrd,
Hash,
)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(proptest_derive::Arbitrary))]
pub struct StateValue {
    pub maybe_bytes: Option<Vec<u8>>,
    hash: HashValue,
}


/// XXX FIXME reference
/// PlainCryptoHash for LeafNode
/// PlainCryptoHash for InternalNode
impl StateValue {
    fn new(maybe_bytes: Option<Vec<u8>>) -> Self {
        let mut hasher = StateValueHasher::default();
        let hash = if let Some(bytes) = &maybe_bytes {
            hasher.update(bytes);
            hasher.finish()
        } else {
            HashValue::zero()
        };
        Self { maybe_bytes, hash }
    }

    pub fn empty() -> Self {
        StateValue::new(None)
    }
}

impl From<Vec<u8>> for StateValue {
    fn from(bytes: Vec<u8>) -> Self {
        StateValue::new(Some(bytes))
    }
}

/// XXX FIXME reference
/// PlainCryptoHash for LeafNode
/// PlainCryptoHash for InternalNode
impl CryptoHash for StateValue {
    type Hasher = StateValueHasher;

    fn hash(&self) -> HashValue {
        self.hash
    }
}