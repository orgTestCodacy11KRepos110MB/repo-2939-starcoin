// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::cli_state::CliState;
use crate::StarcoinOpt;
use anyhow::Result;
use clap::Parser;
use scmd::{CommandAction, ExecContext};
use starcoin_crypto::HashValue;
use starcoin_rpc_api::types::TransactionInfoView;

/// Get transaction info by txn hash or block hash and txn idx in the block
#[derive(Debug, Parser)]
#[clap(name = "get-txn-info", alias = "get_txn_info")]
pub struct GetTransactionInfoOpt {
    #[clap(name = "txn-hash")]
    /// txn hash
    txn_hash: Option<HashValue>,

    #[clap(name = "block-hash", long, required_unless_present = "txn-hash")]
    /// block hash which include the txn, only used when txn-hash is missing.
    block_hash: Option<HashValue>,
    #[clap(name = "idx", long, required_unless_present = "txn-hash")]
    /// the index(start from 0) of the txn in the block
    idx: Option<u64>,
}

pub struct GetTransactionInfoCommand;

impl CommandAction for GetTransactionInfoCommand {
    type State = CliState;
    type GlobalOpt = StarcoinOpt;
    type Opt = GetTransactionInfoOpt;
    type ReturnItem = Option<TransactionInfoView>;

    fn run(
        &self,
        ctx: &ExecContext<Self::State, Self::GlobalOpt, Self::Opt>,
    ) -> Result<Self::ReturnItem> {
        let client = ctx.state().client();
        let opt = ctx.opt();
        match &opt.txn_hash {
            Some(txn_hash) => Ok(client.chain_get_transaction_info(*txn_hash)?),
            None => {
                let block_hash = opt.block_hash.expect("block-hash exists");
                let idx = opt.idx.expect("idx exists");
                Ok(client.chain_get_txn_info_by_block_and_index(block_hash, idx)?)
            }
        }
    }
}
