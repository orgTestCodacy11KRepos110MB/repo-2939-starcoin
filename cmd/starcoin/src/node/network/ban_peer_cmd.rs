// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::cli_state::CliState;
use crate::StarcoinOpt;
use anyhow::Result;
use clap::Parser;
use scmd::{CommandAction, ExecContext};

#[derive(Debug, Parser)]
#[clap(name = "ban_peer")]
/// Ban peer
pub struct BanPeerOpt {
    #[clap(name = "peer")]
    /// format: multiaddr/p2p/peer_id
    peer: String,
    #[clap(name = "ban", long = "ban")]
    /// whether ban the peer
    ban: Option<bool>,
}

pub struct BanPeerCommand;

impl CommandAction for BanPeerCommand {
    type State = CliState;
    type GlobalOpt = StarcoinOpt;
    type Opt = BanPeerOpt;
    type ReturnItem = ();

    fn run(
        &self,
        ctx: &ExecContext<Self::State, Self::GlobalOpt, Self::Opt>,
    ) -> Result<Self::ReturnItem> {
        let client = ctx.state().client();
        let opt = ctx.opt();
        client.ban_peer(opt.peer.clone(), opt.ban.unwrap_or(true))
    }
}
