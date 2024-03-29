// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::cli_state::CliState;
use crate::StarcoinOpt;
use anyhow::Result;
use clap::Parser;
use scmd::{CommandAction, ExecContext};

#[derive(Debug, Parser, Default)]
#[clap(name = "shutdown_system")]
pub struct ShutdownSystemOpt {}

pub struct ShutdownSystemCommand;

impl CommandAction for ShutdownSystemCommand {
    type State = CliState;
    type GlobalOpt = StarcoinOpt;
    type Opt = ShutdownSystemOpt;
    type ReturnItem = ();

    fn run(
        &self,
        ctx: &ExecContext<Self::State, Self::GlobalOpt, Self::Opt>,
    ) -> Result<Self::ReturnItem> {
        let client = ctx.state().client();
        client.node_shutdown_system()
    }
}
