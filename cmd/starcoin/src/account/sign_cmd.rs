// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::cli_state::CliState;
use crate::StarcoinOpt;
use anyhow::Result;
use clap::Parser;
use scmd::{CommandAction, ExecContext};
use serde::{Deserialize, Serialize};
use starcoin_types::sign_message::{SignedMessage, SigningMessage};
use starcoin_vm_types::account_address::AccountAddress;

/// Sign a message by the account's private key.
#[derive(Debug, Parser)]
#[clap(name = "sign-message")]
pub struct SignMessageOpt {
    #[clap(short = 's')]
    /// if `sender` is absent, use default account.
    sender: Option<AccountAddress>,

    #[clap(short = 'm', long = "message", name = "signing-message")]
    message: SigningMessage,
}

pub struct SignMessageCmd;

impl CommandAction for SignMessageCmd {
    type State = CliState;
    type GlobalOpt = StarcoinOpt;
    type Opt = SignMessageOpt;
    type ReturnItem = SignResult;

    fn run(
        &self,
        ctx: &ExecContext<Self::State, Self::GlobalOpt, Self::Opt>,
    ) -> Result<Self::ReturnItem> {
        let opt = ctx.opt();
        let client = ctx.state().account_client();
        let sender = ctx.state().get_account_or_default(opt.sender)?;
        let signed_message = client.sign_message(sender.address, opt.message.clone())?;

        let hex = signed_message.to_string();
        Ok(SignResult {
            msg: signed_message,
            hex,
        })
    }
}

#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct SignResult {
    pub msg: SignedMessage,
    pub hex: String,
}
