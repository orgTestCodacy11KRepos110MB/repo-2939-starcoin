// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::cli_state::CliState;
use crate::StarcoinOpt;
use anyhow::Result;
use clap::Parser;
use scmd::{CommandAction, ExecContext};
use starcoin_account_api::AccountInfo;
use starcoin_vm_types::account_address::AccountAddress;

/// Change account password, should unlock the account before change password.
#[derive(Debug, Parser)]
#[clap(name = "change-password")]
pub struct ChangePasswordOpt {
    #[clap(
        name = "account_address",
        help = "The wallet account address which to change password."
    )]
    account_address: AccountAddress,

    #[clap(short, name = "password")]
    password: String,
}

pub struct ChangePasswordCmd;

impl CommandAction for ChangePasswordCmd {
    type State = CliState;
    type GlobalOpt = StarcoinOpt;
    type Opt = ChangePasswordOpt;
    type ReturnItem = AccountInfo;

    fn run(
        &self,
        ctx: &ExecContext<Self::State, Self::GlobalOpt, Self::Opt>,
    ) -> Result<Self::ReturnItem> {
        let opt: &ChangePasswordOpt = ctx.opt();
        let account_client = ctx.state().account_client();
        let account_info =
            account_client.change_account_password(opt.account_address, opt.password.clone())?;
        Ok(account_info)
    }

    fn skip_history(&self, _ctx: &ExecContext<Self::State, Self::GlobalOpt, Self::Opt>) -> bool {
        true
    }
}
