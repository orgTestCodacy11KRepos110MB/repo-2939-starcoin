// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{CustomCommand, ExecContext};
use anyhow::Result;
use clap::Parser;
use std::marker::PhantomData;

#[derive(Debug, Clone, Default, Parser)]
pub struct EmptyOpt {}

pub trait CommandAction {
    type State;
    type GlobalOpt: Parser;
    type Opt: Parser;
    type ReturnItem: serde::Serialize;

    fn run(
        &self,
        ctx: &ExecContext<Self::State, Self::GlobalOpt, Self::Opt>,
    ) -> Result<Self::ReturnItem>;

    /// This command should skip record in console history when return true.
    fn skip_history(&self, _ctx: &ExecContext<Self::State, Self::GlobalOpt, Self::Opt>) -> bool {
        false
    }

    fn into_cmd(
        self,
    ) -> CustomCommand<Self::State, Self::GlobalOpt, Self::Opt, Self::ReturnItem, Self>
    where
        Self: std::marker::Sized,
    {
        self.into()
    }
}

pub struct FnCommandAction<State, GlobalOpt, Opt, ReturnItem>
where
    State: 'static,
    GlobalOpt: Parser + 'static,
    Opt: Parser + 'static,
    ReturnItem: serde::Serialize,
{
    action: Box<dyn Fn(&ExecContext<State, GlobalOpt, Opt>) -> Result<ReturnItem>>,
}

impl<State, GlobalOpt, Opt, ReturnItem> FnCommandAction<State, GlobalOpt, Opt, ReturnItem>
where
    GlobalOpt: Parser,
    Opt: Parser,
    ReturnItem: serde::Serialize,
{
    pub fn new<A>(action: A) -> Self
    where
        A: Fn(&ExecContext<State, GlobalOpt, Opt>) -> Result<ReturnItem> + 'static,
    {
        Self {
            action: Box::new(action),
        }
    }
}

impl<State, GlobalOpt, Opt, ReturnItem> CommandAction
    for FnCommandAction<State, GlobalOpt, Opt, ReturnItem>
where
    GlobalOpt: Parser,
    Opt: Parser,
    ReturnItem: serde::Serialize,
{
    type State = State;
    type GlobalOpt = GlobalOpt;
    type Opt = Opt;
    type ReturnItem = ReturnItem;

    fn run(
        &self,
        ctx: &ExecContext<Self::State, Self::GlobalOpt, Self::Opt>,
    ) -> Result<Self::ReturnItem> {
        self.action.as_ref()(ctx)
    }
}

pub struct NoneAction<State, GlobalOpt>
where
    State: 'static,
    GlobalOpt: Parser + 'static,
{
    state_type: PhantomData<State>,
    global_opt_type: PhantomData<GlobalOpt>,
}

impl<State, GlobalOpt> CommandAction for NoneAction<State, GlobalOpt>
where
    GlobalOpt: Parser,
{
    type State = State;
    type GlobalOpt = GlobalOpt;
    type Opt = EmptyOpt;
    type ReturnItem = ();

    fn run(
        &self,
        _ctx: &ExecContext<Self::State, Self::GlobalOpt, Self::Opt>,
    ) -> Result<Self::ReturnItem> {
        Ok(())
    }
}
