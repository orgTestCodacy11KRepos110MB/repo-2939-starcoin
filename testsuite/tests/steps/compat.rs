// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0
use crate::MyWorld;
use cucumber::{Steps, StepsBuilder};
use starcoin_logger::prelude::*;
use starcoin_rpc_client::RpcClient;
use std::env;
use std::sync::Arc;

pub fn steps() -> Steps<MyWorld> {
    let mut builder: StepsBuilder<MyWorld> = Default::default();
    builder
        .given("compat node1 rpc client", |world: &mut MyWorld, _step| {
            let rpc_addr = env::var("COMPAT_NODE1_WS").unwrap_or_else(|_| "".to_string());
            let client = RpcClient::connect_websocket(rpc_addr.as_ref()).unwrap();
            info!("rpc client created!");
            world.default_rpc_client = Some(Arc::new(client))
        })
        .given("compat node2 rpc client", |world: &mut MyWorld, _step| {
            let rpc_addr = env::var("COMPAT_NODE2_WS").unwrap_or_else(|_| "".to_string());
            let client = RpcClient::connect_websocket(rpc_addr.as_ref()).unwrap();
            info!("rpc client created!");
            world.rpc_client2 = Some(Arc::new(client))
        })
        .then("compat basic check", |world: &mut MyWorld, _step| {
            let client = world.default_rpc_client.as_ref().take().unwrap();
            let local_client = world.rpc_client2.as_ref().take().unwrap();
            let node_info = client.clone().node_info();
            info!("node1 : {:?}", node_info);
            let node2_info = local_client.clone().node_info();
            info!("node2 : {:?}", node2_info);
        });
    builder.build()
}
