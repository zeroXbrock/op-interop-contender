mod admin_api;
mod args;
mod contracts;
mod file_seed;
mod op_relay;
mod scenarios;
mod spam_callback;
mod utils;

use contender_core::{
    Contender, ContenderCtx, RunOpts,
    alloy::{
        network::AnyNetwork,
        node_bindings::WEI_IN_ETHER,
        primitives::Address,
        providers::{DynProvider, Provider, ProviderBuilder},
        signers::local::PrivateKeySigner,
    },
    generator::agent_pools::{AgentPools, AgentSpec},
    spammer::{TimedSpammer, tx_actor::TxActorHandle},
    test_scenario::Url,
};
use contender_sqlite::SqliteDb;
use file_seed::Seedfile;
use spam_callback::OpInteropCallback;
use std::{collections::HashMap, ops::Deref, sync::Arc, time::Duration};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::{
    args::SpamArgs,
    contracts::bytecode,
    scenarios::bulletin_board,
    spam_callback::OP_ACTOR_NAME,
    utils::{deploy_contract, deploy_create2_contract, get_fresh_sender},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    std::fs::create_dir_all(".contender/reports").unwrap_or_else(|_| {
        warn!("Failed to create report directory, reports will not be saved.");
    });

    let db = Arc::new(SqliteDb::from_file(".contender/contender.db").expect("failed to open db"));
    let seedfile = Seedfile::new();

    // load user-specified options (env vars)
    let SpamArgs {
        sender,
        source_url,
        destination_url,
        txs_per_batch,
        duration,
        make_report,
    } = args::SpamArgs::from_env();

    let dest_client = Arc::new(DynProvider::new(
        ProviderBuilder::new()
            .network::<AnyNetwork>()
            .wallet(sender.to_owned())
            .connect_http(destination_url.to_owned()),
    ));
    let destination_chain_id = dest_client.get_chain_id().await?;
    let bulletin_addrs = deploy_bulletin_contracts(&sender, &source_url, &destination_url).await?;
    let config = bulletin_board::get_config(bulletin_addrs[0], destination_chain_id);
    let agents = config.build_agent_store(&seedfile, AgentSpec::default());
    let dest_tx_actor = Arc::new(TxActorHandle::new(120, db.clone(), dest_client.clone()));
    let msg_handles = HashMap::from_iter([(OP_ACTOR_NAME.to_owned(), dest_tx_actor)]);

    let ctx = ContenderCtx::builder(config, db.deref().to_owned(), seedfile, source_url.as_str())
        .agent_store(agents)
        .funding(WEI_IN_ETHER)
        .user_signers(vec![sender.to_owned()])
        .pending_tx_timeout_secs(10)
        .extra_msg_handles(msg_handles)
        .build();
    let scenario = ctx.build_scenario().await?;

    let mut contender = Contender::new(ctx);
    let spammer = TimedSpammer::new(Duration::from_millis(500));
    let callback = OpInteropCallback::new(&source_url, &destination_url, None).await;

    contender
        .spam(
            spammer,
            callback.into(),
            RunOpts::new()
                .txs_per_period(txs_per_batch)
                .periods(duration)
                .name("OP Interop Message-Passing"),
        )
        .await?;

    if make_report {
        info!("Generating report...");
        let data_dir = std::fs::canonicalize(".contender")?;
        info!("Contender directory: {}", data_dir.display());
        contender_report::command::report(
            None,
            0,
            scenario.db.as_ref(),
            data_dir.to_str().expect("invalid data dir"),
        )
        .await?;
    }

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")); // fallback if RUST_LOG is unset

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_line_number(true)
        .init();
}

async fn deploy_bulletin_contracts(
    sender: &PrivateKeySigner,
    source_url: &Url,
    dest_url: &Url,
) -> Result<Vec<Address>, Box<dyn std::error::Error>> {
    let mut bulletin_addrs = vec![];
    let source_client = Arc::new(DynProvider::new(
        ProviderBuilder::new()
            .network::<AnyNetwork>()
            .wallet(sender.to_owned())
            .connect_http(source_url.to_owned()),
    ));
    let dest_client = Arc::new(DynProvider::new(
        ProviderBuilder::new()
            .network::<AnyNetwork>()
            .wallet(sender.to_owned())
            .connect_http(dest_url.to_owned()),
    ));

    // fund special signer on each client (for CREATE2 factory deployment)
    let admin_signer =
        get_fresh_sender(&[source_client.as_ref(), dest_client.as_ref()], &sender).await?;
    for (idx, client) in [&source_client, &dest_client].iter().enumerate() {
        let factory_address =
            deploy_contract(bytecode::CREATE2_FACTORY.to_owned(), &client, &admin_signer).await?;
        info!("Deployed Create2 factory at: {}", factory_address);

        let salt = [1u8; 32]; // use a fixed salt for simplicity
        let bulletin_address = deploy_create2_contract(
            factory_address,
            salt.into(),
            bytecode::BULLETIN_BOARD.to_owned(),
            &client,
            &admin_signer,
        )
        .await?;
        bulletin_addrs.push(bulletin_address);
        info!("Deployed bulletin board contract on client {idx} at: {bulletin_address}");
    }
    if !bulletin_addrs.iter().all(|&addr| addr == bulletin_addrs[0]) {
        return Err(
            "Bulletin board contracts on source and destination chains must have the same address."
                .into(),
        );
    }

    Ok(bulletin_addrs)
}
