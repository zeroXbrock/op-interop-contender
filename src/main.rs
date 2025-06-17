mod admin_api;
mod args;
mod contracts;
mod file_seed;
mod op_relay;
mod scenarios;
mod spam_callback;
mod utils;

use contender_core::{
    agent_controller::AgentStore,
    alloy::{
        consensus::TxType,
        network::AnyNetwork,
        node_bindings::WEI_IN_ETHER,
        providers::{DynProvider, Provider, ProviderBuilder},
    },
    db::{DbOps, SpamDuration, SpamRunRequest},
    spammer::{Spammer, TimedSpammer, tx_actor::TxActorHandle},
    test_scenario::{PrometheusCollector, TestScenario, TestScenarioParams},
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
    db.create_tables().unwrap_or_else(|_| {
        // ignore; db won't be affected if tables already exist
    });
    let seedfile = Seedfile::new();

    let SpamArgs {
        sender,
        source_url,
        destination_url,
        txs_per_batch,
        duration,
        make_report,
    } = args::SpamArgs::from_env();

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
            .connect_http(destination_url.to_owned()),
    ));

    let interval = Duration::from_millis(500);
    let spammer = TimedSpammer::new(interval);

    let mut agents = AgentStore::new();
    let agent_defs = [("admin", 1), ("spammers", 10)];
    for (name, count) in agent_defs {
        agents.add_new_agent(name, count, &seedfile);
    }

    let destination_chain_id = dest_client.get_chain_id().await?;
    let dest_tx_actor = Arc::new(TxActorHandle::new(120, db.clone(), dest_client.clone()));
    let msg_handles = HashMap::from_iter([(OP_ACTOR_NAME.to_owned(), dest_tx_actor)]);

    let scenario_params = TestScenarioParams {
        rpc_url: source_url.to_owned(),
        builder_rpc_url: None,
        signers: vec![sender.to_owned()],
        agent_store: agents.to_owned(),
        tx_type: TxType::Eip1559,
        pending_tx_timeout_secs: 10,
        bundle_type: Default::default(),
        extra_msg_handles: Some(msg_handles),
    };

    // fund special signer on each client (for CREATE2 factory deployment)
    let admin_signer =
        get_fresh_sender(&[source_client.as_ref(), dest_client.as_ref()], &sender).await?;

    // deploy create2 factory & bulletin board contract on both chains
    let mut bulletin_addrs = vec![];
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

    let config = bulletin_board::get_config(bulletin_addrs[0], destination_chain_id);

    let mut scenario = TestScenario::new(
        config,
        db.clone(),
        seedfile,
        scenario_params,
        None,
        PrometheusCollector::default(),
    )
    .await?;
    let callback = OpInteropCallback::new(&source_url, &destination_url, None).await;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();
    let run_id = db.insert_run(&SpamRunRequest {
        timestamp: timestamp as usize,
        tx_count: (txs_per_batch * duration) as usize,
        scenario_name: "OP Interop Message-Passing".to_string(),
        rpc_url: destination_url.to_string(),
        txs_per_duration: txs_per_batch,
        duration: SpamDuration::Seconds((duration * interval.as_millis() as u64) / 1000),
        timeout: 5,
    })?;

    // fund agent signers if needed on source client
    for (agent_name, _) in agent_defs {
        if let Some(agent) = agents.get_agent(agent_name) {
            // check balance of this test signer. if low, fund accounts
            let test_signer = &agent.signers[0];
            let balance = source_client.get_balance(test_signer.address()).await?;
            if balance < WEI_IN_ETHER {
                agent
                    .fund_signers(&sender, WEI_IN_ETHER, source_client.clone())
                    .await?;
            }
        }
    }

    spammer
        .spam_rpc(
            &mut scenario,
            txs_per_batch,
            duration,
            Some(run_id),
            Arc::new(callback),
        )
        .await?;

    if make_report {
        info!("Generating report...");
        let data_dir = std::fs::canonicalize(".contender")?;
        info!("Contender directory: {}", data_dir.display());
        contender_report::command::report(
            Some(run_id),
            0,
            db.deref(),
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
