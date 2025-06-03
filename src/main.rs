mod contracts;
mod file_seed;
mod op_relay;
mod scenarios;
mod spam_callback;

use alloy::{signers::local::PrivateKeySigner, transports::http::reqwest::Url};
use contender_core::{
    agent_controller::AgentStore,
    alloy::primitives::utils::parse_units,
    db::DbOps,
    spammer::{Spammer, TimedSpammer},
    test_scenario::{PrometheusCollector, TestScenario, TestScenarioParams},
};
use contender_sqlite::SqliteDb;
use contender_testfile::TestConfig;
use file_seed::Seedfile;
use spam_callback::OpInteropCallback;
use std::{str::FromStr, sync::Arc, time::Duration};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let db = Arc::new(SqliteDb::new_memory());
    db.create_tables()?;
    let seedfile = Seedfile::new();
    let sender = PrivateKeySigner::from_str(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )
    .unwrap();
    let source_url = Url::from_str("http://localhost:9545").unwrap();
    let destination_url = Url::from_str("http://localhost:9546").unwrap();
    let supersim_admin_url = Url::from_str("http://localhost:8420").unwrap();

    let spammer = TimedSpammer::new(Duration::from_millis(500));

    let mut agents = AgentStore::new();
    let agent_defs = [("admin", 1), ("spammers", 10)];
    for (name, count) in agent_defs {
        agents.add_new_agent(name, count, &seedfile);
    }

    let scenario_params = TestScenarioParams {
        rpc_url: source_url.to_owned(),
        builder_rpc_url: None,
        signers: vec![sender.to_owned()],
        agent_store: agents,
        tx_type: alloy::consensus::TxType::Eip1559,
        pending_tx_timeout_secs: 10,
        bundle_type: Default::default(),
    };

    let config = TestConfig::from_file("src/scenarios/l2MintAndSend.toml").unwrap();

    let mut scenario = TestScenario::new(
        config,
        db.clone(),
        seedfile,
        scenario_params,
        None,
        PrometheusCollector::default(),
    )
    .await?;
    let callback =
        OpInteropCallback::new(&source_url, &destination_url, &supersim_admin_url, None).await;

    for (agent, _signer) in agent_defs {
        scenario
            .fund_agent_signers(
                agent,
                &sender.to_owned().into(),
                parse_units("2", "ether").unwrap().get_absolute(),
            )
            .await?;
    }

    scenario.deploy_contracts().await?;
    scenario.run_setup().await?;

    spammer
        .spam_rpc(&mut scenario, 10, 1, None, Arc::new(callback))
        .await?;

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
