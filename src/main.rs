mod file_seed;
mod spam_callback;

use std::{str::FromStr, sync::Arc, time::Duration};

use contender_core::{
    PrivateKeySigner, Url,
    agent_controller::AgentStore,
    alloy_primitives::utils::parse_units,
    db::DbOps,
    generator::types::{CreateDefinition, FunctionCallDefinition, SpamRequest},
    spammer::{Spammer, TimedSpammer},
    test_scenario::{PrometheusCollector, TestScenario, TestScenarioParams},
};
use contender_sqlite::SqliteDb;
use contender_testfile::TestConfig;
use file_seed::Seedfile;
use spam_callback::OpInteropCallback;
use tracing::{info, warn};
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
    let source_url = Url::from_str("http://localhost:8545").unwrap();
    let destination_url = Url::from_str("http://localhost:8546").unwrap();

    let spammer = TimedSpammer::new(Duration::from_millis(500));
    let config = TestConfig {
        env: None,
        create: Some(vec![CreateDefinition {
            bytecode: include_str!("./contracts/SpamMe.hex").to_string(),
            name: "test_contract".to_string(),
            from: None,
            from_pool: Some("admin".to_string()),
        }]),
        setup: None,
        spam: Some(vec![SpamRequest::Tx(FunctionCallDefinition {
            to: "{test_contract}".to_string(),
            from: None,
            from_pool: Some("spammers".to_string()),
            signature: "consumeGas()".to_string(),
            args: None,
            gas_limit: Some(120000),
            value: None,
            fuzz: None,
            kind: None,
        })]),
    };
    let mut agents = AgentStore::new();
    let agent_defs = [("admin", 1), ("spammers", 10)];
    for (name, count) in agent_defs {
        agents.add_new_agent(name, count, seedfile.seed());
    }

    let scenario_params = TestScenarioParams {
        rpc_url: source_url.to_owned(),
        builder_rpc_url: None,
        signers: vec![sender.to_owned()],
        agent_store: agents,
        tx_type: contender_core::TxType::Eip1559,
        pending_tx_timeout_secs: 10,
        bundle_type: Default::default(),
    };

    let mut scenario = TestScenario::new(
        config,
        db.clone(),
        seedfile.seed().to_owned(),
        scenario_params,
        None,
        PrometheusCollector::default(),
    )
    .await?;
    let callback = OpInteropCallback::new(destination_url.clone());

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

    let contract = db.get_named_tx("test_contract", source_url.as_str())?;
    if let Some(contract) = contract {
        info!("Contract deployed: {:?}", contract);
    } else {
        warn!("Contract failed to deploy...");
    }

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
