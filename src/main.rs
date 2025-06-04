mod contracts;
mod file_seed;
mod op_relay;
mod scenarios;
mod spam_callback;

use contender_core::{
    agent_controller::AgentStore,
    alloy::{
        consensus::TxType,
        network::AnyNetwork,
        node_bindings::WEI_IN_ETHER,
        primitives::{U256, utils::format_ether},
        providers::{DynProvider, Provider, ProviderBuilder},
        signers::local::PrivateKeySigner,
        transports::http::reqwest::Url,
    },
    db::{DbOps, SpamDuration, SpamRunRequest},
    spammer::{Spammer, TimedSpammer, tx_actor::TxActorHandle},
    test_scenario::{PrometheusCollector, TestScenario, TestScenarioParams},
};
use contender_sqlite::SqliteDb;
use contender_testfile::TestConfig;
use file_seed::Seedfile;
use spam_callback::OpInteropCallback;
use std::{collections::HashMap, ops::Deref, str::FromStr, sync::Arc, time::Duration};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::spam_callback::OP_ACTOR_NAME;

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
    let sender = PrivateKeySigner::from_str(&read_var(
        "SPAM_SENDER_PRIVATE_KEY",
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_owned(),
    ))
    .unwrap();
    let source_url = Url::from_str(&read_var(
        "SPAM_ORIGIN_RPC",
        "http://localhost:9545".to_string(),
    ))
    .unwrap();
    let destination_url = Url::from_str(&read_var(
        "SPAM_DEST_RPC",
        "http://localhost:9546".to_string(),
    ))
    .unwrap();
    let supersim_admin_url = Url::from_str(&read_var(
        "OP_ADMIN_URL",
        "http://localhost:8420".to_string(),
    ))
    .unwrap();
    let txs_per_batch = read_var("SPAM_TXS_PER_BATCH", 25);
    let duration = read_var("SPAM_DURATION", 5);
    let scenario_file = read_var(
        "SPAM_SCENARIO_FILE",
        "scenario_files/l2MintAndSend.toml".to_string(),
    );
    let make_report = read_var("SPAM_MAKE_REPORT", false);

    let interval = Duration::from_millis(500);
    let spammer = TimedSpammer::new(interval);

    let mut agents = AgentStore::new();
    let agent_defs = [("admin", 1), ("spammers", 10)];
    for (name, count) in agent_defs {
        agents.add_new_agent(name, count, &seedfile);
    }

    let source_client = DynProvider::new(
        ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_http(source_url.to_owned()),
    );
    let dest_client = DynProvider::new(
        ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_http(destination_url.to_owned()),
    );
    let dest_tx_actor = Arc::new(TxActorHandle::new(120, db.clone(), Arc::new(dest_client)));
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

    let config = TestConfig::from_file(&scenario_file).unwrap();

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

    for (agent_name, _) in agent_defs {
        if let Some(agent) = agents.get_agent(agent_name) {
            // check balance of this test signer. if low, fund accounts
            let test_signer = &agent.signers[0];
            let balance = source_client.get_balance(test_signer.address()).await?;
            if balance < WEI_IN_ETHER / U256::from(10) {
                let pending_txs = scenario
                    .fund_agent_signers(agent_name, &sender.to_owned().into(), WEI_IN_ETHER)
                    .await?;
                for tx in &pending_txs {
                    // wait for the tx to be mined
                    let mined_hash = source_client
                        .watch_pending_transaction(tx.to_owned())
                        .await?
                        .await?;
                    info!(
                        "Funded {} with {} eth ({mined_hash})",
                        test_signer.address(),
                        format_ether(WEI_IN_ETHER)
                    );
                }
            }
        }
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();
    let run_id = db.insert_run(&SpamRunRequest {
        timestamp: timestamp as usize,
        tx_count: (txs_per_batch * duration) as usize,
        scenario_name: "OP Interop Mint and Relay".to_string(),
        rpc_url: destination_url.to_string(),
        txs_per_duration: txs_per_batch,
        duration: SpamDuration::Seconds((duration * interval.as_millis() as u64) / 1000),
        timeout: 5,
    })?;

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
    } else {
        info!("Skipping report generation.");
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

fn read_var<T: FromStr + std::fmt::Display + Clone>(varname: &str, default: T) -> T {
    std::env::var(varname)
        .ok()
        .and_then(|v| v.parse::<T>().ok())
        .unwrap_or_else(|| {
            warn!("{varname} not set, defaulting to {default}");
            default.clone()
        })
}
