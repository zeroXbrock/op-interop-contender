use std::{collections::HashMap, sync::Arc};

use contender_core::{
    Url,
    alloy_primitives::Address,
    alloy_providers::{
        DynProvider, PendingTransactionConfig, Provider, ProviderBuilder, network::AnyNetwork,
    },
    generator::{NamedTxRequest, types::AnyProvider},
    spammer::{OnBatchSent, OnTxSent, tx_actor::TxActorHandle},
    tokio_task::{self},
};

use crate::contracts::SUPERCHAIN_TOKEN_BRIDGE;

pub struct OpInteropCallback {
    destination_provider: Arc<AnyProvider>,
    source_provider: Arc<AnyProvider>,
}

impl OpInteropCallback {
    pub fn new(source_rpc_url: &Url, destination_rpc_url: &Url) -> Self {
        let source_provider = DynProvider::new(
            ProviderBuilder::new()
                .network::<AnyNetwork>()
                .connect_http(source_rpc_url.to_owned()),
        );
        let destination_provider = DynProvider::new(
            ProviderBuilder::new()
                .network::<AnyNetwork>()
                .connect_http(destination_rpc_url.to_owned()),
        );
        Self {
            destination_provider: Arc::new(destination_provider),
            source_provider: Arc::new(source_provider),
        }
    }
}

impl OnBatchSent for OpInteropCallback {
    fn on_batch_sent(&self) -> Option<tokio_task::JoinHandle<Result<(), String>>> {
        println!("Tx batch sent to L1.");
        None
    }
}

impl OnTxSent for OpInteropCallback {
    fn on_tx_sent(
        &self,
        pending_tx: PendingTransactionConfig,
        _tx_req: &NamedTxRequest,
        _extra: Option<HashMap<String, String>>,
        _tx_handler: Option<Arc<TxActorHandle>>,
    ) -> Option<tokio_task::JoinHandle<()>> {
        println!(
            "Sending transaction {} to destination chain.",
            pending_tx.tx_hash()
        );

        let xchain_log_topic = "0x382409ac69001e11931a28435afef442cbfd20d9891907e8fa373ba7d351f320";

        let dest_provider = self.destination_provider.clone();
        let source_provider = self.source_provider.clone();
        let src_hash = pending_tx.tx_hash().to_owned();
        let handle = tokio_task::spawn(async move {
            // get logs from receipt via source provider
            let receipt;
            loop {
                let fresh_receipt = source_provider
                    .get_transaction_receipt(src_hash)
                    .await
                    .unwrap_or_else(|e| {
                        println!("Failed to get transaction receipt: {e}");
                        None
                    });
                if fresh_receipt.is_some() {
                    receipt = fresh_receipt;
                    break;
                } else {
                    println!("Waiting for transaction receipt...");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
            let mut xchain_log = None;
            let receipt = receipt.expect("receipt");
            if let Some(to) = receipt.inner.to {
                if to == SUPERCHAIN_TOKEN_BRIDGE.parse::<Address>().unwrap() {
                    let logs = receipt.inner.inner.logs();
                    for log in logs {
                        if let Some(topic) = log.topics().first() {
                            if topic.to_string() == xchain_log_topic {
                                println!("Found xchain log");
                                xchain_log = Some(log);
                                break;
                            }
                        }
                    }
                }
            }

            if let Some(log) = xchain_log {
                todo!("Process xchain log: {log:?}");
                dest_provider
                    // TODO: make relay transactions
                    .send_transaction(Default::default())
                    .await
                    .inspect_err(|e| {
                        println!("Failed to send transaction: {e}");
                    })
                    .ok();
            }
        });

        Some(handle)
    }
}
