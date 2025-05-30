use std::{collections::HashMap, sync::Arc};

use contender_core::{
    Url,
    alloy_providers::{
        DynProvider, PendingTransactionConfig, Provider, ProviderBuilder, network::AnyNetwork,
    },
    generator::{NamedTxRequest, types::AnyProvider},
    spammer::{OnBatchSent, OnTxSent, tx_actor::TxActorHandle},
    tokio_task::{self},
};

pub struct OpInteropCallback {
    provider: Arc<AnyProvider>,
}

impl OpInteropCallback {
    pub fn new(destination_rpc_url: Url) -> Self {
        let provider = DynProvider::new(
            ProviderBuilder::new()
                .network::<AnyNetwork>()
                .connect_http(destination_rpc_url),
        );
        Self {
            provider: Arc::new(provider),
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
            "Transaction {} sending to destination chain.",
            pending_tx.tx_hash()
        );

        let provider = self.provider.clone();
        let handle = tokio_task::spawn(async move {
            provider
                // TODO: make relay transactions
                .send_transaction(Default::default())
                .await
                .inspect_err(|e| {
                    println!("Failed to send transaction: {e}");
                })
                .ok();
        });

        Some(handle)
    }
}
