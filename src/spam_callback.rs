use crate::op_relay::{find_xchain_log, relay_message};
use contender_core::alloy::{
    network::EthereumWallet,
    primitives::TxHash,
    providers::{
        DynProvider, PendingTransactionConfig, Provider, ProviderBuilder, network::AnyNetwork,
    },
    signers::local::PrivateKeySigner,
    transports::http::reqwest::Url,
};
use contender_core::spammer::RuntimeTxInfo;
use contender_core::spammer::tx_actor::CacheTx;
use contender_core::{
    generator::{NamedTxRequest, types::AnyProvider},
    spammer::{OnBatchSent, OnTxSent, tx_actor::TxActorHandle},
    tokio_task::{self},
};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn};

pub static OP_ACTOR_NAME: &str = "op-dest";

pub struct OpInteropCallback {
    destination_provider: Arc<AnyProvider>,
    source_provider: Arc<AnyProvider>,
    source_chain_id: u64,
}

impl OpInteropCallback {
    pub async fn new(
        source_rpc_url: &Url,
        destination_rpc_url: &Url,
        admin_signer: Option<&PrivateKeySigner>,
    ) -> Self {
        let source_provider = DynProvider::new(
            ProviderBuilder::new()
                .network::<AnyNetwork>()
                .connect_http(source_rpc_url.to_owned()),
        );
        let source_chain_id = source_provider
            .get_chain_id()
            .await
            .expect("Failed to get source chain ID");
        let destination_wallet: EthereumWallet = admin_signer
            .unwrap_or(
                &PrivateKeySigner::from_str(
                    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
                )
                .unwrap(),
            )
            .to_owned()
            .into();
        let destination_provider = DynProvider::new(
            ProviderBuilder::new()
                .network::<AnyNetwork>()
                .wallet(destination_wallet)
                .connect_http(destination_rpc_url.to_owned()),
        );
        Self {
            destination_provider: Arc::new(destination_provider),
            source_provider: Arc::new(source_provider),
            source_chain_id,
        }
    }
}

impl OnBatchSent for OpInteropCallback {
    fn on_batch_sent(&self) -> Option<tokio_task::JoinHandle<Result<(), String>>> {
        None
    }
}

impl OnTxSent for OpInteropCallback {
    fn on_tx_sent(
        &self,
        pending_tx: PendingTransactionConfig,
        _tx_req: &NamedTxRequest,
        extra: RuntimeTxInfo,
        tx_actors: Option<HashMap<String, Arc<TxActorHandle>>>,
    ) -> Option<tokio_task::JoinHandle<()>> {
        let dest_provider = self.destination_provider.clone();
        let source_provider = self.source_provider.clone();
        let source_chain_id = self.source_chain_id;
        let source_tx_hash = pending_tx.tx_hash().to_owned();

        let handle = tokio_task::spawn(async move {
            let relay_tx_hash = handle_on_tx_sent(
                &source_provider,
                source_tx_hash,
                source_chain_id,
                &dest_provider,
            )
            .await
            .map_err(|e| format!("Failed to handle on_tx_sent: {e}"))
            .unwrap_or_else(|e| {
                warn!("Error: {e}");
                None
            });
            if let Some(relay_tx_hash) = relay_tx_hash {
                info!("Message {source_tx_hash} relayed by tx {relay_tx_hash}");
                let tx = CacheTx {
                    tx_hash: relay_tx_hash,
                    start_timestamp_ms: extra.start_timestamp_ms(),
                    kind: extra.kind().cloned(),
                    error: extra.error().cloned(),
                };
                if let Some(Some(actor)) =
                    tx_actors.map(|actors| actors.get(OP_ACTOR_NAME).cloned())
                {
                    actor.cache_run_tx(tx).await.unwrap_or_else(|e| {
                        warn!("Failed to cache transaction: {e}");
                    });
                }
            }
        });

        Some(handle)
    }
}

/// Waits for transaction to land on source chain, then
/// finds the xchain log in the receipt and relays it to the destination chain.
pub async fn handle_on_tx_sent(
    source_provider: &AnyProvider,
    tx_hash: TxHash,
    source_chain_id: u64,
    destination_provider: &AnyProvider,
) -> Result<Option<TxHash>, Box<dyn std::error::Error>> {
    // wait for tx to land
    let _ = source_provider
        .watch_pending_transaction(PendingTransactionConfig::new(tx_hash))
        .await?
        .await?;

    // get receipt for logs
    let receipt = source_provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or(format!("tx receipt for {tx_hash} not found"))?;

    // Find xchain log; if present, relay msg to destination chain.
    let xchain_log = find_xchain_log(&receipt).await?;
    let mut relay_tx_hash = None;
    if let Some(log) = xchain_log {
        info!("Interop message {tx_hash} detected.");
        let block = source_provider
            .get_block_by_hash(receipt.block_hash.expect("receipt block hash"))
            .await?
            .ok_or_else(|| format!("Block for receipt {tx_hash} not found"))?;
        let res = relay_message(
            &log,
            block.header.timestamp,
            source_chain_id,
            destination_provider,
        )
        .await?;
        relay_tx_hash = res.map(|tx| tx.tx_hash().to_owned());
    }
    Ok(relay_tx_hash)
}
