use crate::op_relay::{SupersimAdminProvider, find_xchain_log, relay_message};
use alloy::network::EthereumWallet;
use alloy::primitives::TxHash;
use contender_core::PrivateKeySigner;
use contender_core::{
    Url,
    alloy_providers::{
        DynProvider, PendingTransactionConfig, Provider, ProviderBuilder, network::AnyNetwork,
    },
    generator::{NamedTxRequest, types::AnyProvider},
    spammer::{OnBatchSent, OnTxSent, tx_actor::TxActorHandle},
    tokio_task::{self},
};
use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};
use tracing::{info, warn};

pub struct OpInteropCallback {
    destination_provider: Arc<AnyProvider>,
    source_provider: Arc<AnyProvider>,
    op_admin_provider: Arc<SupersimAdminProvider>,
    source_chain_id: u64,
}

impl OpInteropCallback {
    pub async fn new(
        source_rpc_url: &Url,
        destination_rpc_url: &Url,
        admin_url: &Url,
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
        let destination_wallet = if let Some(signer) = admin_signer {
            EthereumWallet::from(signer.to_owned())
        } else {
            PrivateKeySigner::from_str(
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            )
            .unwrap()
            .into()
        };
        let destination_provider = DynProvider::new(
            ProviderBuilder::new()
                .network::<AnyNetwork>()
                .wallet(destination_wallet)
                .connect_http(destination_rpc_url.to_owned()),
        );
        let op_admin_provider = SupersimAdminProvider::new(admin_url.to_owned());
        Self {
            destination_provider: Arc::new(destination_provider),
            source_provider: Arc::new(source_provider),
            op_admin_provider: Arc::new(op_admin_provider),
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
        _extra: Option<HashMap<String, String>>,
        _tx_handler: Option<Arc<TxActorHandle>>,
    ) -> Option<tokio_task::JoinHandle<()>> {
        let dest_provider = self.destination_provider.clone();
        let source_provider = self.source_provider.clone();
        let op_admin_provider = self.op_admin_provider.clone();
        let source_chain_id = self.source_chain_id;
        let tx_hash = pending_tx.tx_hash().to_owned();

        let handle = tokio_task::spawn(async move {
            handle_on_tx_sent(
                &source_provider,
                tx_hash,
                source_chain_id,
                &dest_provider,
                &op_admin_provider,
            )
            .await
            .map_err(|e| format!("Failed to handle on_tx_sent: {e}"))
            .unwrap_or_else(|e| {
                warn!("Error: {e}");
            });
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
    op_admin_provider: &SupersimAdminProvider,
) -> Result<(), Box<dyn std::error::Error>> {
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
    if let Some(log) = xchain_log {
        info!("Relaying message {tx_hash} to destination chain.");
        let block = source_provider
            .get_block_by_hash(receipt.block_hash.expect("receipt block hash"))
            .await?
            .ok_or_else(|| format!("Block for receipt {tx_hash} not found"))?;
        relay_message(
            &log,
            block.header.timestamp,
            source_chain_id,
            destination_provider,
            op_admin_provider,
        )
        .await?;
    }
    Ok(())
}
