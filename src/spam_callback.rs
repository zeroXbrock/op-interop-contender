use crate::contracts::SUPERCHAIN_TOKEN_BRIDGE;
use crate::op_relay::{SupersimAdminProvider, XCHAIN_LOG_TOPIC, relay_message};
use alloy::network::{AnyTransactionReceipt, EthereumWallet};
use alloy::primitives::TxHash;
use alloy::rpc::types::Log;
use contender_core::PrivateKeySigner;
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
use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};

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
        println!(
            "Relaying transaction {} to destination chain.",
            pending_tx.tx_hash()
        );

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
                eprintln!("Error: {e}");
            });
        });

        Some(handle)
    }
}

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

    // find xchain log if present
    let xchain_log = find_xchain_log(&receipt).await?;
    if let Some(log) = xchain_log {
        let block = source_provider
            .get_block_by_hash(receipt.block_hash.expect("receipt block hash"))
            .await
            .expect("block request")
            .expect("no block");
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

pub async fn find_xchain_log(
    receipt: &AnyTransactionReceipt,
) -> Result<Option<Log>, Box<dyn std::error::Error>> {
    let mut xchain_log = None;
    if let Some(to) = receipt.inner.to {
        if to == SUPERCHAIN_TOKEN_BRIDGE.parse::<Address>().unwrap() {
            let logs = receipt.inner.inner.logs();
            for log in logs {
                if let Some(topic) = log.topics().first() {
                    if topic.to_string() == XCHAIN_LOG_TOPIC {
                        xchain_log = Some(log.to_owned());
                    }
                }
            }
        }
    }
    Ok(xchain_log)
}
