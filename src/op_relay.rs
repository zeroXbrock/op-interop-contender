use crate::contracts::{
    L2_TO_L2_CROSS_DOMAIN_MESSENGER, SUPERCHAIN_TOKEN_BRIDGE, XCHAIN_LOG_TOPIC,
};
use alloy::{
    network::{AnyNetwork, AnyTransactionReceipt},
    primitives::{Address, Bytes, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::types::{AccessList, Log, TransactionRequest},
    sol,
    sol_types::SolCall,
};
use contender_core::{Url, generator::types::AnyProvider};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

sol! {
    /// https://github.com/ethereum-optimism/optimism/blob/develop/packages/contracts-bedrock/interfaces/L2/ICrossL2Inbox.sol#L6-L12
    struct Identifier {
        address origin;      // Account (contract) that emits the log
        uint256 blocknumber; // Block number in which the log was emitted
        uint256 logIndex;    // Index of the log in the array of all logs emitted in the block
        uint256 timestamp;   // Timestamp that the log was emitted
        uint256 chainId;     // Chain ID of the chain that emitted the log
    }

    /// https://github.com/ethereum-optimism/optimism/blob/develop/packages/contracts-bedrock/src/L2/L2ToL2CrossDomainMessenger.sol#L203-L206
    function relayMessage(
        Identifier calldata _id,
        bytes calldata _sentMessage,
    ) external payable returns (bytes memory);
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentifierWithPayload {
    origin: Address,
    block_number: u64,
    log_index: u64,
    timestamp: u64,
    chain_id: u64,
    payload: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListResponse {
    pub access_list: AccessList,
}

impl IdentifierWithPayload {
    pub fn new(log: &Log, timestamp: u64, chain_id: u64, payload: Bytes) -> Self {
        Self {
            origin: log.address(),
            block_number: log.block_number.unwrap_or_default(),
            log_index: log.log_index.unwrap_or_default(),
            timestamp,
            chain_id,
            payload,
        }
    }

    pub fn to_sol(&self) -> Identifier {
        Identifier {
            origin: self.origin,
            blocknumber: U256::from(self.block_number),
            logIndex: U256::from(self.log_index),
            timestamp: U256::from(self.timestamp),
            chainId: U256::from(self.chain_id),
        }
    }
}

pub struct SupersimAdminProvider {
    provider: Arc<AnyProvider>,
}

impl SupersimAdminProvider {
    pub fn new(url: Url) -> Self {
        let provider = DynProvider::new(
            ProviderBuilder::new()
                .network::<AnyNetwork>()
                .connect_http(url.to_owned()),
        );
        Self {
            provider: Arc::new(provider),
        }
    }

    pub async fn get_access_list_for_identifier(
        &self,
        identifier: &IdentifierWithPayload,
    ) -> Result<AccessListResponse, Box<dyn std::error::Error>> {
        self.provider
            .raw_request::<[IdentifierWithPayload; 1], AccessListResponse>(
                "admin_getAccessListForIdentifier".into(),
                [identifier.to_owned()],
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}

pub fn build_payload(log: &Log) -> Bytes {
    let mut payload = vec![];
    payload.extend_from_slice(log.topics().concat().as_slice());
    payload.extend_from_slice(&log.data().data);
    payload.into()
}

pub async fn relay_message(
    log: &Log,
    source_timestamp: u64,
    source_chain_id: u64,
    dest_provider: &AnyProvider,
    op_admin_provider: &SupersimAdminProvider,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = build_payload(log);

    let id_req =
        IdentifierWithPayload::new(log, source_timestamp, source_chain_id, payload.to_owned());
    let access_list = op_admin_provider
        .get_access_list_for_identifier(&id_req)
        .await?;

    let calldata = relayMessageCall {
        _id: id_req.to_sol(),
        _sentMessage: payload.into(),
    }
    .abi_encode();

    let tx_req = TransactionRequest::default()
        .to(*L2_TO_L2_CROSS_DOMAIN_MESSENGER)
        .input(calldata.into())
        .access_list(access_list.access_list);

    dest_provider
        .send_transaction(tx_req.into())
        .await
        .inspect_err(|e| {
            println!("Failed to send transaction: {e}");
        })
        .ok();
    Ok(())
}

/// Finds cross-chain log in the transaction receipt if present.
/// Returns `None` if xchain log not present.
pub async fn find_xchain_log(
    receipt: &AnyTransactionReceipt,
) -> Result<Option<Log>, Box<dyn std::error::Error>> {
    match receipt.inner.to {
        Some(to) if to == *SUPERCHAIN_TOKEN_BRIDGE => {}
        _ => return Ok(None),
    };

    let log = receipt
        .inner
        .inner
        .logs()
        .iter()
        .find(|log| log.topics().first().map(|t| *t) == Some(*XCHAIN_LOG_TOPIC))
        .cloned();

    Ok(log)
}
