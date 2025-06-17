use crate::{
    admin_api::{AdminAPI, IdentifierWithPayload, relayMessageCall},
    contracts::L2_TO_L2_CROSS_DOMAIN_MESSENGER,
};
use contender_core::alloy::{
    hex::FromHex,
    network::AnyTransactionReceipt,
    primitives::{Bytes, FixedBytes},
    providers::{PendingTransactionConfig, Provider},
    rpc::types::{Log, TransactionRequest},
    sol_types::SolCall,
};
use contender_core::generator::types::AnyProvider;
use std::sync::LazyLock;

pub static XCHAIN_LOG_TOPIC: LazyLock<FixedBytes<32>> = LazyLock::new(|| {
    FixedBytes::<32>::from_hex("0x382409ac69001e11931a28435afef442cbfd20d9891907e8fa373ba7d351f320")
        .expect("invalid topic")
});

pub async fn relay_message(
    log: &Log,
    source_timestamp: u64,
    source_chain_id: u64,
    dest_provider: &AnyProvider,
) -> Result<Option<PendingTransactionConfig>, Box<dyn std::error::Error>> {
    let payload = build_payload(log);

    let id_req =
        IdentifierWithPayload::new(log, source_timestamp, source_chain_id, payload.to_owned());
    let access_list = AdminAPI::get_access_list_for_identifier(&id_req).await?;

    let calldata = relayMessageCall {
        _id: id_req.to_sol(),
        _sentMessage: payload.into(),
    }
    .abi_encode();

    let tx_req = TransactionRequest::default()
        .to(*L2_TO_L2_CROSS_DOMAIN_MESSENGER)
        .input(calldata.into())
        .access_list(access_list);

    let pending_tx = dest_provider
        .send_transaction(tx_req.into())
        .await
        .inspect_err(|e| {
            println!("Failed to send transaction: {e}");
        })
        .ok();
    Ok(pending_tx.map(|tx| tx.inner().to_owned()))
}

/// Finds cross-chain log in the transaction receipt if present.
/// Returns `None` if xchain log not present.
pub async fn find_xchain_log(
    receipt: &AnyTransactionReceipt,
) -> Result<Option<Log>, Box<dyn std::error::Error>> {
    let log = receipt
        .inner
        .inner
        .logs()
        .iter()
        .find(|log| log.topics().first().map(|t| *t) == Some(*XCHAIN_LOG_TOPIC))
        .cloned();

    Ok(log)
}

pub fn build_payload(log: &Log) -> Bytes {
    let mut payload = log.topics().concat();
    payload.extend_from_slice(&log.data().data);
    payload.into()
}
