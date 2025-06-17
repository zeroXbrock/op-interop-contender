use crate::contracts::{self, L2_TO_L2_CROSS_DOMAIN_MESSENGER};
use contender_core::alloy::{
    hex::{FromHex, ToHexExt},
    network::{AnyNetwork, AnyTransactionReceipt},
    primitives::{Address, Bytes, FixedBytes, U256, keccak256},
    providers::{DynProvider, PendingTransactionConfig, Provider, ProviderBuilder},
    rpc::types::{AccessList, AccessListItem, Log, TransactionRequest},
    sol,
    sol_types::SolCall,
    transports::http::reqwest::Url,
};
use contender_core::generator::types::AnyProvider;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock};

pub static XCHAIN_LOG_TOPIC: LazyLock<FixedBytes<32>> = LazyLock::new(|| {
    FixedBytes::<32>::from_hex("0x382409ac69001e11931a28435afef442cbfd20d9891907e8fa373ba7d351f320")
        .expect("invalid topic")
});

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

pub struct ChecksumArgs {
    block_number: u64,
    timestamp: u64,
    log_index: u32,
    chain_id: U256,
    log_hash: FixedBytes<32>,
}

pub struct Access {
    pub block_number: u64,
    pub timestamp: u64,
    pub log_index: u32,
    pub chain_id: U256,
    pub checksum: FixedBytes<32>,
}

impl Access {
    fn lookup_entry(&self) -> FixedBytes<32> {
        println!("calculating lookup entry");
        const PREFIX_LOOKUP: u8 = 0x01;

        let mut out = [0u8; 32];
        out[0] = PREFIX_LOOKUP;

        // Write chain_id (as u64) at offset 4, since we've already used index 0 and leave indexes 1-3 as zero.
        out[4..12].copy_from_slice(&self.chain_id.to_be_bytes::<32>()[..8]);

        // Write block_number at offset 12.
        out[12..20].copy_from_slice(&U256::from(self.block_number).to_be_bytes::<32>()[..8]);

        // Write timestamp at offset 20.
        out[20..28].copy_from_slice(&U256::from(self.timestamp).to_be_bytes::<32>()[..8]);

        // Write log_index at offset 28.
        out[28..32].copy_from_slice(&U256::from(self.log_index).to_be_bytes::<32>()[..4]);

        FixedBytes::from(out)
    }

    fn chain_id_extension_entry(&self) -> FixedBytes<32> {
        println!("calculating chain_id extension entry");
        const PREFIX_CHAIN_ID_EXTENSION: u8 = 0x02;
        let mut out = [0u8; 32];
        out[0] = PREFIX_CHAIN_ID_EXTENSION;
        let chain_id_bytes = &self.chain_id.to_be_bytes::<32>()[..24];
        out[8..32].copy_from_slice(chain_id_bytes);
        FixedBytes::from(out)
    }
}

impl ChecksumArgs {
    pub fn access(&self) -> Access {
        Access {
            block_number: self.block_number,
            timestamp: self.timestamp,
            log_index: self.log_index,
            chain_id: self.chain_id,
            checksum: self.checksum(),
        }
    }

    pub fn checksum(&self) -> FixedBytes<32> {
        println!("calculating checksum");
        let mut id_packed = Vec::with_capacity(32); // 12 zero bytes + u64 + u64 + u32
        id_packed.extend_from_slice(&[0u8; 12]);
        id_packed.extend_from_slice(&self.block_number.to_be_bytes());
        id_packed.extend_from_slice(&self.timestamp.to_be_bytes());
        id_packed.extend_from_slice(&self.log_index.to_be_bytes());
        let id_log_hash = keccak256([self.log_hash.as_slice(), id_packed.as_slice()].concat());
        let chain_id_bytes = self.chain_id.to_be_bytes::<32>();
        let mut out = keccak256([id_log_hash.as_slice(), &chain_id_bytes].concat());
        out[0] = 0x03; // type/version byte
        out
    }
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

    pub fn checksum_args(&self, msg_hash: FixedBytes<32>) -> ChecksumArgs {
        ChecksumArgs {
            block_number: self.block_number,
            timestamp: self.timestamp,
            log_index: self.log_index as u32,
            chain_id: U256::from(self.chain_id),
            log_hash: payload_hash_to_log_hash(msg_hash, self.origin),
        }
    }
}

fn payload_hash_to_log_hash(payload_hash: FixedBytes<32>, origin: Address) -> FixedBytes<32> {
    let mut msg = Vec::with_capacity(64); // 20 bytes for address (padded to 32) + 32 bytes for hash
    msg.extend_from_slice(origin.as_slice());
    msg.extend_from_slice(payload_hash.as_slice());
    keccak256(&msg)
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
        get_access_list_for_identifier(identifier)
            .map(|access_list| AccessListResponse { access_list })
    }
}

fn encode_access_list(accesses: &[Access]) -> Vec<FixedBytes<32>> {
    let mut out = Vec::with_capacity(accesses.len() * 2);
    for acc in accesses {
        out.push(acc.lookup_entry());
        if acc.chain_id <= U256::from(u64::MAX) {
            out.push(acc.chain_id_extension_entry());
        }
        println!("checksum: {}", acc.checksum.encode_hex());
        if acc.checksum.as_slice()[0] != 0x03 {
            panic!("invalid checksum entry");
        }
        out.push(acc.checksum);
    }
    out
}

fn get_access_list_for_identifier(
    identifier: &IdentifierWithPayload,
) -> Result<AccessList, Box<dyn std::error::Error>> {
    if identifier.origin == Address::ZERO {
        return Err("Origin address cannot be zero".into());
    }

    let access = identifier
        .checksum_args(keccak256(identifier.payload.to_owned()))
        .access();
    let access_list: AccessList = vec![AccessListItem {
        address: contracts::CROSS_L2_INBOX.to_owned(),
        storage_keys: encode_access_list(&[access]),
    }]
    .into();

    Ok(access_list)
}

pub fn build_payload(log: &Log) -> Bytes {
    let mut payload = log.topics().concat();
    payload.extend_from_slice(&log.data().data);
    payload.into()
}

pub async fn relay_message(
    log: &Log,
    source_timestamp: u64,
    source_chain_id: u64,
    dest_provider: &AnyProvider,
    op_admin_provider: &SupersimAdminProvider,
) -> Result<Option<PendingTransactionConfig>, Box<dyn std::error::Error>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use contender_core::alloy::primitives::Bytes;

    #[test]
    fn test_checksum_args() {
        let args = ChecksumArgs {
            block_number: 123456,
            timestamp: 1622547800,
            log_index: 42,
            chain_id: U256::from(1),
            log_hash: FixedBytes::<32>::from([0u8; 32]),
        };
        let access = args.access();
        assert_eq!(access.block_number, 123456);
        assert_eq!(access.timestamp, 1622547800);
        assert_eq!(access.log_index, 42);
        assert_eq!(access.chain_id, U256::from(1));
    }

    #[test]
    fn test_lookup_entry() {
        let access = Access {
            block_number: 123456,
            timestamp: 1622547800,
            log_index: 42,
            chain_id: U256::from(1),
            checksum: FixedBytes::<32>::from([0u8; 32]),
        };
        let entry = access.lookup_entry();
        assert_eq!(entry.as_slice()[0], 0x01); // Check prefix
        assert_eq!(
            &entry.as_slice()[4..12],
            &U256::from(1).to_be_bytes::<32>()[..8]
        );
        assert_eq!(
            &entry.as_slice()[12..20],
            &U256::from(123456).to_be_bytes::<32>()[..8]
        );
        assert_eq!(
            &entry.as_slice()[20..28],
            &U256::from(1622547800).to_be_bytes::<32>()[..8]
        );
        assert_eq!(
            &entry.as_slice()[28..32],
            &U256::from(42).to_be_bytes::<32>()[..4]
        );
    }

    #[test]
    fn test_encode_access_list() {
        let checksum_args = ChecksumArgs {
            block_number: 123456,
            timestamp: 1622547800,
            log_index: 42,
            chain_id: U256::from(1),
            log_hash: FixedBytes::<32>::from([0u8; 32]),
        };
        let access = Access {
            block_number: 123456,
            timestamp: 1622547800,
            log_index: 42,
            chain_id: U256::from(1),
            checksum: checksum_args.checksum(),
        };
        let accesses = vec![access];
        let encoded = encode_access_list(&accesses);
        assert_eq!(encoded.len(), 3); // 1 lookup entry + 1 chain_id extension + 1 checksum
    }
}
