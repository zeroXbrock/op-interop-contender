use contender_core::alloy::{
    primitives::{Address, Bytes, FixedBytes, U256, keccak256},
    rpc::types::{AccessList, AccessListItem, Log},
    sol,
};
use serde::{Deserialize, Serialize};

use crate::contracts;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentifierWithPayload {
    pub origin: Address,
    pub block_number: u64,
    pub log_index: u64,
    pub timestamp: u64,
    pub chain_id: u64,
    pub payload: Bytes,
}

pub struct ChecksumArgs {
    pub block_number: u64,
    pub timestamp: u64,
    pub log_index: u32,
    pub chain_id: U256,
    pub log_hash: FixedBytes<32>,
}

pub struct Access {
    pub block_number: u64,
    pub timestamp: u64,
    pub log_index: u32,
    pub chain_id: U256,
    pub checksum: FixedBytes<32>,
}

pub struct AdminAPI {}

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

impl AdminAPI {
    pub async fn get_access_list_for_identifier(
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

impl Access {
    pub fn lookup_entry(&self) -> FixedBytes<32> {
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

    pub fn chain_id_extension_entry(&self) -> FixedBytes<32> {
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

pub fn encode_access_list(accesses: &[Access]) -> Vec<FixedBytes<32>> {
    let mut out = Vec::with_capacity(accesses.len() * 2);
    for acc in accesses {
        out.push(acc.lookup_entry());
        if acc.chain_id <= U256::from(u64::MAX) {
            out.push(acc.chain_id_extension_entry());
        }
        if acc.checksum.as_slice()[0] != 0x03 {
            panic!("invalid checksum entry");
        }
        out.push(acc.checksum);
    }
    out
}

fn payload_hash_to_log_hash(payload_hash: FixedBytes<32>, origin: Address) -> FixedBytes<32> {
    let mut msg = Vec::with_capacity(64); // 20 bytes for address (padded to 32) + 32 bytes for hash
    msg.extend_from_slice(origin.as_slice());
    msg.extend_from_slice(payload_hash.as_slice());
    keccak256(&msg)
}

#[cfg(test)]
mod tests {
    use contender_core::alloy::primitives::U256;

    use crate::admin_api::{Access, ChecksumArgs, encode_access_list};

    use super::*;

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
