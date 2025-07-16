//! https://github.com/zeroXbrock/interop-contracts/blob/main/src/CrossChainBulletinBoard.sol

use contender_core::{
    alloy::{hex::ToHexExt, primitives::Address},
    generator::types::{FunctionCallDefinition, SpamRequest},
};
use contender_testfile::TestConfig;

pub fn get_config(bulletin_board: Address, destination_chainid: u64) -> TestConfig {
    TestConfig {
        env: None,
        // no create steps because we need to deploy the contracts on two chains
        // so we have our own deployment code
        create: None,
        setup: None,
        spam: Some(vec![SpamRequest::Tx(FunctionCallDefinition {
            to: bulletin_board.to_string(),
            from: None,
            from_pool: Some("spammers".into()),
            signature: Some("postBulletin(uint256 toChainId, bytes calldata data)".to_string()),
            args: Some(vec![destination_chainid.to_string(), "howdy".encode_hex()]),
            gas_limit: None,
            value: None,
            fuzz: None,
            kind: None,
        })]),
    }
}
