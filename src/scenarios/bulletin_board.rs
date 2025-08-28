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
        spam: Some(vec![SpamRequest::Tx(
            FunctionCallDefinition::new(bulletin_board.to_string())
                .with_from_pool("spammers")
                .with_signature("postBulletin(uint256 toChainId, bytes calldata data)")
                .with_args(&[destination_chainid.to_string(), "howdy".encode_hex()])
                .into(),
        )]),
    }
}
