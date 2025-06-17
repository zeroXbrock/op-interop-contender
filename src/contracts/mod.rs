use std::sync::LazyLock;

use contender_core::alloy::{primitives::Address, sol};

pub static L2_TO_L2_CROSS_DOMAIN_MESSENGER: LazyLock<Address> = LazyLock::new(|| {
    "0x4200000000000000000000000000000000000023"
        .parse::<Address>()
        .expect("Invalid address")
});

pub static CROSS_L2_INBOX: LazyLock<Address> = LazyLock::new(|| {
    "0x4200000000000000000000000000000000000022"
        .parse::<Address>()
        .expect("Invalid address")
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

pub mod bytecode {
    use std::{str::FromStr, sync::LazyLock};

    use contender_core::alloy::primitives::Bytes;

    pub static BULLETIN_BOARD: LazyLock<Bytes> = LazyLock::new(|| {
        Bytes::from_str(include_str!("./CrossChainBulletinBoard.hex"))
            .expect("failed to parse CrossChainBulletinBoard bytecode")
    });
    pub static CREATE2_FACTORY: LazyLock<Bytes> = LazyLock::new(|| {
        Bytes::from_str(include_str!("./Create2Factory.hex"))
            .expect("failed to parse Create2Factory bytecode")
    });
}
