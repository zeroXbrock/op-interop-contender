use std::sync::LazyLock;

use contender_core::alloy::primitives::Address;

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
