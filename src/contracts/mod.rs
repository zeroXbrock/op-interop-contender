use std::sync::LazyLock;

use alloy::{
    hex::FromHex,
    primitives::{Address, FixedBytes},
};

pub static L2_TO_L2_CROSS_DOMAIN_MESSENGER: LazyLock<Address> = LazyLock::new(|| {
    "0x4200000000000000000000000000000000000023"
        .parse::<Address>()
        .expect("Invalid address")
});

pub static SUPERCHAIN_TOKEN_BRIDGE: LazyLock<Address> = LazyLock::new(|| {
    "0x4200000000000000000000000000000000000028"
        .parse::<Address>()
        .expect("Invalid address")
});

pub static XCHAIN_LOG_TOPIC: LazyLock<FixedBytes<32>> = LazyLock::new(|| {
    FixedBytes::<32>::from_hex("0x382409ac69001e11931a28435afef442cbfd20d9891907e8fa373ba7d351f320")
        .expect("invalid topic")
});
