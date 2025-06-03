use std::sync::LazyLock;

use contender_core::alloy::primitives::Address;

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
