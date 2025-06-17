use std::sync::LazyLock;

use contender_core::alloy::primitives::Address;

pub static L2_TO_L2_CROSS_DOMAIN_MESSENGER: LazyLock<Address> = LazyLock::new(|| {
    "0x4200000000000000000000000000000000000023"
        .parse::<Address>()
        .expect("Invalid address")
});

pub mod bytecode {
    pub static BULLETIN_BOARD: &str = include_str!("./CrossChainBulletinBoard.hex");
    pub static CREATE2_FACTORY: &str = include_str!("./Create2Factory.hex");
}
