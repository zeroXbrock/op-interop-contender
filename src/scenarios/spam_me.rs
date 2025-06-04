//! Left here as an example of how to set up a spam scenario manually.

use contender_core::generator::types::{CreateDefinition, FunctionCallDefinition, SpamRequest};
use contender_testfile::TestConfig;
use std::sync::LazyLock;

pub static CONFIG: LazyLock<TestConfig> = LazyLock::new(|| TestConfig {
    env: None,
    create: Some(vec![CreateDefinition {
        bytecode: include_str!("../contracts/SpamMe.hex").into(),
        name: "test_contract".into(),
        from: None,
        from_pool: Some("admin".into()),
    }]),
    setup: None,
    spam: Some(vec![SpamRequest::Tx(FunctionCallDefinition {
        to: "{test_contract}".into(),
        from: None,
        from_pool: Some("spammers".into()),
        signature: "consumeGas()".into(),
        args: None,
        gas_limit: Some(120000),
        value: None,
        fuzz: None,
        kind: None,
    })]),
});
