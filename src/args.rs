use contender_core::alloy::{signers::local::PrivateKeySigner, transports::http::reqwest::Url};
use std::str::FromStr;
use tracing::warn;

pub struct SpamArgs {
    pub sender: PrivateKeySigner,
    pub source_url: Url,
    pub destination_url: Url,
    /// TODO: remove this; calculate access list locally
    pub supersim_admin_url: Url,
    pub txs_per_batch: u64,
    pub duration: u64,
    pub make_report: bool,
}

impl SpamArgs {
    pub fn from_env() -> Self {
        let sender = PrivateKeySigner::from_str(&read_var(
            "SPAM_SENDER_PRIVATE_KEY",
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_owned(),
        ))
        .expect("Invalid private key format");

        let source_url = Url::from_str(&read_var(
            "SPAM_ORIGIN_RPC",
            "http://localhost:9545".to_string(),
        ))
        .expect("Invalid source URL format");

        let destination_url = Url::from_str(&read_var(
            "SPAM_DEST_RPC",
            "http://localhost:9546".to_string(),
        ))
        .expect("Invalid destination URL format");

        let supersim_admin_url = Url::from_str(&read_var(
            "OP_ADMIN_URL",
            "http://localhost:8420".to_string(),
        ))
        .expect("Invalid Supersim admin URL format");

        let txs_per_batch = read_var("SPAM_TXS_PER_BATCH", 25);
        let duration = read_var("SPAM_DURATION", 5);
        let make_report = read_var("SPAM_MAKE_REPORT", false);

        Self {
            sender,
            source_url,
            destination_url,
            supersim_admin_url,
            txs_per_batch,
            duration,
            make_report,
        }
    }
}

fn read_var<T: FromStr + std::fmt::Display + Clone>(varname: &str, default: T) -> T {
    std::env::var(varname)
        .ok()
        .and_then(|v| v.parse::<T>().ok())
        .unwrap_or_else(|| {
            warn!("{varname} not set, defaulting to {default}");
            default
        })
}
