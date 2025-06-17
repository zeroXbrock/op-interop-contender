use crate::{contracts::bytecode, utils::Create2Factory::deployCall};
use contender_core::{
    alloy::{
        network::{AnyTxEnvelope, EthereumWallet, ReceiptResponse, TransactionBuilder},
        primitives::{Address, Bytes, FixedBytes, TxKind},
        providers::Provider,
        rpc::types::{TransactionInput, TransactionRequest},
        signers::local::PrivateKeySigner,
        sol,
        sol_types::{SolEvent, SolInterface},
    },
    generator::types::AnyProvider,
};
use std::str::FromStr;

sol! {
    contract Create2Factory {
        event Deployed(address indexed addr);

        function deploy(bytes32 salt, bytes calldata code) external payable returns (address);
    }
}

pub async fn deploy_create2_factory(
    provider: &AnyProvider,
    sender: &PrivateKeySigner,
) -> Result<Address, Box<dyn std::error::Error>> {
    let tx = TransactionRequest {
        from: Some(sender.address()),
        to: Some(TxKind::Create),
        input: TransactionInput::both(
            Bytes::from_str(bytecode::CREATE2_FACTORY).expect("invalid bytecode hex"),
        ),
        ..Default::default()
    };
    let tx = prepare_tx_request(tx, provider, sender).await?;
    let signed_tx = tx.build(&EthereumWallet::new(sender.to_owned())).await?;

    let tx_hash = provider
        .send_tx_envelope(AnyTxEnvelope::Ethereum(signed_tx))
        .await?
        .watch()
        .await?;
    let receipt = provider.get_transaction_receipt(tx_hash).await?;
    // get the contract address from the receipt
    if let Some(receipt) = receipt {
        if let Some(address) = receipt.contract_address() {
            return Ok(address);
        }
    }
    Err("Deployment failed or no contract address found".into())
}

pub async fn deploy_create2_contract(
    factory: Address,
    salt: FixedBytes<32>,
    code: Bytes,
    provider: &AnyProvider,
    sender: &PrivateKeySigner,
) -> Result<Address, Box<dyn std::error::Error>> {
    let tx = TransactionRequest {
        from: sender.address().into(),
        to: Some(TxKind::Call(factory)),
        input: TransactionInput::new(
            Create2Factory::Create2FactoryCalls::deploy(deployCall { salt, code })
                .abi_encode()
                .into(),
        ),
        ..Default::default()
    };
    let tx = prepare_tx_request(tx, provider, sender).await?;

    // sign tx
    let signer = EthereumWallet::new(sender.to_owned());
    let signed_tx = tx.build(&signer).await?;

    // send tx
    let tx_hash = provider
        .send_tx_envelope(AnyTxEnvelope::Ethereum(signed_tx))
        .await?
        .with_required_confirmations(1)
        .watch()
        .await?;

    // parse the 'Deployed' event to get the address
    let receipt = provider.get_transaction_receipt(tx_hash).await?;
    if let Some(receipt) = receipt {
        if !receipt.status() {
            return Err("Transaction failed".into());
        }

        for log in receipt.inner.inner.logs() {
            if log.topics()[0] == Create2Factory::Deployed::SIGNATURE_HASH
                && log.topics().len() == 2
            {
                return Ok(Address::from_slice(&log.topics()[1].0[12..]));
            }
        }
    }

    Err("Deployment failed or no Deployed event found".into())
}

async fn prepare_tx_request(
    tx: TransactionRequest,
    provider: &AnyProvider,
    sender: &PrivateKeySigner,
) -> Result<TransactionRequest, Box<dyn std::error::Error>> {
    let gas_price = provider.get_gas_price().await?;
    let nonce = provider.get_transaction_count(sender.address()).await?;
    let tx = tx
        .with_max_fee_per_gas(gas_price)
        .with_max_priority_fee_per_gas(gas_price / 10)
        .with_nonce(nonce)
        .with_chain_id(provider.get_chain_id().await?);
    let gas_estimate = provider.estimate_gas(tx.to_owned().into()).await?;

    Ok(tx.with_gas_limit(gas_estimate))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use contender_core::alloy::{
        network::AnyNetwork,
        node_bindings::{Anvil, AnvilInstance},
        providers::{DynProvider, ProviderBuilder},
        signers::local::PrivateKeySigner,
    };

    pub fn get_provider(anvil: &AnvilInstance) -> DynProvider<AnyNetwork> {
        DynProvider::new(
            ProviderBuilder::new()
                .network::<AnyNetwork>()
                .connect_http(anvil.endpoint_url()),
        )
    }

    pub fn get_signer() -> PrivateKeySigner {
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse::<PrivateKeySigner>()
            .unwrap()
    }

    #[tokio::test]
    async fn test_deploy_create2_factory() {
        let anvil = Anvil::new().spawn();
        let provider = get_provider(&anvil);
        let signer = get_signer();

        let factory_address = deploy_create2_factory(&provider, &signer).await.unwrap();
        // check code at the factory address
        let code = provider.get_code_at(factory_address).await.unwrap();
        println!("Factory deployed at: {:?}", factory_address);
        println!("Factory code: {:?}", code);
        assert!(
            !code.is_empty(),
            "Factory contract code should not be empty"
        );
    }

    #[tokio::test]
    async fn test_deploy_create2_contract() -> Result<(), Box<dyn std::error::Error>> {
        let anvil = Anvil::new().spawn();
        let provider = get_provider(&anvil);
        let signer = get_signer();

        let factory_address = deploy_create2_factory(&provider, &signer).await?;
        let salt = [1u8; 32];
        let code = Bytes::from_str(bytecode::BULLETIN_BOARD)?;

        let contract_address =
            deploy_create2_contract(factory_address, salt.into(), code, &provider, &signer)
                .await
                .unwrap();

        // check code at the contract address
        let code_at_address = provider.get_code_at(contract_address).await?;
        println!("Contract deployed at: {:?}", contract_address);
        assert!(
            !code_at_address.is_empty(),
            "Deployed contract code should not be empty"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_create2_deployments_same_on_different_chains()
    -> Result<(), Box<dyn std::error::Error>> {
        let anvil1 = Anvil::new().chain_id(42).spawn();
        let anvil2 = Anvil::new().chain_id(43).spawn();
        let provider1 = get_provider(&anvil1);
        let provider2 = get_provider(&anvil2);
        let signer = get_signer();

        let factory_address_1 = deploy_create2_factory(&provider1, &signer).await?;
        let factory_address_2 = deploy_create2_factory(&provider2, &signer).await?;
        let salt = [1u8; 32];
        let code = Bytes::from_str(bytecode::BULLETIN_BOARD)?;

        println!(
            "Factory addresses: {:?} on chain 1, {:?} on chain 2",
            factory_address_1, factory_address_2
        );

        let contract_address1 = deploy_create2_contract(
            factory_address_1,
            salt.into(),
            code.clone(),
            &provider1,
            &signer,
        )
        .await?;

        let contract_address2 =
            deploy_create2_contract(factory_address_2, salt.into(), code, &provider2, &signer)
                .await?;

        assert_eq!(contract_address1, contract_address2);
        println!(
            "Both deployments resulted in the same contract address: {:?}",
            contract_address1
        );

        Ok(())
    }
}
