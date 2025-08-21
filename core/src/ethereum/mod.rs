mod contract;
use crate::config::EthereumConfig;
use crate::ethereum::contract::{RecipientRefunded, UserAddDeposit, UserRegistered};
use crate::persist::{repo, PersistCtx};

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use futures_util::StreamExt;
use log::{error, info, warn};
use tokio;
use tokio::task::JoinHandle;

pub struct EthereumListener {
    config: EthereumConfig,
    persist_ctx: PersistCtx,
}

/// EthereumListener is responsible for listening to Ethereum blockchain events and processing them.
///
/// # Notes
/// - This is a slow asynchronous operation that fetches transactions from both the blockchain and the database.
/// - It can become a bottleneck for performance in high-throughput scenarios.
///
/// # TODO
/// - Optimize the implementation to improve performance.
/// - Consider batching or parallelizing operations where possible.
impl EthereumListener {
    pub fn new(config: EthereumConfig, persist_ctx: PersistCtx) -> Self {
        Self {
            config,
            persist_ctx,
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let ws = WsConnect::new(&self.config.ws_rpc_url);
        let provider = ProviderBuilder::new().connect_ws(ws).await?;

        let contract_address: Address = self.config.contract_address.parse()?;
        let filter = Filter::new()
            .address(contract_address)
            .events(vec![
                UserRegistered::SIGNATURE,
                UserAddDeposit::SIGNATURE,
                RecipientRefunded::SIGNATURE,
            ])
            .from_block(BlockNumberOrTag::Latest);

        let persist_ctx = self.persist_ctx.clone();
        let _: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            // TODO: Handle failures and try to reconnect.

            // Subscribe to logs.
            let sub = provider.subscribe_logs(&filter).await.map_err(|err| {
                error!("Failed to subscribe to logs: {err}");
                err
            })?;
            let mut stream = sub.into_stream();

            info!("[EthereumListener] Subscribed to contract \"{contract_address}\" events");

            while let Some(log) = stream.next().await {
                match log.topic0() {
                    Some(&UserRegistered::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<UserRegistered>().map_err(|err| {
                            error!("[EthereumListener] Error when decoding log: {err}");
                        }) else {
                            continue;
                        };
                        info!("[EthereumListener] Received: {:?}", log.data());

                        let UserRegistered { _from, _collateral } = log.data();

                        repo::register_user_with_deposit(
                            &persist_ctx,
                            _from.to_string(),
                            _collateral.into(),
                        )
                        .await
                        .map_err(|err| {
                            error!("Failed to register user: {err}");
                            err
                        })
                        .ok();
                    }
                    Some(&UserAddDeposit::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<UserAddDeposit>().map_err(|err| {
                            error!("[EthereumListener] Error when decoding log: {err}");
                        }) else {
                            continue;
                        };
                        info!("[EthereumListener] Received: {:?}", log.data());

                        let UserAddDeposit { _from, _collateral } = log.data();

                        repo::add_user_deposit(&persist_ctx, _from.to_string(), _collateral.into())
                            .await
                            .map_err(|err| {
                                error!("Failed to add user deposit: {err}");
                                err
                            })
                            .ok();
                    }
                    Some(&RecipientRefunded::SIGNATURE_HASH) => {
                        let Ok(log) = log.log_decode::<RecipientRefunded>().map_err(|err| {
                            error!("[EthereumListener] Error when decoding log: {err}");
                        }) else {
                            continue;
                        };
                        info!("[EthereumListener] Received: {:?}", log.data());

                        let RecipientRefunded {
                            transactionHash: transaction_hash,
                            sender,
                            ..
                        } = log.data();

                        repo::fail_transaction(
                            &persist_ctx,
                            sender.to_string(),
                            transaction_hash.to_string(),
                        )
                        .await
                        .map_err(|err| {
                            error!("Failed to fail the transaction: {err}");
                            err
                        })
                        .ok();
                    }
                    log => {
                        info!("[EthereumListener] Received unknown log: {log:?}");
                    }
                }
            }

            warn!("Exited from the Ethereum listener loop!");
            Ok(())
        });

        Ok(())
    }
}
