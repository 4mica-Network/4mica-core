use alloy::rpc::types::Log;
use alloy_primitives::Address;
use async_trait::async_trait;
use entities::sea_orm_active_enums::CollateralEventType;
use log::{info, warn};
use metrics_4mica::measure;

use crate::metrics::misc::record_event_handler_time;
use crate::{
    error::BlockchainListenerError,
    ethereum::{contract::*, event_data::EventMeta, event_handler::EthereumEventHandler},
    persist::repo,
    service::CoreService,
};

#[async_trait]
impl EthereumEventHandler for CoreService {
    #[measure(record_event_handler_time, name = "collateral_deposited")]
    async fn handle_collateral_deposited(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CollateralDeposited {
            user,
            amount,
            asset,
            ..
        } = *log.log_decode()?.data();
        info!("Deposit by {user:?} of {amount}, asset={asset}");

        let meta = self.event_meta_from_log(&log)?;
        repo::credit_collateral_with_event_on(
            self.inner.persist_ctx.db.as_ref(),
            user.to_string(),
            asset.to_string(),
            amount,
            CollateralEventType::Deposit,
            Some(meta),
        )
        .await?;
        self.sync_stablecoin_balance_from_chain(user, asset).await?;
        Ok(())
    }

    #[measure(record_event_handler_time, name = "collateral_withdrawn")]
    async fn handle_collateral_withdrawn(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CollateralWithdrawn {
            user,
            asset,
            amount,
            ..
        } = *log.log_decode()?.data();
        info!("Collateral withdrawn by {user:?}: {amount}");

        let meta = self.event_meta_from_log(&log)?;
        if self.stablecoin_a_token(asset).await?.is_some() {
            repo::mark_withdrawal_executed_with_event(
                &self.inner.persist_ctx,
                user.to_string(),
                asset.to_string(),
                amount,
                Some(&meta),
            )
            .await?;
            self.sync_stablecoin_balance_from_chain(user, asset).await?;
        } else {
            repo::finalize_withdrawal_with_event(
                &self.inner.persist_ctx,
                user.to_string(),
                asset.to_string(),
                amount,
                Some(&meta),
            )
            .await?;
        }
        Ok(())
    }

    #[measure(record_event_handler_time, name = "withdrawal_requested")]
    async fn handle_withdrawal_requested(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let WithdrawalRequested {
            user,
            asset,
            when,
            amount,
            ..
        } = *log.log_decode()?.data();
        info!("Withdrawal requested: {user:?}, asset={asset}, when={when}, amount={amount}");

        let meta = self.event_meta_from_log(&log)?;
        repo::request_withdrawal_with_event(
            &self.inner.persist_ctx,
            user.to_string(),
            asset.to_string(),
            when.to(),
            amount,
            Some(&meta),
        )
        .await?;
        Ok(())
    }

    #[measure(record_event_handler_time, name = "withdrawal_canceled")]
    async fn handle_withdrawal_canceled(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let WithdrawalCanceled { user, asset, .. } = *log.log_decode()?.data();
        info!("Withdrawal canceled by {user:?}, asset={asset}");

        let meta = self.event_meta_from_log(&log)?;
        repo::cancel_withdrawal_with_event(
            &self.inner.persist_ctx,
            user.to_string(),
            asset.to_string(),
            Some(&meta),
        )
        .await?;
        Ok(())
    }

    #[measure(record_event_handler_time, name = "cycle_committed")]
    async fn handle_cycle_committed(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CycleCommitted { cycleId, .. } = *log.log_decode()?.data();
        let tx_hash = tx_hash_from_log(&log)?;
        self.process_cycle_committed(cycleId, &tx_hash)
            .await
            .map_err(|e| BlockchainListenerError::EventHandlerError(e.to_string()))
    }

    #[measure(record_event_handler_time, name = "debtor_paid")]
    async fn handle_debtor_paid(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let DebtorPaid {
            cycleId, debtor, ..
        } = *log.log_decode()?.data();
        let tx_hash = tx_hash_from_log(&log)?;
        self.process_paid_debtor(cycleId, &debtor.to_string(), &tx_hash)
            .await
            .map_err(|e| BlockchainListenerError::EventHandlerError(e.to_string()))
    }

    #[measure(record_event_handler_time, name = "creditor_claimed")]
    async fn handle_creditor_claimed(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CreditorClaimed {
            cycleId,
            creditor,
            asset,
            amount,
        } = *log.log_decode()?.data();

        let meta = self.event_meta_from_log(&log)?;
        self.process_credit_claim(
            cycleId,
            creditor.to_string(),
            asset.to_string(),
            amount,
            meta,
        )
        .await
        .map_err(|e| BlockchainListenerError::EventHandlerError(e.to_string()))
    }

    #[measure(record_event_handler_time, name = "debtor_defaulted")]
    async fn handle_debtor_defaulted(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let DebtorDefaulted {
            cycleId,
            debtor,
            asset,
            amount,
        } = *log.log_decode()?.data();

        let meta = self.event_meta_from_log(&log)?;
        self.process_defaulted_debtor(cycleId, debtor.to_string(), asset.to_string(), amount, meta)
            .await
            .map_err(|e| BlockchainListenerError::EventHandlerError(e.to_string()))
    }

    #[measure(record_event_handler_time, name = "cycle_finalized")]
    async fn handle_cycle_finalized(&self, log: Log) -> Result<(), BlockchainListenerError> {
        let CycleFinalized { cycleId, .. } = *log.log_decode()?.data();
        self.process_cycle_finalized(cycleId)
            .await
            .map_err(|e| BlockchainListenerError::EventHandlerError(e.to_string()))
    }

    #[measure(record_event_handler_time, name = "admin_event")]
    async fn handle_admin_event(
        &self,
        log: Log,
        event_name: &str,
    ) -> Result<(), BlockchainListenerError> {
        match event_name {
            "WithdrawalGracePeriodUpdated" => {
                let WithdrawalGracePeriodUpdated {
                    newGracePeriod: new_grace_period,
                    ..
                } = *log.log_decode()?.data();
                let new_grace_period = new_grace_period.to();
                info!("WithdrawalGracePeriodUpdated: {}s", new_grace_period);
                self.set_withdrawal_grace_period(new_grace_period);

                // Surface a governance change that breaks the
                // delayed-withdrawal solvency invariant; health checks will report it.
                if let Err(err) = self.check_settlement_timing_invariant() {
                    warn!(
                        "settlement timing invariant violated after grace-period update: {err:#}"
                    );
                }
            }
            "VerificationKeyUpdated" => {
                let ev = log.log_decode::<VerificationKeyUpdated>()?;
                info!("{:?}", ev);
            }
            "GuaranteeVersionUpdated" => {
                let ev = log.log_decode::<GuaranteeVersionUpdated>()?;
                info!("{:?}", ev);
            }
            _ => {
                info!("Unknown simple event: {}", event_name);
            }
        }
        Ok(())
    }

    #[measure(record_event_handler_time, name = "unknown")]
    async fn handle_unknown_event(&self, log: Log) -> Result<(), BlockchainListenerError> {
        info!("Unknown event: {:?}", log);
        Ok(())
    }
}

fn tx_hash_from_log(log: &Log) -> Result<String, BlockchainListenerError> {
    log.transaction_hash
        .map(|hash| format!("{hash:#x}"))
        .ok_or_else(|| {
            BlockchainListenerError::EventHandlerError("log missing tx_hash".to_string())
        })
}

impl CoreService {
    async fn sync_stablecoin_balance_from_chain(
        &self,
        user: Address,
        asset: Address,
    ) -> Result<(), BlockchainListenerError> {
        if asset == Address::ZERO {
            return Ok(());
        }

        if self.stablecoin_a_token(asset).await?.is_none() {
            return Ok(());
        }

        let contract = self.read_contract()?;
        let guarantee_capacity = contract
            .guaranteeCapacity(user, asset)
            .call()
            .await
            .map_err(|err| {
                BlockchainListenerError::EventHandlerError(format!(
                    "failed to load guarantee capacity for user {user} asset {asset}: {err}"
                ))
            })?;

        repo::sync_user_asset_total(
            &self.inner.persist_ctx,
            &user.to_string(),
            &asset.to_string(),
            guarantee_capacity,
        )
        .await?;

        Ok(())
    }

    fn read_contract(
        &self,
    ) -> Result<
        crate::ethereum::contract::contract_abi::Core4Mica::Core4MicaInstance<
            alloy::providers::DynProvider,
        >,
        BlockchainListenerError,
    > {
        use crate::ethereum::contract::contract_abi::Core4Mica;

        let contract_address = self
            .inner
            .config
            .ethereum_config
            .contract_address
            .parse::<Address>()
            .map_err(|err| {
                BlockchainListenerError::EventHandlerError(format!(
                    "failed to parse contract address {}: {err}",
                    self.inner.config.ethereum_config.contract_address
                ))
            })?;

        Ok(Core4Mica::new(
            contract_address,
            self.inner.read_provider.clone(),
        ))
    }

    async fn stablecoin_a_token(
        &self,
        asset: Address,
    ) -> Result<Option<Address>, BlockchainListenerError> {
        if asset == Address::ZERO {
            return Ok(None);
        }

        let contract = self.read_contract()?;
        let a_token = contract
            .stablecoinAToken(asset)
            .call()
            .await
            .map_err(|err| {
                BlockchainListenerError::EventHandlerError(format!(
                    "failed to load stablecoin aToken for asset {asset}: {err}"
                ))
            })?;

        if a_token == Address::ZERO {
            Ok(None)
        } else {
            Ok(Some(a_token))
        }
    }

    fn event_meta_from_log(&self, log: &Log) -> Result<EventMeta, BlockchainListenerError> {
        let chain_id = self.inner.config.ethereum_config.chain_id;
        let Some(block_hash) = log.block_hash else {
            return Err(BlockchainListenerError::EventHandlerError(
                "log missing block_hash".to_owned(),
            ));
        };
        let Some(tx_hash) = log.transaction_hash else {
            return Err(BlockchainListenerError::EventHandlerError(
                "log missing tx_hash".to_owned(),
            ));
        };
        let Some(log_index) = log.log_index else {
            return Err(BlockchainListenerError::EventHandlerError(
                "log missing log_index".to_owned(),
            ));
        };

        Ok(EventMeta {
            chain_id,
            block_hash: format!("{:#x}", block_hash),
            tx_hash: format!("{:#x}", tx_hash),
            log_index,
        })
    }
}
