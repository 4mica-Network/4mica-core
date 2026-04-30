use std::str::FromStr;

use alloy::primitives::{Address, B256, U256, keccak256};
use anyhow::anyhow;
use chrono::{NaiveDateTime, Utc};
use entities::sea_orm_active_enums::SettlementCycleStatus;
use log::info;

use crate::{
    error::{ServiceError, ServiceResult},
    ethereum::ClearingCommitInput,
    persist::repo,
    service::CoreService,
};

impl CoreService {
    pub async fn commit_cycle_to_chain(&self, cycle_id: &str) -> ServiceResult<()> {
        let cycle = repo::get_cycle_by_id(&self.inner.persist_ctx, cycle_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Settlement cycle {cycle_id}")))?;
        if cycle.status != SettlementCycleStatus::NettingComputed {
            return Err(ServiceError::InvalidParams(format!(
                "settlement cycle {cycle_id} is {:?}, expected {:?}",
                cycle.status,
                SettlementCycleStatus::NettingComputed
            )));
        }

        let batch =
            repo::get_clearing_batch_by_cycle_on(self.inner.persist_ctx.db.as_ref(), cycle_id)
                .await?
                .ok_or_else(|| {
                    ServiceError::InvalidParams(format!(
                        "settlement cycle {cycle_id} has no clearing batch"
                    ))
                })?;
        let _clearing_house_address = parse_address(
            "ETHEREUM_CLEARING_HOUSE_ADDRESS",
            &self.inner.config.ethereum_config.clearing_house_address,
        )
        .and_then(|address| {
            if address == Address::ZERO {
                Err(ServiceError::InvalidParams(
                    "ETHEREUM_CLEARING_HOUSE_ADDRESS must be configured before committing clearing batches"
                        .to_string(),
                ))
            } else {
                Ok(address)
            }
        })?;

        let input = ClearingCommitInput {
            cycle_id: clearing_cycle_id(&cycle.id),
            asset: parse_address("cycle asset", &batch.asset_address)?,
            merkle_root: parse_bytes32("clearing batch Merkle root", &batch.merkle_root)?,
            total_net_debit: parse_amount(
                "clearing batch total net debit",
                &batch.total_net_debit,
            )?,
            total_net_credit: parse_amount(
                "clearing batch total net credit",
                &batch.total_net_credit,
            )?,
            payment_submission_deadline: timestamp_u64(
                "payment submission deadline",
                cycle.payment_submission_deadline,
            )?,
            payment_finality_deadline: timestamp_u64(
                "payment finality deadline",
                cycle.payment_finality_deadline,
            )?,
        };

        let commit = self
            .inner
            .contract_api
            .commit_clearing_cycle(input)
            .await
            .map_err(|err| ServiceError::Other(anyhow!(err)))?;
        let tx_hash = commit.tx_hash.to_string();
        let now = Utc::now().naive_utc();
        let changed = repo::mark_cycle_payment_window_open_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            Some(tx_hash.clone()),
            now,
        )
        .await?;
        repo::set_clearing_batch_commit_tx_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            tx_hash.clone(),
            now,
        )
        .await?;
        if changed {
            info!(
                "committed settlement cycle {} to ClearingHouse in tx {}",
                cycle_id, tx_hash
            );
        }
        Ok(())
    }

    pub async fn process_paid_debtor(
        &self,
        cycle_id: &str,
        debtor: &str,
        tx_hash: &str,
    ) -> ServiceResult<()> {
        info!(
            "payment event bridge received: cycle={}, debtor={}, tx={}",
            cycle_id, debtor, tx_hash
        );
        Ok(())
    }

    pub async fn process_credit_claim(
        &self,
        cycle_id: &str,
        creditor: &str,
        tx_hash: &str,
    ) -> ServiceResult<()> {
        info!(
            "claim event bridge received: cycle={}, creditor={}, tx={}",
            cycle_id, creditor, tx_hash
        );
        Ok(())
    }

    pub async fn process_defaulted_debtor(
        &self,
        cycle_id: &str,
        debtor: &str,
    ) -> ServiceResult<()> {
        let changed = repo::mark_cycle_defaulted_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            Utc::now().naive_utc(),
        )
        .await?;
        if changed {
            info!(
                "default event bridge received: cycle={}, debtor={}",
                cycle_id, debtor
            );
        }
        Ok(())
    }

    pub async fn finalize_cycle(&self, cycle_id: &str) -> ServiceResult<()> {
        let changed = repo::mark_cycle_finalized_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            Utc::now().naive_utc(),
        )
        .await?;
        if changed {
            info!("finalized settlement cycle {}", cycle_id);
        }
        Ok(())
    }
}

fn clearing_cycle_id(cycle_id: &str) -> B256 {
    keccak256(cycle_id.as_bytes())
}

fn parse_address(label: &str, raw: &str) -> ServiceResult<Address> {
    Address::from_str(raw.trim()).map_err(|err| {
        ServiceError::InvalidParams(format!("invalid {label} address '{raw}': {err}"))
    })
}

fn parse_bytes32(label: &str, raw: &str) -> ServiceResult<B256> {
    B256::from_str(raw.trim())
        .map_err(|err| ServiceError::InvalidParams(format!("invalid {label} '{raw}': {err}")))
}

fn parse_amount(label: &str, raw: &str) -> ServiceResult<U256> {
    U256::from_str(raw.trim())
        .map_err(|err| ServiceError::InvalidParams(format!("invalid {label} '{raw}': {err}")))
}

fn timestamp_u64(label: &str, value: NaiveDateTime) -> ServiceResult<u64> {
    let timestamp = value.and_utc().timestamp();
    u64::try_from(timestamp)
        .map_err(|_| ServiceError::InvalidParams(format!("{label} is before unix epoch")))
}
