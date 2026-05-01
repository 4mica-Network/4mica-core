use std::str::FromStr;

use alloy::primitives::{Address, B256, U256, keccak256};
use anyhow::anyhow;
use chrono::{NaiveDateTime, Utc};
use entities::sea_orm_active_enums::{ParticipantCycleStatus, SettlementCycleStatus};
use log::{info, warn};

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

    pub async fn process_cycle_committed(
        &self,
        onchain_cycle_id: B256,
        tx_hash: &str,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("cycle commit event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let now = Utc::now().naive_utc();
        let changed = repo::mark_cycle_payment_window_open_by_id_on(
            self.inner.persist_ctx.db.as_ref(),
            &cycle_id,
            Some(tx_hash.to_string()),
            now,
        )
        .await?;
        repo::set_clearing_batch_commit_tx_on(
            self.inner.persist_ctx.db.as_ref(),
            &cycle_id,
            tx_hash.to_string(),
            now,
        )
        .await?;
        if changed {
            info!("mirrored ClearingHouse CycleCommitted for cycle {cycle_id}");
        }
        Ok(())
    }

    pub async fn process_paid_debtor(
        &self,
        onchain_cycle_id: B256,
        debtor: &str,
        tx_hash: &str,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("debtor payment event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let changed = repo::mark_participant_position_status_on(
            self.inner.persist_ctx.db.as_ref(),
            &cycle_id,
            debtor,
            ParticipantCycleStatus::Unpaid,
            ParticipantCycleStatus::Paid,
            Some(tx_hash.to_string()),
            Utc::now().naive_utc(),
        )
        .await?;
        if changed {
            info!("mirrored DebtorPaid: cycle={cycle_id}, debtor={debtor}, tx={tx_hash}");
        }
        Ok(())
    }

    pub async fn process_credit_claim(
        &self,
        onchain_cycle_id: B256,
        creditor: &str,
        tx_hash: &str,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("credit claim event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        let changed = repo::mark_participant_position_status_on(
            self.inner.persist_ctx.db.as_ref(),
            &cycle_id,
            creditor,
            ParticipantCycleStatus::Claimable,
            ParticipantCycleStatus::Claimed,
            Some(tx_hash.to_string()),
            Utc::now().naive_utc(),
        )
        .await?;
        if changed {
            info!("mirrored CreditorClaimed: cycle={cycle_id}, creditor={creditor}, tx={tx_hash}");
        }
        Ok(())
    }

    pub async fn process_defaulted_debtor(
        &self,
        onchain_cycle_id: B256,
        debtor: &str,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("debtor default event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        repo::mark_participant_position_status_on(
            self.inner.persist_ctx.db.as_ref(),
            &cycle_id,
            debtor,
            ParticipantCycleStatus::Unpaid,
            ParticipantCycleStatus::Defaulted,
            None,
            Utc::now().naive_utc(),
        )
        .await?;
        let changed = repo::mark_cycle_defaulted_on(
            self.inner.persist_ctx.db.as_ref(),
            &cycle_id,
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

    pub async fn process_default_covered(
        &self,
        onchain_cycle_id: B256,
        debtor: &str,
    ) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("default covered event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        info!("mirrored DefaultCovered: cycle={cycle_id}, debtor={debtor}");
        Ok(())
    }

    pub async fn process_cycle_finalized(&self, onchain_cycle_id: B256) -> ServiceResult<()> {
        let Some(cycle_id) = self.resolve_onchain_cycle_id(onchain_cycle_id).await? else {
            warn!("cycle finalized event for unknown on-chain cycle id {onchain_cycle_id:#x}");
            return Ok(());
        };
        self.finalize_cycle(&cycle_id).await
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

    async fn resolve_onchain_cycle_id(
        &self,
        onchain_cycle_id: B256,
    ) -> ServiceResult<Option<String>> {
        let cycles =
            repo::list_cycles_for_onchain_resolution_on(self.inner.persist_ctx.db.as_ref()).await?;
        Ok(cycles
            .into_iter()
            .find(|cycle| clearing_cycle_id(&cycle.id) == onchain_cycle_id)
            .map(|cycle| cycle.id))
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
