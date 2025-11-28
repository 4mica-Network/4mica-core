use crate::service::CoreService;
use crate::{
    auth::verify_guarantee_request_signature,
    error::{ServiceError, ServiceResult},
    persist::repo,
    util::u256_to_string,
};
use alloy::primitives::U256;
use anyhow::anyhow;
use chrono::TimeZone;
use crypto::bls::BLSCert;
use entities::sea_orm_active_enums::TabStatus;
use log::info;
use rpc::{
    PaymentGuaranteeClaims, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims,
    PaymentGuaranteeRequestClaimsV1, PaymentGuaranteeRequestEssentials,
};
use std::str::FromStr;

impl CoreService {
    async fn verify_guarantee_request_claims_v1(
        &self,
        claims: &PaymentGuaranteeRequestClaimsV1,
    ) -> ServiceResult<U256> {
        let last_opt = repo::get_last_guarantee_for_tab(&self.inner.persist_ctx, claims.tab_id)
            .await
            .map_err(ServiceError::from)?;

        let next_req_id = match last_opt {
            Some(ref last) => {
                let prev_req_id = U256::from_str(&last.req_id).map_err(|e| {
                    ServiceError::InvalidParams(format!("Invalid prev_req_id: {}", e))
                })?;

                prev_req_id
                    .checked_add(U256::from(1u8))
                    .ok_or(ServiceError::InvalidRequestID)?
            }
            None => {
                info!(
                    "No previous guarantee found for tab_id={}. This must be the first request.",
                    claims.tab_id,
                );
                U256::ZERO
            }
        };

        let now_i64 = chrono::Utc::now().timestamp();
        if now_i64 < 0 {
            return Err(ServiceError::Other(anyhow!("System time before epoch")));
        }
        let now_secs = now_i64 as u64;

        if now_secs < claims.timestamp {
            return Err(ServiceError::FutureTimestamp);
        }

        let Some(tab) = repo::get_tab_by_id(&self.inner.persist_ctx, claims.tab_id).await? else {
            return Err(ServiceError::NotFound(u256_to_string(claims.tab_id)));
        };

        if (tab.status == TabStatus::Pending) != (next_req_id == U256::ZERO) {
            return Err(ServiceError::InvalidRequestID);
        }

        if tab.asset_address != claims.asset_address {
            return Err(ServiceError::InvalidParams("Invalid asset address".into()));
        }

        if tab.ttl <= 0 {
            return Err(ServiceError::InvalidParams("Invalid tab TTL".into()));
        }

        let tab_start_ts_i64 = tab.start_ts.and_utc().timestamp();
        if tab_start_ts_i64 < 0 {
            return Err(ServiceError::Other(anyhow!("Negative tab start_ts")));
        }

        if tab.status == TabStatus::Pending {
            let start_ts = chrono::Utc
                .timestamp_opt(claims.timestamp as i64, 0)
                .single()
                .ok_or_else(|| ServiceError::InvalidParams("Invalid timestamp".into()))?
                .naive_utc();
            repo::open_tab(&self.inner.persist_ctx, claims.tab_id, start_ts).await?;
        }

        let tab_start_ts = tab_start_ts_i64 as u64;
        let tab_expiry = tab_start_ts.saturating_add(tab.ttl as u64);

        // Always validate the claimed timestamp against the stored tab window.
        if claims.timestamp < tab_start_ts || claims.timestamp > tab_expiry {
            return Err(ServiceError::ModifiedStartTs);
        }

        if tab_expiry < now_secs {
            return Err(ServiceError::TabClosed);
        }

        Ok(next_req_id)
    }

    async fn create_bls_cert(&self, claims: PaymentGuaranteeClaims) -> ServiceResult<BLSCert> {
        BLSCert::new(&self.bls_private_key(), claims)
            .map_err(|err| ServiceError::Other(anyhow!(err)))
    }

    pub async fn issue_payment_guarantee(
        &self,
        req: PaymentGuaranteeRequest,
    ) -> ServiceResult<BLSCert> {
        let tab_id = req.claims.tab_id();
        let amount = req.claims.amount();

        info!(
            "Received guarantee request v1; tab_id={}, amount={}",
            tab_id, amount
        );

        verify_guarantee_request_signature(&self.inner.public_params, &req)?;

        repo::ensure_user_is_active(&self.inner.persist_ctx, req.claims.user_address()).await?;

        let req_id = match &req.claims {
            PaymentGuaranteeRequestClaims::V1(claims) => {
                self.verify_guarantee_request_claims_v1(claims).await?
            }
        };

        let total_amount = {
            let tab_guarantees =
                repo::get_guarantees_for_tab(&self.inner.persist_ctx, tab_id).await?;
            let total_until_now: U256 = tab_guarantees
                .into_iter()
                .map(|g| U256::from_str(&g.value))
                .collect::<Result<Vec<U256>, _>>()
                .map_err(|e| ServiceError::Other(anyhow!(e)))?
                .iter()
                .sum();

            total_until_now
                .checked_add(amount)
                .ok_or_else(|| ServiceError::Other(anyhow!("Total amount overflow")))?
        };

        let guarantee_claims = PaymentGuaranteeClaims::from_request(
            &req.claims,
            self.inner.guarantee_domain,
            req_id,
            total_amount,
        );
        let cert: BLSCert = self.create_bls_cert(guarantee_claims.clone()).await?;

        repo::lock_and_store_guarantee(&self.inner.persist_ctx, &guarantee_claims, &cert)
            .await
            .map_err(ServiceError::from)?;
        Ok(cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::ethereum::CoreContractApi;
    use crate::persist::repo::users::ensure_user_exists_on;
    use crate::persist::{PersistCtx, repo};
    use crate::util::u256_to_string;
    use alloy::providers::{DynProvider, Provider, ProviderBuilder};
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use entities::sea_orm_active_enums::{SettlementStatus, TabStatus};
    use rand::random;
    use rpc::PaymentGuaranteeRequestClaimsV1;
    use sea_orm::{ActiveValue::Set, EntityTrait};
    use std::panic;
    use std::sync::{Arc, Once};

    fn load_env() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            dotenv::dotenv().ok();
            dotenv::from_filename("../.env").ok();
        });
    }

    struct MockContractApi {
        chain_id: u64,
        domain: [u8; 32],
    }

    #[async_trait]
    impl CoreContractApi for MockContractApi {
        async fn get_chain_id(&self) -> Result<u64, crate::error::CoreContractApiError> {
            Ok(self.chain_id)
        }

        async fn get_guarantee_domain_separator(
            &self,
        ) -> Result<[u8; 32], crate::error::CoreContractApiError> {
            Ok(self.domain)
        }

        async fn record_payment(
            &self,
            _tab_id: U256,
            _asset: alloy::primitives::Address,
            _amount: U256,
        ) -> Result<(), crate::error::CoreContractApiError> {
            Ok(())
        }
    }

    fn build_read_provider() -> anyhow::Result<DynProvider> {
        let provider_res = panic::catch_unwind(|| {
            ProviderBuilder::new()
                .connect_anvil_with_wallet_and_config(|anvil| anvil.port(40105u16))
        });

        let provider = match provider_res {
            Ok(Ok(p)) => p,
            Ok(Err(err)) => return Err(anyhow::Error::from(err)),
            Err(_) => return Err(anyhow::anyhow!("failed to start anvil provider (panic)")),
        };

        Ok(provider.erased())
    }

    async fn build_core_service(persist_ctx: PersistCtx) -> anyhow::Result<CoreService> {
        dotenv::dotenv().ok();
        let config = AppConfig::fetch()?;
        let read_provider = build_read_provider()?;
        let chain_id = read_provider.get_chain_id().await?;

        let contract_api: Arc<dyn CoreContractApi> = Arc::new(MockContractApi {
            chain_id,
            domain: [0u8; 32],
        });

        let core_service = CoreService::new_with_dependencies(
            config,
            persist_ctx,
            contract_api,
            chain_id,
            read_provider,
            [0u8; 32],
        )?;
        Ok(core_service)
    }

    async fn seed_user(ctx: &PersistCtx, addr: &str) {
        ensure_user_exists_on(ctx.db.as_ref(), addr)
            .await
            .expect("seed user");
    }

    async fn insert_pending_tab(
        ctx: &PersistCtx,
        tab_id: U256,
        user_address: String,
        recipient_address: String,
        start_ts: chrono::NaiveDateTime,
        ttl: i64,
    ) {
        let now = Utc::now().naive_utc();
        let tab = entities::tabs::ActiveModel {
            id: Set(u256_to_string(tab_id)),
            user_address: Set(user_address),
            server_address: Set(recipient_address),
            asset_address: Set(crate::config::DEFAULT_ASSET_ADDRESS.to_string()),
            start_ts: Set(start_ts),
            ttl: Set(ttl),
            status: Set(TabStatus::Pending),
            settlement_status: Set(SettlementStatus::Pending),
            created_at: Set(now),
            updated_at: Set(now),
        };

        entities::tabs::Entity::insert(tab)
            .exec(ctx.db.as_ref())
            .await
            .expect("insert tab");
    }

    fn build_claims(
        tab_id: U256,
        user_address: String,
        recipient_address: String,
        timestamp: u64,
    ) -> PaymentGuaranteeRequestClaimsV1 {
        PaymentGuaranteeRequestClaimsV1 {
            tab_id,
            user_address,
            recipient_address,
            asset_address: crate::config::DEFAULT_ASSET_ADDRESS.to_string(),
            amount: U256::from(1u64),
            timestamp,
        }
    }

    #[tokio::test]
    async fn accepts_timestamp_within_tab_window() {
        load_env();
        let ctx = match PersistCtx::new().await {
            Ok(ctx) => ctx,
            Err(err) => {
                eprintln!("skipping accepts_timestamp_within_tab_window: {err}");
                return;
            }
        };
        let core_service = match build_core_service(ctx.clone()).await {
            Ok(cs) => cs,
            Err(err) => {
                eprintln!("skipping accepts_timestamp_within_tab_window: {err}");
                return;
            }
        };

        let user_addr = format!("0x{:040x}", rand::random::<u128>());
        let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
        seed_user(&ctx, &user_addr).await;
        seed_user(&ctx, &recipient_addr).await;

        let tab_id = U256::from(random::<u64>());
        let start_ts = (Utc::now() - Duration::seconds(300)).naive_utc();
        let ttl = 600i64;
        insert_pending_tab(
            &ctx,
            tab_id,
            user_addr.clone(),
            recipient_addr.clone(),
            start_ts,
            ttl,
        )
        .await;

        let claims_ts = (start_ts + Duration::seconds(120)).and_utc().timestamp() as u64;
        let claims = build_claims(tab_id, user_addr, recipient_addr, claims_ts);

        let req_id = core_service
            .verify_guarantee_request_claims_v1(&claims)
            .await
            .expect("claims should be valid");
        assert_eq!(req_id, U256::ZERO);

        let tab = repo::get_tab_by_id(&ctx, tab_id)
            .await
            .expect("tab fetch")
            .expect("tab exists");
        assert_eq!(tab.status, TabStatus::Open);
        assert_eq!(tab.start_ts.and_utc().timestamp(), claims_ts as i64);
    }

    #[tokio::test]
    async fn rejects_timestamp_outside_tab_window() {
        load_env();
        let ctx = match PersistCtx::new().await {
            Ok(ctx) => ctx,
            Err(err) => {
                eprintln!("skipping rejects_timestamp_outside_tab_window: {err}");
                return;
            }
        };
        let core_service = match build_core_service(ctx.clone()).await {
            Ok(cs) => cs,
            Err(err) => {
                eprintln!("skipping rejects_timestamp_outside_tab_window: {err}");
                return;
            }
        };

        let user_addr = format!("0x{:040x}", rand::random::<u128>());
        let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
        seed_user(&ctx, &user_addr).await;
        seed_user(&ctx, &recipient_addr).await;

        let tab_id = U256::from(random::<u64>());
        let start_ts = (Utc::now() - Duration::seconds(600)).naive_utc();
        let ttl = 300i64;
        insert_pending_tab(
            &ctx,
            tab_id,
            user_addr.clone(),
            recipient_addr.clone(),
            start_ts,
            ttl,
        )
        .await;

        let before_start = (start_ts - Duration::seconds(1)).and_utc().timestamp() as u64;
        let claims = build_claims(
            tab_id,
            user_addr.clone(),
            recipient_addr.clone(),
            before_start,
        );
        let err = core_service
            .verify_guarantee_request_claims_v1(&claims)
            .await
            .expect_err("timestamp before start should fail");
        assert!(matches!(err, ServiceError::ModifiedStartTs));

        let after_expiry = (start_ts + Duration::seconds(ttl + 1))
            .and_utc()
            .timestamp() as u64;
        let claims = build_claims(tab_id, user_addr, recipient_addr, after_expiry);
        let err = core_service
            .verify_guarantee_request_claims_v1(&claims)
            .await
            .expect_err("timestamp after expiry should fail");
        assert!(matches!(err, ServiceError::ModifiedStartTs));

        let tab = repo::get_tab_by_id(&ctx, tab_id)
            .await
            .expect("tab fetch")
            .expect("tab exists");
        assert_eq!(tab.status, TabStatus::Pending);
        assert_eq!(
            tab.start_ts.and_utc().timestamp(),
            start_ts.and_utc().timestamp()
        );
    }
}
