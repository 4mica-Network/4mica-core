//! Composition root. Builds the shared context and every service in dependency order, then hands
//! them out through accessors. It holds no domain logic — callers reach past it to the service
//! that owns the operation.

use std::collections::HashMap;
use std::sync::Arc;

use alloy::providers::DynProvider;
use anyhow::Context;
use validators::ValidatorRegistry;

use crate::config::AppConfig;
use crate::ethereum::{ChainDeployment, ChainService, CoreContractApi, CoreContractProxy};
use crate::persist::PersistCtx;
use crate::service::ctx::{self, Ctx};
use crate::service::domain::auth::AuthService;
use crate::service::domain::clearing::ClearingService;
use crate::service::domain::guarantee::GuaranteeService;
use crate::service::domain::health::HealthService;
use crate::service::domain::netting::NettingService;
use crate::service::domain::query::QueryService;
use crate::service::domain::system::SystemService;
use crate::service::domain::validation::ValidationService;
use crate::service::shared::clearing_proofs::ClearingProofOps;
use crate::service::shared::cycle::CycleOps;

/// Everything a caller can reach, wired once and shared.
struct Services {
    auth: Arc<AuthService>,
    clearing: Arc<ClearingService>,
    guarantees: Arc<GuaranteeService>,
    health: Arc<HealthService>,
    netting: Arc<NettingService>,
    query: Arc<QueryService>,
    system: Arc<SystemService>,
    validation: Arc<ValidationService>,
}

#[derive(Clone)]
pub struct CoreService {
    ctx: Arc<Ctx>,
    services: Arc<Services>,
}

pub struct CoreServiceDeps {
    pub persist_ctx: PersistCtx,
    pub contract_api: Arc<dyn CoreContractApi>,
    pub chain_id: u64,
    pub read_provider: DynProvider,
    pub guarantee_domains: HashMap<u64, [u8; 32]>,
    pub validators: ValidatorRegistry,
    pub withdrawal_grace_period: u64,
    pub core_domain_separator: Option<[u8; 32]>,
}

impl CoreService {
    pub async fn new(config: AppConfig) -> anyhow::Result<Self> {
        let persist_ctx = PersistCtx::new().await?;
        config.guarantee.validate()?;

        let contract_api: Arc<dyn CoreContractApi> =
            Arc::new(CoreContractProxy::new(&config).await?);
        let deployment =
            ChainDeployment::load(contract_api.as_ref(), config.ethereum_config.chain_id).await?;

        // Fail fast if the settlement-cycle timeline does not leave the operator
        // enough margin to seize a defaulter's collateral before it can be withdrawn.
        config
            .settlement_cycle
            .validate_against_withdrawal_grace_period(deployment.withdrawal_grace_period)
            .context(
                "settlement cycle timing is incompatible with on-chain withdrawalGracePeriod",
            )?;

        let read_provider = ChainService::build_ws_provider(config.ethereum_config.clone()).await?;
        let validators =
            ValidatorRegistry::build(&config.guarantee.validators()?, Some(read_provider.clone()))
                .await?;

        Self::new_with_dependencies(
            config,
            CoreServiceDeps {
                persist_ctx,
                contract_api,
                chain_id: deployment.chain_id,
                read_provider,
                guarantee_domains: deployment.guarantee_domains,
                validators,
                withdrawal_grace_period: deployment.withdrawal_grace_period,
                core_domain_separator: deployment.core_domain_separator,
            },
        )
    }

    pub fn new_with_dependencies(config: AppConfig, deps: CoreServiceDeps) -> anyhow::Result<Self> {
        config.guarantee.validate()?;

        let public_params = ctx::public_parameters(
            &config,
            deps.chain_id,
            &deps.guarantee_domains,
            deps.core_domain_separator,
            &deps.validators,
        )?;
        let chain = Arc::new(ChainService::new(
            deps.contract_api,
            deps.read_provider,
            &config.ethereum_config,
        ));
        let ctx = Arc::new(Ctx::new(
            config,
            public_params,
            deps.persist_ctx,
            chain,
            deps.validators,
            deps.guarantee_domains,
            deps.withdrawal_grace_period,
        ));

        Ok(Self::from_ctx(ctx))
    }

    /// Wire every service from the shared context, in dependency order.
    fn from_ctx(ctx: Arc<Ctx>) -> Self {
        // Layer 3: shared primitives, depending only on the context.
        let cycle_ops = Arc::new(CycleOps::new(ctx.clone()));
        let proof_ops = Arc::new(ClearingProofOps::new(ctx.clone()));

        // Layer 2: domain services, which never depend on each other.
        let services = Services {
            auth: Arc::new(AuthService::new(ctx.clone())),
            clearing: Arc::new(ClearingService::new(
                ctx.clone(),
                cycle_ops.clone(),
                proof_ops.clone(),
            )),
            guarantees: Arc::new(GuaranteeService::new(ctx.clone(), cycle_ops.clone())),
            health: Arc::new(HealthService::new(ctx.clone())),
            netting: Arc::new(NettingService::new(ctx.clone(), cycle_ops, proof_ops)),
            query: Arc::new(QueryService::new(ctx.clone())),
            system: Arc::new(SystemService::new(ctx.clone())),
            validation: Arc::new(ValidationService::new(ctx.clone())),
        };

        Self {
            ctx,
            services: Arc::new(services),
        }
    }

    // --- accessors ---------------------------------------------------------------------------

    pub fn ctx(&self) -> &Arc<Ctx> {
        &self.ctx
    }

    pub fn auth(&self) -> &Arc<AuthService> {
        &self.services.auth
    }

    pub fn clearing(&self) -> &Arc<ClearingService> {
        &self.services.clearing
    }

    pub fn guarantees(&self) -> &Arc<GuaranteeService> {
        &self.services.guarantees
    }

    pub fn health(&self) -> &Arc<HealthService> {
        &self.services.health
    }

    pub fn netting(&self) -> &Arc<NettingService> {
        &self.services.netting
    }

    pub fn query(&self) -> &Arc<QueryService> {
        &self.services.query
    }

    pub fn system(&self) -> &Arc<SystemService> {
        &self.services.system
    }

    pub fn validation(&self) -> &Arc<ValidationService> {
        &self.services.validation
    }

    pub fn persist_ctx(&self) -> &PersistCtx {
        &self.ctx.persist
    }

    pub fn chain(&self) -> &Arc<ChainService> {
        &self.ctx.chain
    }

    pub fn read_provider(&self) -> &DynProvider {
        self.ctx.chain.provider()
    }
}
