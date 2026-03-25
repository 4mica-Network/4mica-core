use alloy::primitives::{Address, B256, U256};
use rpc::{
    CorePublicParameters, GUARANTEE_CLAIMS_VERSION, PaymentGuaranteeRequestClaimsV1,
    PaymentGuaranteeRequestClaimsV2, PaymentGuaranteeValidationPolicyV2, SigningScheme,
    compute_validation_request_hash, compute_validation_subject_hash,
    version_requires_validation_registry,
};

#[derive(Debug, Clone)]
pub struct PaymentGuaranteeIntent {
    pub user_address: String,
    pub recipient_address: String,
    pub tab_id: U256,
    pub req_id: U256,
    pub amount: U256,
    pub asset_address: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct PaymentGuaranteeValidationInput {
    pub validation_registry_address: Option<Address>,
    pub validator_address: Address,
    pub validator_agent_id: U256,
    pub min_validation_score: u8,
    pub required_validation_tag: String,
}

#[derive(Debug, Clone)]
pub enum PreparedPaymentGuaranteeClaims {
    V1(PaymentGuaranteeRequestClaimsV1),
    V2(PaymentGuaranteeRequestClaimsV2),
}

impl PreparedPaymentGuaranteeClaims {
    pub fn version(&self) -> u64 {
        match self {
            Self::V1(_) => GUARANTEE_CLAIMS_VERSION,
            Self::V2(_) => 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreparedPaymentGuaranteeRequest {
    pub claims: PreparedPaymentGuaranteeClaims,
    pub signature: String,
    pub scheme: SigningScheme,
}

pub fn prepare_payment_guarantee_claims(
    public_params: &CorePublicParameters,
    intent: PaymentGuaranteeIntent,
    validation: Option<PaymentGuaranteeValidationInput>,
) -> anyhow::Result<PreparedPaymentGuaranteeClaims> {
    let accepted_versions = public_params.accepted_guarantee_versions_or_default();
    let accepts_v1 = accepted_versions.contains(&GUARANTEE_CLAIMS_VERSION);
    let accepts_validation_gated = accepted_versions
        .iter()
        .any(|&v| version_requires_validation_registry(v));

    match validation {
        Some(validation) => {
            if !accepts_validation_gated {
                anyhow::bail!(
                    "validation input was provided, but no validation-gated guarantee version is accepted by core"
                );
            }
            Ok(PreparedPaymentGuaranteeClaims::V2(build_v2_claims(
                public_params,
                intent,
                validation,
            )?))
        }
        None => {
            if accepts_v1 {
                Ok(PreparedPaymentGuaranteeClaims::V1(build_v1_claims(intent)))
            } else if accepts_validation_gated {
                anyhow::bail!(
                    "core requires validation-gated guarantees, but validation input is missing"
                )
            } else {
                anyhow::bail!("core does not advertise any accepted guarantee versions")
            }
        }
    }
}

fn build_v1_claims(intent: PaymentGuaranteeIntent) -> PaymentGuaranteeRequestClaimsV1 {
    PaymentGuaranteeRequestClaimsV1 {
        user_address: intent.user_address,
        recipient_address: intent.recipient_address,
        tab_id: intent.tab_id,
        req_id: intent.req_id,
        amount: intent.amount,
        asset_address: intent.asset_address,
        timestamp: intent.timestamp,
    }
}

fn build_v2_claims(
    public_params: &CorePublicParameters,
    intent: PaymentGuaranteeIntent,
    validation: PaymentGuaranteeValidationInput,
) -> anyhow::Result<PaymentGuaranteeRequestClaimsV2> {
    let validation_registry_address = match validation.validation_registry_address {
        Some(address) => address,
        None => public_params
            .trusted_validation_registries
            .first()
            .ok_or_else(|| {
                anyhow::anyhow!("core does not expose any trusted validation registries")
            })?
            .parse::<Address>()?,
    };

    let validation_subject_hash = compute_validation_subject_hash(
        &intent.user_address,
        &intent.recipient_address,
        intent.tab_id,
        intent.req_id,
        intent.amount,
        &intent.asset_address,
        intent.timestamp,
    )?;

    let mut validation_policy = PaymentGuaranteeValidationPolicyV2 {
        validation_registry_address,
        validation_request_hash: B256::ZERO,
        validation_chain_id: public_params.chain_id,
        validator_address: validation.validator_address,
        validator_agent_id: validation.validator_agent_id,
        min_validation_score: validation.min_validation_score,
        validation_subject_hash: B256::from(validation_subject_hash),
        required_validation_tag: validation.required_validation_tag,
    };
    validation_policy.validation_request_hash =
        B256::from(compute_validation_request_hash(&validation_policy)?);

    PaymentGuaranteeRequestClaimsV2::builder(
        intent.user_address,
        intent.recipient_address,
        intent.tab_id,
        intent.req_id,
        intent.amount,
        intent.timestamp,
    )
    .asset_address(intent.asset_address)
    .validation_policy(validation_policy)
    .build()
}

#[cfg(test)]
mod tests {
    use super::{
        PaymentGuaranteeIntent, PaymentGuaranteeValidationInput, PreparedPaymentGuaranteeClaims,
        prepare_payment_guarantee_claims,
    };
    use alloy::primitives::{Address, U256};
    use rpc::CorePublicParameters;

    fn params(max: u64, accepted: Vec<u64>) -> CorePublicParameters {
        CorePublicParameters {
            public_key: vec![],
            contract_address: "0x0000000000000000000000000000000000000000".to_string(),
            ethereum_http_rpc_url: "http://localhost:8545".to_string(),
            eip712_name: "4mica".to_string(),
            eip712_version: "1".to_string(),
            chain_id: 1,
            max_accepted_guarantee_version: max,
            accepted_guarantee_versions: accepted,
            active_guarantee_domain_separator:
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            trusted_validation_registries: vec![
                "0x1111111111111111111111111111111111111111".to_string(),
            ],
            validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V1".to_string(),
        }
    }

    fn intent() -> PaymentGuaranteeIntent {
        PaymentGuaranteeIntent {
            user_address: Address::repeat_byte(0x11).to_string(),
            recipient_address: Address::repeat_byte(0x22).to_string(),
            tab_id: U256::from(1u64),
            req_id: U256::ZERO,
            amount: U256::from(3u64),
            asset_address: Address::ZERO.to_string(),
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn auto_selects_v1_when_validation_input_is_missing() {
        let claims = prepare_payment_guarantee_claims(&params(2, vec![1, 2]), intent(), None)
            .expect("claims");
        assert!(matches!(claims, PreparedPaymentGuaranteeClaims::V1(_)));
    }

    #[test]
    fn auto_selects_v2_when_validation_input_is_present() {
        let claims = prepare_payment_guarantee_claims(
            &params(2, vec![1, 2]),
            intent(),
            Some(PaymentGuaranteeValidationInput {
                validation_registry_address: None,
                validator_address: Address::repeat_byte(0x33),
                validator_agent_id: U256::from(7u64),
                min_validation_score: 80,
                required_validation_tag: "hard-finality".to_string(),
            }),
        )
        .expect("claims");
        assert!(matches!(claims, PreparedPaymentGuaranteeClaims::V2(_)));
    }

    #[test]
    fn auto_rejects_missing_validation_input_when_only_v2_is_accepted() {
        let err = prepare_payment_guarantee_claims(&params(2, vec![2]), intent(), None)
            .expect_err("missing validation input must fail");
        assert!(err.to_string().contains("validation-gated"));
    }
}
