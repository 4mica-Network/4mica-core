use core_service::service::CoreService;
use rpc::GUARANTEE_CLAIMS_VERSION;
use test_log::test;

mod common;
use common::chain::setup_e2e_environment;

#[test(tokio::test(flavor = "multi_thread", worker_threads = 2))]
#[serial_test::file_serial(db)]
async fn rejects_startup_when_a_supported_guarantee_version_is_disabled_on_chain()
-> anyhow::Result<()> {
    let env = setup_e2e_environment().await?;

    let (key, domain, decoder, _) = {
        let config = env
            .contract
            .getGuaranteeVersionConfig(GUARANTEE_CLAIMS_VERSION)
            .call()
            .await?;
        (
            config.verificationKey,
            config.domainSeparator,
            config.decoder,
            config.enabled,
        )
    };
    env.contract
        .configureGuaranteeVersion(GUARANTEE_CLAIMS_VERSION, key, domain, decoder, false)
        .send()
        .await?
        .get_receipt()
        .await?;

    let err = match CoreService::new(env.cfg.clone()).await {
        Ok(_) => panic!("startup should fail when a supported version is disabled on-chain"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains(&format!(
            "supported guarantee version {GUARANTEE_CLAIMS_VERSION} is disabled on-chain"
        )),
        "unexpected startup error: {err}"
    );

    Ok(())
}
