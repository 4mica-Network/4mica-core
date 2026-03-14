use core_service::service::CoreService;
use test_log::test;

mod common;
use common::setup::setup_e2e_environment;

#[test(tokio::test(flavor = "multi_thread", worker_threads = 2))]
#[serial_test::serial]
async fn rejects_startup_when_max_accepted_guarantee_version_is_disabled_on_chain()
-> anyhow::Result<()> {
    let mut env = setup_e2e_environment().await?;
    env.cfg.guarantee.max_accepted_version = 2;
    env.cfg.guarantee.accepted_request_versions = "2".to_string();
    env.cfg.guarantee.trusted_validation_registries =
        "0x1111111111111111111111111111111111111111".to_string();

    let err = match CoreService::new(env.cfg.clone()).await {
        Ok(_) => panic!("startup should fail when configured active version is disabled on-chain"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("accepted guarantee version 2 is disabled on-chain"),
        "unexpected startup error: {err}"
    );

    Ok(())
}
