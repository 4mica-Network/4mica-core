use std::{
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use core_service::{
    config::{AppConfig, Eip712Config, EthereumConfig, Secrets, ServerConfig},
    error::BlockchainWriterError,
    ethereum::PaymentWriter,
    persist::PersistCtx,
    service::{CoreService, test_hooks},
};
use crypto::hex::HexBytes;
use sea_orm::Database;
use tokio::time::sleep;

#[derive(Default)]
struct MockPaymentWriter;

#[async_trait]
impl PaymentWriter for MockPaymentWriter {
    async fn record_payment(
        &self,
        _tab_id: alloy::primitives::U256,
        _amount: alloy::primitives::U256,
    ) -> Result<(), BlockchainWriterError> {
        Ok(())
    }
}

struct HookGuard;

impl Drop for HookGuard {
    fn drop(&mut self) {
        test_hooks::clear_scan_callback();
        test_hooks::clear_scheduler_callback();
    }
}

fn build_config(cron_expr: &str, lookback: u64) -> AppConfig {
    AppConfig {
        server_config: ServerConfig {
            host: "127.0.0.1".into(),
            port: "3000".into(),
            log_level: log::Level::Info,
        },
        ethereum_config: EthereumConfig {
            chain_id: 1,
            ws_rpc_url: "ws://localhost:8545".into(),
            http_rpc_url: "http://localhost:8545".into(),
            contract_address: "0x0000000000000000000000000000000000000001".into(),
            cron_job_settings: cron_expr.into(),
            number_of_blocks_to_confirm: lookback,
            number_of_pending_blocks: 1,
            ethereum_private_key:
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        },
        secrets: Secrets {
            bls_private_key: HexBytes::from_str(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            )
            .expect("valid hex"),
        },
        eip712: Eip712Config {
            name: "4mica".into(),
            version: "1".into(),
        },
    }
}

#[tokio::test]
async fn monitor_transactions_triggers_scheduler_and_scan() -> anyhow::Result<()> {
    let cron_expr = "*/1 * * * * *";
    let lookback = 5u64;

    let config = build_config(cron_expr, lookback);
    let conn = Database::connect("sqlite::memory:").await?;
    let persist_ctx = PersistCtx::from_conn(conn);
    let payment_writer: Arc<dyn PaymentWriter> = Arc::new(MockPaymentWriter::default());

    let service = Arc::new(CoreService::new_with_dependencies(
        config,
        persist_ctx,
        payment_writer,
    )?);

    test_hooks::clear_scheduler_callback();
    test_hooks::clear_scan_callback();
    let _hook_guard = HookGuard;

    let scheduler_calls: Arc<Mutex<Vec<(String, u64)>>> =
        Arc::new(Mutex::new(Vec::with_capacity(1)));
    let scan_count = Arc::new(AtomicUsize::new(0));

    test_hooks::set_scheduler_callback({
        let scheduler_calls = Arc::clone(&scheduler_calls);
        Arc::new(move |cron, lb| {
            scheduler_calls
                .lock()
                .expect("scheduler_calls poisoned")
                .push((cron.to_string(), lb));
        })
    });

    test_hooks::set_scan_callback({
        let scan_count = Arc::clone(&scan_count);
        Arc::new(move |lb| {
            assert_eq!(lb, lookback);
            scan_count.fetch_add(1, Ordering::SeqCst);
            true
        })
    });

    service.monitor_transactions();

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !scheduler_calls
                .lock()
                .expect("scheduler_calls poisoned")
                .is_empty()
            {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("scheduler callback not invoked in time");

    let (recorded_cron, recorded_lookback) = scheduler_calls
        .lock()
        .expect("scheduler_calls poisoned")
        .first()
        .cloned()
        .expect("scheduler callback missing");

    assert_eq!(recorded_cron, cron_expr);
    assert_eq!(recorded_lookback, lookback);

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if scan_count.load(Ordering::SeqCst) > 0 {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("scan callback not invoked in time");

    Ok(())
}
