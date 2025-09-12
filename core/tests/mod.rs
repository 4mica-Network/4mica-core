pub fn init() -> anyhow::Result<core_service::config::AppConfig> {
    dotenv::dotenv().ok();
    Ok(core_service::config::AppConfig::fetch())
}

pub mod adversarial;
pub mod deposits;
pub mod guarantees;
pub mod remuneration;
pub mod transactions;
pub mod withdrawals;
