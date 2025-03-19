use crate::persist::prisma::PrismaClient;
use rpc::common::UserTransactionInfo;
use std::sync::Arc;

#[allow(warnings, unused)]
pub mod prisma;
pub mod repo;

#[derive(Clone)]
pub struct PersistCtx {
    pub client: Arc<PrismaClient>,
}

impl PersistCtx {
    pub async fn new() -> anyhow::Result<Self> {
        let client = PrismaClient::_builder().build().await?;
        Ok(Self {
            client: Arc::new(client),
        })
    }
}

impl Into<UserTransactionInfo> for prisma::user_transaction::Data {
    fn into(self) -> UserTransactionInfo {
        UserTransactionInfo {
            user_addr: self.user_address,
            tx_hash: self.tx_id,
            amount: self.amount,
            verified: self.verified,
            finalized: self.finalized,
            failed: self.failed,
            cert: self.cert,
            created_at: self.created_at.timestamp_millis(),
        }
    }
}
