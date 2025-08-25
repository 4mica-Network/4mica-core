use crate::persist::prisma::PrismaClient;
use rpc::common::UserTransactionInfo;
use std::sync::Arc;

pub mod connector;
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

impl From<prisma::user_transaction::Data> for UserTransactionInfo {
    fn from(val: prisma::user_transaction::Data) -> Self {
        UserTransactionInfo {
            user_addr: val.user_address,
            recipient_addr: val.recipient_address,
            tx_hash: val.tx_id,
            amount: val.amount,
            finalized: val.finalized,
            failed: val.failed,
            cert: val.cert,
            created_at: val.created_at.timestamp_millis(),
        }
    }
}
