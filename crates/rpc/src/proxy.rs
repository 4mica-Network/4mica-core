use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use std::ops::Deref;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct RpcProxy {
    client: Arc<HttpClient>,
}

impl RpcProxy {
    pub fn new(endpoint: &str) -> anyhow::Result<Self> {
        let client = HttpClientBuilder::default().build(endpoint)?;
        Ok(Self {
            client: Arc::new(client),
        })
    }
}

impl Deref for RpcProxy {
    type Target = HttpClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}
