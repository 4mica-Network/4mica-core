use std::ops::Deref;
use std::sync::Arc;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};

#[derive(Clone)]
pub struct RpcProxy {
    client: Arc<HttpClient>,
}

impl RpcProxy {
    pub async fn new(addr: &str) -> anyhow::Result<Self> {
        let client = HttpClientBuilder::default().build(format!("http://{addr}"))?;
        Ok(Self { client: Arc::new(client) })
    }
}

impl Deref for RpcProxy {
    type Target = HttpClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}
