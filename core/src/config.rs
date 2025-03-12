use crypto::hex::HexBytes;
use envconfig::Envconfig;

#[derive(Debug, Clone, Envconfig)]
pub struct ServerConfig {
    #[envconfig(from = "SERVER_HOST", default = "127.0.0.1")]
    pub host: String,

    #[envconfig(from = "SERVER_PORT", default = "3000")]
    pub port: String,

    #[envconfig(from = "LOG_LEVEL", default = "info")]
    pub log_level: log::Level,
}

#[derive(Debug, Clone, Envconfig)]
pub struct EthereumConfig {
    #[envconfig(from = "ETHEREUM_RPC_URL")]
    pub rpc_url: String,

    #[envconfig(from = "ETHEREUM_CONTRACT_ADDRESS")]
    pub contract_address: String,
}

#[derive(Debug, Clone, Envconfig)]
pub struct Secrets {
    #[envconfig(from = "BLS_PRIVATE_KEY")]
    pub bls_private_key: HexBytes,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server_config: ServerConfig,
    pub ethereum_config: EthereumConfig,
    pub secrets: Secrets,
}

impl AppConfig {
    pub fn fetch() -> Self {
        let server_config = ServerConfig::init_from_env().expect("Failed to load server config");
        let ethereum_config =
            EthereumConfig::init_from_env().expect("Failed to load ethereum config");
        let secrets = Secrets::init_from_env().expect("Failed to load secrets");

        Self {
            server_config,
            ethereum_config,
            secrets,
        }
    }
}
