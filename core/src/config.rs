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
    #[envconfig(from = "ETHEREUM_WS_RPC_URL")]
    pub ws_rpc_url: String,
    #[envconfig(from = "ETHEREUM_HTTP_RPC_URL")]
    pub http_rpc_url: String,
    #[envconfig(from = "ETHEREUM_CONTRACT_ADDRESS")]
    pub contract_address: String,
    #[envconfig(from = "NUMBER_OF_BLOCKS_TO_CONFIRM", default = "20")]
    pub number_of_blocks_to_confirm: u64,
    #[envconfig(from = "NUMBER_OF_PENDING_BLOCKS", default = "5")]
    pub number_of_pending_blocks: u64,
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
