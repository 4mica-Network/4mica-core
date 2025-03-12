use envconfig::Envconfig;

#[derive(Debug, Clone, Envconfig)]
pub struct ServerConfig {
    #[envconfig(from = "SERVER_HOST", default = "127.0.0.1")]
    pub host: String,

    #[envconfig(from = "SERVER_PORT", default = "3010")]
    pub port: String,

    #[envconfig(from = "LOG_LEVEL", default = "info")]
    pub log_level: log::Level,
}

#[derive(Debug, Clone, Envconfig)]
pub struct ProxyConfig {
    #[envconfig(from = "PROXY_CORE_ADDR", default = "127.0.0.1:3000")]
    pub core_addr: String,
}

#[derive(Clone)]
pub struct AppConfig {
    pub server_config: ServerConfig,
    pub proxy_config: ProxyConfig,
}

impl AppConfig {
    pub fn fetch() -> Self {
        let server_config = ServerConfig::init_from_env().expect("Failed to load server config");
        let proxy_config = ProxyConfig::init_from_env().expect("Failed to load proxy config");

        Self {
            server_config,
            proxy_config,
        }
    }
}
