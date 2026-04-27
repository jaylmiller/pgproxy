use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use crate::proxy::Upstream;

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub sni: String,
    pub hostname: String,
    pub port: u16,
    #[serde(default)]
    pub ssl: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub listen: Option<String>,
    pub backends: Vec<BackendConfig>,
    pub default_backend: Option<DefaultBackendConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DefaultBackendConfig {
    pub hostname: String,
    pub port: u16,
    #[serde(default)]
    pub ssl: bool,
}

impl ProxyConfig {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(Path::new(path))?;
        let config: ProxyConfig = serde_json::from_str(&contents)?;
        Ok(config)
    }

    /// Build a HashMap of SNI -> Upstream for fast lookups
    pub fn into_upstream_map(self) -> (HashMap<String, Upstream>, Option<Upstream>) {
        let mut map = HashMap::new();
        for backend in self.backends {
            map.insert(
                backend.sni,
                Upstream {
                    hostname: backend.hostname,
                    port: backend.port,
                    ssl: backend.ssl,
                },
            );
        }
        let default = self.default_backend.map(|d| Upstream {
            hostname: d.hostname,
            port: d.port,
            ssl: d.ssl,
        });
        (map, default)
    }
}
