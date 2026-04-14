use std::collections::HashMap;
use std::sync::Arc;

use client::init_connection;
use pingora::{
    prelude::Opt,
    server::{configuration::ServerConf, Server},
};
use proxy::Upstream;
use structopt::StructOpt;
use tracing_subscriber::EnvFilter;

mod client;
mod config;
mod pg;
mod proxy;
mod tls;

#[derive(StructOpt, Debug, Default)]
#[structopt(name = "pgproxy")]
struct CustomOpts {
    #[structopt(long, env)]
    cert_path: String,

    #[structopt(long, env)]
    key_path: String,

    /// Output logs human readable instead of json (for dev)
    #[structopt(long, env)]
    pretty_logs: bool,

    #[structopt(long, env)]
    test_client: bool,

    /// Path to a JSON config file that maps SNI hostnames to backend servers.
    /// When provided, the proxy routes connections based on the SNI in the TLS handshake.
    #[structopt(long, env = "CONFIG_PATH")]
    config: Option<String>,
}

async fn test_client() -> anyhow::Result<()> {
    let conn = init_connection(
        "localhost",
        5433,
        Some(Arc::new(tls::setup_client())),
        false,
    )
    .await?;
    dbg!(conn);
    Ok(())
}

fn main() -> anyhow::Result<()> {
    load_env_files();
    let opts = CustomOpts::from_args();
    init_log(opts.pretty_logs);
    if opts.test_client {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed building the Runtime")
            .block_on(test_client())
            .unwrap();
        return Ok(());
    }

    let mut server = Server::new_with_opt_and_conf(
        Opt {
            conf: None,
            daemon: false,
            nocapture: false,
            test: false,
            upgrade: false,
        },
        ServerConf {
            threads: 4,
            ..Default::default()
        },
    );

    server.bootstrap();
    let tls = tls::setup(&opts.cert_path, &opts.key_path)?;
    let client_tls = tls::setup_client();

    let (listen_addr, upstreams, default_upstream) = if let Some(config_path) = &opts.config {
        let proxy_config = config::ProxyConfig::from_file(config_path)?;
        let listen = proxy_config
            .listen
            .clone()
            .unwrap_or_else(|| "0.0.0.0:5431".to_string());
        let (map, default) = proxy_config.into_upstream_map();
        tracing::info!(
            listen = %listen,
            backends = map.len(),
            has_default = default.is_some(),
            "Loaded SNI routing config"
        );
        for (sni, upstream) in &map {
            tracing::info!(sni, hostname = %upstream.hostname, port = upstream.port, ssl = upstream.ssl, "Registered backend");
        }
        (listen, map, default)
    } else {
        // Backwards-compatible: single upstream at 127.0.0.1:5433
        let map = HashMap::new();
        let upstream = Upstream {
            hostname: "127.0.0.1".to_string(),
            port: 5433,
            ssl: false,
        };
        ("0.0.0.0:5431".to_string(), map, Some(upstream))
    };

    let proxy_service = proxy::proxy_service(
        &listen_addr,
        upstreams,
        default_upstream,
        Arc::new(tls),
        Arc::new(client_tls),
    );
    server.add_service(proxy_service);

    server.run_forever()
}

fn init_log(pretty_logs: bool) {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    let filter = EnvFilter::from_default_env();
    let trace_sub = tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_env_filter(filter)
        .with_ansi(pretty_logs);
    if pretty_logs {
        trace_sub.init()
    } else {
        trace_sub.json().flatten_event(true).init()
    }
}

fn load_env_files() {
    let files = [".env", ".env.local"];
    for file in files {
        if let Ok(path) = dotenv::from_filename(file) {
            tracing::info!("loaded env from {}", path.display())
        }
    }
}
