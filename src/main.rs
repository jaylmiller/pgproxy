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

    /// Address to listen on
    #[structopt(long, env, default_value = "0.0.0.0:5431")]
    listen_addr: String,

    /// Upstream PostgreSQL hostname
    #[structopt(long, env, default_value = "127.0.0.1")]
    upstream_host: String,

    /// Upstream PostgreSQL port
    #[structopt(long, env, default_value = "5433")]
    upstream_port: u16,

    /// Require SSL for upstream connection
    #[structopt(long, env)]
    upstream_ssl: bool,
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

    let upstream = Upstream {
        hostname: opts.upstream_host,
        port: opts.upstream_port,
        ssl: opts.upstream_ssl,
    };

    let proxy_service = proxy::proxy_service(
        &opts.listen_addr,
        upstream,
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
