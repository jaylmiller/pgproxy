use std::sync::Arc;

use pingora::{
    prelude::Opt,
    server::{configuration::ServerConf, Server},
};
use structopt::StructOpt;
use tracing_subscriber::EnvFilter;

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
}

fn main() -> anyhow::Result<()> {
    load_env_files();
    let opts = CustomOpts::from_args();
    init_log(opts.pretty_logs);
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
    let proxy_service = proxy::proxy_service(
        "0.0.0.0:5431", // listen
        "0.0.0.0:5433", // proxy to
        Arc::new(tls),
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
