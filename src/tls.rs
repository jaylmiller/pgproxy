use pingora::tls::{load_certs_and_key_files, version, ServerConfig, TlsAcceptor};
use std::sync::Arc;

pub fn setup(cert_path: &str, key_path: &str) -> anyhow::Result<pingora::tls::TlsAcceptor> {
    let (certs, key) = load_certs_and_key_files(cert_path, key_path)?.unwrap();
    let conf = ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(conf)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_local_certs() {
        let cert = format!(
            "{}/local-certs/server/server.crt",
            env!("CARGO_MANIFEST_DIR")
        );
        let key = format!("{}/local-certs/server/key.pem", env!("CARGO_MANIFEST_DIR"));
        let tls = setup(&cert, &key).unwrap();
        dbg!(tls.config());
    }
}
