use pingora::tls::{
    load_certs_and_key_files, load_native_certs, version, ClientConfig, RootCertStore,
    ServerConfig, TlsAcceptor, TlsConnector,
};
use std::sync::Arc;

pub fn setup(cert_path: &str, key_path: &str) -> pingora::Result<pingora::tls::TlsAcceptor> {
    let (certs, key) = load_certs_and_key_files(cert_path, key_path)?.unwrap();
    let mut conf =
        ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("building tls config shouldnt fail");
    conf.alpn_protocols = vec![b"postgresql".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(conf)))
}

fn client_root_store() -> RootCertStore {
    let mut store = RootCertStore::empty();
    let certs = load_native_certs().expect("loading native certs failed");
    for c in certs {
        store.add(c).expect("adding native cert shouldn't fail");
    }
    store
}

pub fn setup_client() -> TlsConnector {
    let mut conf =
        ClientConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
            .with_root_certificates(client_root_store())
            .with_no_client_auth();

    conf.alpn_protocols = vec![b"postgresql".to_vec()];
    conf.enable_sni = true;
    TlsConnector::from(Arc::new(conf))
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

    #[test]
    fn client_setup_works() {
        setup_client();
    }
}
