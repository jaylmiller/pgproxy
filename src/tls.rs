use anyhow::Context;
use pingora::protocols::tls::server::handshake;
use pingora::tls::ssl::{SslAcceptor, SslFiletype, SslMethod};

use rustls_pemfile::{certs, pkcs8_private_keys};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;

// pub fn setup_tls(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, std::io::Error> {
//     let cert = certs(&mut BufReader::new(File::open(cert_path)?))?
//         .into_iter()
//         .map(|x| CertificateDer::from_slice(&x))
//         .collect::<Vec<_>>();

//     let key = pkcs8_private_keys(&mut BufReader::new(File::open("examples/ssl/server.key")?))
//         .map(|key| key.into_iter().map(|x| PrivateKeyDer::from))
//         .collect::<Result<Vec<PrivateKeyDer>, std::io::Error>>()?
//         .remove(0);

//     let mut config = ServerConfig::builder()
//         .with_no_client_auth()
//         .with_single_cert(cert, key)
//         .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

//     config.alpn_protocols = vec![b"postgresql".to_vec()];

//     Ok(TlsAcceptor::from(Arc::new(config)))
// }

pub fn setup_ssl(cert_path: &str, key_path: &str) -> anyhow::Result<SslAcceptor> {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();

    acceptor
        .set_private_key_file(key_path, SslFiletype::PEM)
        .context("setting private key failed")?;
    acceptor
        .set_certificate_chain_file(cert_path)
        .context("setting cert failed")?;
    acceptor
        .check_private_key()
        .context("checking key/cert consistency failed")?;

    Ok(acceptor.build())
}

pub fn setup_tls(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, std::io::Error> {
    // Load certificates
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    // Load private key
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);

    // Try to read as PKCS8 first
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?;

    // If no PKCS8 keys found, try RSA keys
    if keys.is_empty() {
        key_reader = BufReader::new(File::open(key_path)?);
        keys = rustls_pemfile::rsa_private_keys(&mut key_reader)?;
    }

    // If still no keys, return an error
    if keys.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "No private key found",
        ));
    }

    let key = PrivateKey(keys.remove(0));

    // Create server configuration
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;

    // Create TLS acceptor
    Ok(TlsAcceptor::from(Arc::new(server_config)))
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
        let res = setup_ssl(&cert, &key);
    }
}
