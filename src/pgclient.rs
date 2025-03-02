use std::any::Any;
use std::io::ErrorKind;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use bytes::{Buf, BufMut, BytesMut};
use futures::{SinkExt, StreamExt};
// adapted code from https://github.com/sunng87/pgwire/blob/aad3de9c909560c87e4f49760d565a6f1f4b8aa5/src/tokio/client.rs
use pgwire::error::{PgWireError, PgWireResult};
use pgwire::messages::response::SslResponse;
use pgwire::messages::startup::SslRequest;
use pgwire::messages::{self, startup, Message, PgWireBackendMessage, PgWireFrontendMessage};
use pin_project::pin_project;

use pingora::protocols::IO;
use pingora::tls::{ServerName, TlsConnector};
use pingora::{
    connectors::TransportConnector, tls::ClientTlsStream, upstreams::peer::BasicPeer, ErrorType,
};
use pingora::{
    protocols::{l4::stream::Stream as L4, Peek},
    Result,
};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Decoder, Encoder, Framed};

pub struct PgWireMessageClientCodec;

impl Decoder for PgWireMessageClientCodec {
    type Item = PgWireBackendMessage;
    type Error = PgWireError;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        PgWireBackendMessage::decode(src)
    }
}

impl Encoder<PgWireFrontendMessage> for PgWireMessageClientCodec {
    type Error = PgWireError;

    fn encode(
        &mut self,
        item: PgWireFrontendMessage,
        dst: &mut bytes::BytesMut,
    ) -> Result<(), Self::Error> {
        item.encode(dst)
    }
}

fn hostname_is_ipv4(hostname: &str) -> bool {
    std::net::Ipv4Addr::from_str(hostname).is_ok()
}

fn to_peer(hostname: &str, port: u16, tls: bool) -> BasicPeer {
    for addr in format!("{hostname}:{port}")
        .to_socket_addrs()
        .expect("could not parse socketaddr")
    {
        if addr.is_ipv4() {
            let mut peer = BasicPeer::new(&addr.to_string());
            if tls && !hostname_is_ipv4(hostname) {
                peer.sni = hostname.to_string();
            }
            return peer;
        }
    }
    panic!("to_socket_addrs failed unexpectedly")
}

pub async fn init_connection(
    hostname: &str,
    port: u16,
    connector: &TransportConnector,
    tls_connector: Option<Arc<TlsConnector>>,
    require_ssl: bool,
) -> Result<Client> {
    let peer = to_peer(hostname, port, tls_connector.is_some());

    let session = connector
        .new_stream(&peer)
        .await?
        .into_any()
        .downcast::<L4>()
        .unwrap();
    let session = Framed::new(session, PgWireMessageClientCodec);
    let client = match ssl_handshake(session, &peer, tls_connector, require_ssl).await {
        Ok(s) => s,
        Err(err) => {
            tracing::error!("Error occurred during ssl handshake with upstream: {err:?}");
            return Err(pingora::Error::new(ErrorType::ConnectError));
        }
    };
    Ok(client)
}

#[derive(Debug)]
pub enum Client {
    Plain(L4),
    Secure(ClientTlsStream<L4>),
}

async fn connect_tls(
    socket: L4,
    peer: &BasicPeer,
    tls_connector: Arc<TlsConnector>,
) -> Result<ClientTlsStream<L4>, std::io::Error> {
    let server_name = ServerName::try_from(peer.sni.clone())
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;
    let tls_stream = tls_connector.connect(server_name, socket).await?;
    Ok(tls_stream)
}

async fn ssl_handshake(
    mut socket: Framed<Box<L4>, PgWireMessageClientCodec>,
    peer: &BasicPeer,
    tls_connector: Option<Arc<TlsConnector>>,
    require_ssl: bool,
) -> Result<Client, std::io::Error> {
    let Some(tls_connector) = tls_connector else {
        // ssl is disabled on client side
        return Ok(Client::Plain(*socket.into_inner()));
    };

    socket
        .send(PgWireFrontendMessage::SslRequest(Some(
            pgwire::messages::startup::SslRequest::new(),
        )))
        .await?;

    if let Some(Ok(PgWireBackendMessage::SslResponse(ssl_resp))) = socket.next().await {
        match ssl_resp {
            SslResponse::Accept => {
                let conn = connect_tls(*socket.into_inner(), peer, tls_connector).await?;
                Ok(Client::Secure(conn))
            }
            SslResponse::Refuse => {
                if require_ssl {
                    Err(std::io::Error::new(
                        ErrorKind::ConnectionAborted,
                        "TLS is not enabled on server but client specified it must be required",
                    ))
                } else {
                    Ok(Client::Plain(*socket.into_inner()))
                }
            }
            _ => unreachable!(),
        }
    } else {
        // connection closed
        Err(std::io::Error::new(
            ErrorKind::ConnectionAborted,
            "Expect SslResponse",
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::init_log;

    use super::*;

    struct TestDbConn {
        port: String,
        pw: String,
        username: String,
        db: String,
        hostname: String,
        tls: bool,
    }

    fn local_testdb() -> Option<TestDbConn> {
        let Some(port) = option_env!("TESTDB_PORT") else {
            return None;
        };
        let load_env = |key: &str, default: &str| {
            std::env::var(key)
                .ok()
                .as_ref()
                .map(|x| x.to_string())
                .unwrap_or_else(|| default.to_string())
        };

        let pw = load_env("TESTDB_PW", "pw");
        let db = load_env("TESTDB_DATABASE", "postgres");
        let hostname = load_env("TESTDB_HOSTNAME", "localhost");
        let username = load_env("TESTDB_USERNAME", "postgres");
        let tls = load_env("TESTDB_TLS", "");
        let tls = ["1", "true"].contains(&tls.as_str());

        Some(TestDbConn {
            port: port.to_string(),
            pw,
            username,
            db,
            hostname,
            tls,
        })
    }

    // // https://rnacentral.org/help/public-database
    // fn public_db() -> TestDbConn {
    //     TestDbConn {
    //         port: "5432".to_string(),
    //         username: "reader".to_string(),
    //         pw: "NWDMCE5xdipIjRrp".to_string(),
    //         hostname: "hh-pgsql-public.ebi.ac.uk".to_string(),
    //         db: "pfmegrnargs".to_string(),
    //         tls: false,
    //     }
    // }

    #[test]
    fn test_to_peer() {
        let peer = to_peer("localhost", 5433, false);

        let peer = to_peer("localhost", 5433, true);
        assert_eq!(peer.sni, "localhost");
    }

    #[tokio::test]
    async fn test_init_connection_localdb() {
        init_log(true);
        let Some(db) = local_testdb() else {
            eprintln!("local testdb not configured in env, skipping");
            return;
        };

        let connector = TransportConnector::new(None);

        let tls_conn = if db.tls {
            Some(Arc::new(crate::tls::setup_client()))
        } else {
            None
        };

        let client = init_connection(
            &db.hostname,
            db.port.parse().unwrap(),
            &connector,
            tls_conn,
            db.tls,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_tls() {
        let Some(db) = local_testdb() else {
            eprintln!("local testdb not configured in env, skipping");
            return;
        };
        let peer = to_peer(&db.hostname, db.port.parse().unwrap(), true);
        let connector = TransportConnector::new(None);
        let session = connector
            .new_stream(&peer)
            .await
            .unwrap()
            .into_any()
            .downcast::<L4>()
            .unwrap();
        let conn = connect_tls(*session, &peer, Arc::new(crate::tls::setup_client())).await;
        dbg!(&conn);
    }
}
