use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use pgwire::api::{DefaultClient, PgWireConnectionState};
use pgwire::messages::response::SslResponse;
use pgwire::messages::{PgWireBackendMessage, PgWireFrontendMessage};
use pingora::protocols::tls::server::handshake;
use pingora::tls::ssl::SslAcceptor;
use rustls_pemfile::certs;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Framed;
use tracing::debug;

use core::net::SocketAddr;

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;

use pingora::apps::ServerApp;
use pingora::connectors::TransportConnector;
use pingora::listeners::Listeners;
use pingora::protocols::l4::stream::Stream as TcpStream;
use pingora::protocols::{Peek, Stream, IO};
use pingora::server::ShutdownWatch;
use pingora::services::listening::Service;
use pingora::upstreams::peer::BasicPeer;

use crate::pg::{
    check_ssl_direct_negotiation, peek_for_sslrequest, PgWireMessageServerCodec, SslNegotiationType,
};

pub fn proxy_service(addr: &str, proxy_addr: &str, ssl: Arc<SslAcceptor>) -> Service<ProxyApp> {
    let proxy_to = BasicPeer::new(proxy_addr);

    Service::with_listeners(
        "Proxy Service".to_string(),
        Listeners::tcp(addr),
        ProxyApp::new(proxy_to, ssl),
    )
}

// pub fn proxy_service_tls(
//     addr: &str,
//     proxy_addr: &str,
//     proxy_sni: &str,
//     cert_path: &str,
//     key_path: &str,
// ) -> Service<ProxyApp> {
//     let mut proxy_to = BasicPeer::new(proxy_addr);
//     // set SNI to enable TLS
//     proxy_to.sni = proxy_sni.into();
//     Service::with_listeners(
//         "Proxy Service TLS".to_string(),
//         Listeners::tls(addr, cert_path, key_path).unwrap(),
//         ProxyApp::new(proxy_to),
//     )
// }

pub struct ProxyApp {
    proxy_to: BasicPeer,
    ssl: Arc<SslAcceptor>,
}

enum ProxyEvents {
    DownstreamRead(usize),
    UpstreamRead(usize),
}

impl ProxyApp {
    pub fn new(proxy_to: BasicPeer, ssl: Arc<SslAcceptor>) -> Self {
        ProxyApp {
            // client_connector: TransportConnector::new(None),
            proxy_to,
            ssl,
        }
    }

    // async fn handle_startup(&self, mut stream: Stream) {
    //     let codec = PgWireMessageServerCodec::new();
    //     let mut socket = Framed::new(&mut stream, codec);
    //     todo!()
    // }

    /// Bidirectionaly proxy data between server_session and client_session.
    /// I.e. any bytes read from server session get sent to client session and vice versa.
    async fn proxy_streams(&self, mut server_session: Stream, mut client_session: Stream) {
        let mut upstream_buf = [0; 1024];
        let mut downstream_buf = [0; 1024];
        loop {
            let downstream_read = server_session.read(&mut upstream_buf);
            let upstream_read = client_session.read(&mut downstream_buf);
            let event: ProxyEvents;
            select! {
                n = downstream_read => event
                    = ProxyEvents::DownstreamRead(n.unwrap()),
                n = upstream_read => event
                    = ProxyEvents::UpstreamRead(n.unwrap()),
            }
            match event {
                ProxyEvents::DownstreamRead(0) => {
                    debug!("downstream session closing");
                    return;
                }
                ProxyEvents::UpstreamRead(0) => {
                    debug!("upstream session closing");
                    return;
                }
                ProxyEvents::DownstreamRead(n) => {
                    client_session.write_all(&upstream_buf[0..n]).await.unwrap();
                    client_session.flush().await.unwrap();
                }
                ProxyEvents::UpstreamRead(n) => {
                    server_session
                        .write_all(&downstream_buf[0..n])
                        .await
                        .unwrap();
                    server_session.flush().await.unwrap();
                }
            }
        }
    }

    async fn handle_startup(
        &self,
        mut io: TcpStream,
        socketaddr: SocketAddr,
    ) -> anyhow::Result<()> {
        let client_info = DefaultClient::<()>::new(socketaddr, false);
        let mut socket = Framed::new(&mut io, PgWireMessageServerCodec::new(client_info));
        let ssl_req = {
            let direct_negotiation = {
                let mut buf = [0u8; 1];

                let peeked = socket.get_mut().try_peek(&mut buf).await?;
                assert!(peeked, "try_peek returned false");
                buf[0] == 0x16
            };
            if direct_negotiation {
                anyhow::Ok(SslNegotiationType::Direct)
            } else if let Some(Ok(PgWireFrontendMessage::SslRequest(Some(_)))) = socket.next().await
            {
                socket
                    .send(PgWireBackendMessage::SslResponse(SslResponse::Accept))
                    .await?;
                Ok(SslNegotiationType::Postgres)
            } else {
                Ok(SslNegotiationType::None)
            }
        };

        tracing::info!("Ssl negotation for {socketaddr}: {ssl_req:?}");
        drop(socket);

        // let mut dc = io.as_any();
        // let tcpstream = dc.downcast_mut::<TcpStream>().unwrap();
        // println!("downcast successfully");
        let ssl = handshake(&self.ssl, io);

        Ok(())
    }
}

#[async_trait]
impl ServerApp for ProxyApp {
    async fn process_new(
        self: &Arc<Self>,
        mut io: Stream,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let sockinfo = io.get_socket_digest().unwrap();
        let socketaddr = sockinfo
            .peer_addr()
            .expect("peer_addr should have value")
            .as_inet()
            .expect("should be inet socket");
        tracing::info!("Got new connection: peer_addr={}", socketaddr);

        let mut dc = io.into_any();
        let tcpstream = dc.downcast::<TcpStream>().unwrap();
        println!("downcast success");

        if let Err(err) = self.handle_startup(*tcpstream, *socketaddr).await {
            tracing::error!("Handling startup failed ({socketaddr}): {err:?}");
            panic!("{err:?}");
        };

        None
        // let client_session = self.client_connector.new_stream(&self.proxy_to).await;

        // match client_session {
        //     Ok(client_session) => {
        //         self.proxy_streams(io, client_session).await;
        //         None
        //     }
        //     Err(e) => {
        //         debug!("Failed to create client session: {}", e);
        //         None
        //     }
        // }
    }

    /// This callback will be called once after the service stops listening to its endpoints.
    async fn cleanup(&self) {
        tracing::info!(
            "Cleaning up connection: addr={}, sni={}",
            self.proxy_to._address,
            self.proxy_to.sni
        );
    }
}
