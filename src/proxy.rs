use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use pgwire::api::DefaultClient;
use pgwire::error::ErrorInfo;
use pgwire::messages::response::SslResponse;
use pgwire::messages::startup::Startup;
use pgwire::messages::{PgWireBackendMessage, PgWireFrontendMessage};
use tokio_util::codec::Framed;
use tracing::debug;

use core::net::SocketAddr;

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;

use pingora::apps::ServerApp;

use pingora::listeners::Listeners;
use pingora::protocols::l4::stream::Stream as L4;
use pingora::protocols::{GetSocketDigest, Peek, Stream};
use pingora::server::ShutdownWatch;
use pingora::services::listening::Service;
use pingora::tls::{ServerTlsStream, TlsAcceptor, TlsConnector};
use pingora::upstreams::peer::BasicPeer;

use crate::pg::{check_ssl_direct_negotiation, PgWireMessageServerCodec, SslNegotiationType};

pub fn proxy_service(
    addr: &str,
    proxy_addr: &str,
    tls: Arc<TlsAcceptor>,
    client_tls: Arc<TlsConnector>,
) -> Service<ProxyApp> {
    let proxy_to = BasicPeer::new(proxy_addr);

    Service::with_listeners(
        "Proxy Service".to_string(),
        Listeners::tcp(addr),
        ProxyApp::new(proxy_to, tls, client_tls),
    )
}

pub struct ProxyApp {
    proxy_to: BasicPeer,
    tls: Arc<TlsAcceptor>,
    client_tls: Arc<TlsConnector>,
}

enum ProxyEvents {
    DownstreamRead(usize),
    UpstreamRead(usize),
}

impl ProxyApp {
    pub fn new(proxy_to: BasicPeer, tls: Arc<TlsAcceptor>, client_tls: Arc<TlsConnector>) -> Self {
        ProxyApp {
            proxy_to,
            tls,
            client_tls,
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

    async fn init_downstream(
        &self,
        mut io: L4,
        socketaddr: SocketAddr,
    ) -> anyhow::Result<(ServerTlsStream<L4>, Startup)> {
        let mut socket = Framed::new(&mut io, PgWireMessageServerCodec::new(socketaddr, false));

        let ssl_neg = {
            let direct_negotiation = check_ssl_direct_negotiation(socket.get_mut()).await?;
            if direct_negotiation {
                SslNegotiationType::Direct
            } else if let Some(Ok(PgWireFrontendMessage::SslRequest(Some(_)))) = socket.next().await
            {
                socket
                    .send(PgWireBackendMessage::SslResponse(SslResponse::Accept))
                    .await?;
                SslNegotiationType::Postgres
            } else {
                SslNegotiationType::None
            }
        };

        tracing::info!("Ssl negotation for {socketaddr}: {ssl_neg:?}");
        drop(socket);
        let tls_stream = self.tls.accept(io).await?;

        let mut socket = Framed::new(tls_stream, PgWireMessageServerCodec::new(socketaddr, true));
        let startup: Startup;
        loop {
            match socket.next().await {
                Some(Ok(msg @ PgWireFrontendMessage::SslRequest(_))) => {
                    tracing::debug!("Got ssl request message ({socketaddr}): {msg:?}");
                }
                Some(Ok(PgWireFrontendMessage::Startup(val))) => {
                    startup = val;
                    return Ok((socket.into_inner(), startup));
                }
                Some(Ok(msg)) => {
                    anyhow::bail!("Got unexpected message during startup ({socketaddr}): {msg:?}");
                }
                Some(Err(err)) => {
                    anyhow::bail!("Got protocol error during startup ({socketaddr}) : {err:?}");
                }
                None => {
                    anyhow::bail!(
                        "No message received after tls stream initialized ({socketaddr})"
                    );
                }
            }
        }
    }

    /// Create a new connection to postgres server requests are being proxied to.
    pub async fn init_upstream() {}
}

#[async_trait]
impl ServerApp for ProxyApp {
    async fn process_new(
        self: &Arc<Self>,
        io: Stream,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let sockinfo = io.get_socket_digest().unwrap();

        let socketaddr = sockinfo
            .peer_addr()
            .expect("peer_addr should have value")
            .as_inet()
            .expect("should be inet socket");
        tracing::info!("Got new connection: peer_addr={}", socketaddr);

        let io: Box<L4> = io.into_any().downcast().unwrap();

        let (tls_stream, startup) = match self.init_downstream(*io, *socketaddr).await {
            Err(err) => {
                tracing::error!("Handling startup failed ({socketaddr}): {err:?}");
                return None;
            }
            Ok(s) => s,
        };

        dbg!(tls_stream.get_ref().1.server_name());

        None
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
