use anyhow::anyhow;
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use pgwire::messages::response::SslResponse;
use pgwire::messages::{PgWireBackendMessage, PgWireFrontendMessage};
use tokio_util::codec::Framed;

use core::net::SocketAddr;
use std::collections::HashMap;

use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use pingora::apps::ServerApp;

use pingora::listeners::Listeners;
use pingora::protocols::l4::stream::Stream as L4;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use pingora::services::listening::Service;
use pingora::tls::{ClientTlsStream, ServerTlsStream, TlsAcceptor, TlsConnector};

use crate::pg::PgWireMessageServerCodec;

pub fn proxy_service(
    addr: &str,
    upstreams: HashMap<String, Upstream>,
    default_upstream: Option<Upstream>,
    tls: Arc<TlsAcceptor>,
    client_tls: Arc<TlsConnector>,
) -> Service<ProxyApp> {
    Service::with_listeners(
        "Proxy Service".to_string(),
        Listeners::tcp(addr),
        ProxyApp::new(upstreams, default_upstream, tls, client_tls),
    )
}

#[derive(Debug, Clone)]
pub struct Upstream {
    pub hostname: String,
    pub port: u16,
    /// Equivalent to sslmode=require queryparam
    pub ssl: bool,
}

pub struct ProxyApp {
    upstreams: HashMap<String, Upstream>,
    default_upstream: Option<Upstream>,
    tls: Arc<TlsAcceptor>,
    client_tls: Arc<TlsConnector>,
}

enum ProxyEvents {
    DownstreamRead(usize),
    UpstreamRead(usize),
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl AsyncReadWrite for L4 {}
impl AsyncReadWrite for ClientTlsStream<L4> {}

impl ProxyApp {
    pub fn new(
        upstreams: HashMap<String, Upstream>,
        default_upstream: Option<Upstream>,
        tls: Arc<TlsAcceptor>,
        client_tls: Arc<TlsConnector>,
    ) -> Self {
        ProxyApp {
            upstreams,
            default_upstream,
            tls,
            client_tls,
        }
    }

    /// Look up the upstream backend based on the SNI from the client's TLS handshake.
    /// Falls back to the default upstream if no SNI match is found.
    fn resolve_upstream(&self, sni: Option<&str>) -> Option<&Upstream> {
        if let Some(sni) = sni {
            if let Some(upstream) = self.upstreams.get(sni) {
                tracing::info!(sni, "Resolved upstream via SNI");
                return Some(upstream);
            }
            tracing::warn!(sni, "No upstream configured for SNI, trying default");
        } else {
            tracing::warn!("No SNI provided by client, trying default");
        }
        self.default_upstream.as_ref()
    }

    /// Bidirectionaly proxy data between downstream and upstream
    async fn proxy_streams(
        &self,
        mut downstream: ServerTlsStream<L4>,
        upstream: crate::client::Client,
    ) -> anyhow::Result<()> {
        let mut upstream = match upstream {
            crate::client::Client::Plain(stream) => Box::new(stream) as Box<dyn AsyncReadWrite>,
            crate::client::Client::Secure(tls_stream) => Box::new(tls_stream),
        };
        let mut upstream_buf = [0; 1024];
        let mut downstream_buf = [0; 1024];
        loop {
            let downstream_read = downstream.read(&mut upstream_buf);
            let upstream_read = upstream.read(&mut downstream_buf);
            let event: ProxyEvents;
            tokio::select! {
                n = downstream_read => event
                    = ProxyEvents::DownstreamRead(n?),
                n = upstream_read => event
                    = ProxyEvents::UpstreamRead(n?),
            }
            match event {
                ProxyEvents::DownstreamRead(0) => {
                    tracing::debug!("downstream session closing");
                    return Ok(());
                }
                ProxyEvents::UpstreamRead(0) => {
                    tracing::debug!("upstream session closing");
                    return Ok(());
                }
                ProxyEvents::DownstreamRead(n) => {
                    upstream.write_all(&upstream_buf[0..n]).await.unwrap();
                    upstream.flush().await.unwrap();
                }
                ProxyEvents::UpstreamRead(n) => {
                    downstream.write_all(&downstream_buf[0..n]).await.unwrap();
                    downstream.flush().await.unwrap();
                }
            }
        }
    }

    /// Initialize the downstream (client-facing) TLS connection.
    /// Returns the TLS stream and the SNI hostname extracted from the handshake.
    async fn init_downstream(
        &self,
        mut io: L4,
        socketaddr: SocketAddr,
    ) -> anyhow::Result<(ServerTlsStream<L4>, Option<String>)> {
        io.set_nodelay().unwrap();
        let mut socket = Framed::new(io, PgWireMessageServerCodec::new(socketaddr, false));
        match socket
            .next()
            .await
            .ok_or_else(|| anyhow!("never received message"))??
        {
            PgWireFrontendMessage::SslRequest(Some(_)) => {
                tracing::trace!("Got SslRequest message");
            }
            other => {
                anyhow::bail!("Got unexpected message: {other:?}");
            }
        }

        socket
            .send(PgWireBackendMessage::SslResponse(SslResponse::Accept))
            .await?;
        tracing::trace!("Sent SslResponse::Accept, upgrading conn now");

        let tls_stream = self.tls.accept(socket.into_inner()).await?;
        let sni = tls_stream
            .get_ref()
            .1
            .server_name()
            .map(|s| s.to_string());
        tracing::info!(sni = ?sni, "Opened upgraded TLS conn");
        Ok((tls_stream, sni))
    }

    /// Create a new connection to postgres server requests are being proxied to.
    pub async fn init_upstream(
        &self,
        upstream: &Upstream,
    ) -> pingora::Result<crate::client::Client> {
        let tls_connector = if upstream.ssl {
            Some(self.client_tls.clone())
        } else {
            None
        };
        crate::client::init_connection(
            &upstream.hostname,
            upstream.port,
            tls_connector,
            upstream.ssl,
        )
        .await
    }
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
        let (downstream, sni) = match self.init_downstream(*io, *socketaddr).await {
            Ok(v) => v,
            Err(err) => {
                tracing::error!("Failed to initialize the downstream session: {err:?}");
                return None;
            }
        };

        let upstream_config = match self.resolve_upstream(sni.as_deref()) {
            Some(u) => u,
            None => {
                tracing::error!(sni = ?sni, "No upstream backend found for SNI and no default configured");
                return None;
            }
        };

        let upstream = match self.init_upstream(upstream_config).await {
            Ok(v) => v,
            Err(err) => {
                tracing::error!("Failed to initialize the upstream session: {err:?}");
                return None;
            }
        };

        if let Err(err) = self.proxy_streams(downstream, upstream).await {
            tracing::error!("Proxy failed: {err:?}");
        }

        None
    }

    /// This callback will be called once after the service stops listening to its endpoints.
    async fn cleanup(&self) {}
}
