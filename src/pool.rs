use std::sync::Arc;

use async_trait::async_trait;
use pingora::tls::TlsConnector;
use tokio::io::AsyncReadExt;

use crate::client::{self, Client};
use crate::proxy::Upstream;

/// Manages the lifecycle of upstream PostgreSQL connections for the bb8 pool.
pub struct PgConnectionManager {
    upstream: Upstream,
    client_tls: Arc<TlsConnector>,
}

impl PgConnectionManager {
    pub fn new(upstream: Upstream, client_tls: Arc<TlsConnector>) -> Self {
        Self {
            upstream,
            client_tls,
        }
    }
}

#[async_trait]
impl bb8::ManageConnection for PgConnectionManager {
    type Connection = Client;
    type Error = anyhow::Error;

    /// Create a new TCP/TLS connection to the upstream PostgreSQL server.
    async fn connect(&self) -> Result<Client, Self::Error> {
        let tls_connector = if self.upstream.ssl {
            Some(self.client_tls.clone())
        } else {
            None
        };
        client::init_connection(
            &self.upstream.hostname,
            self.upstream.port,
            tls_connector,
            self.upstream.ssl,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to upstream: {:?}", e))
    }

    /// Check whether an existing connection is still usable.
    ///
    /// Attempts a non-blocking read with a short timeout. If the server has
    /// closed the connection we will see EOF (0 bytes) or an error; if the
    /// connection is idle the read will time out, which we treat as healthy.
    async fn is_valid(&self, conn: &mut Client) -> Result<(), Self::Error> {
        let mut buf = [0u8; 1];
        match tokio::time::timeout(std::time::Duration::from_millis(10), conn.read(&mut buf)).await
        {
            Ok(Ok(0)) => Err(anyhow::anyhow!("connection closed by server")),
            Ok(Err(e)) => Err(anyhow::anyhow!("connection error: {}", e)),
            Ok(Ok(_)) => Err(anyhow::anyhow!("unexpected data on idle connection")),
            // Timeout — no data available, connection is still alive.
            Err(_) => Ok(()),
        }
    }

    fn has_broken(&self, _conn: &mut Client) -> bool {
        false
    }
}
