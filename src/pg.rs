use std::net::SocketAddr;

use bytes::Buf;
use pgwire::{
    api::{ClientInfo, DefaultClient, PgWireConnectionState},
    error::PgWireError,
    messages::{
        startup::{SslRequest, Startup},
        Message, PgWireBackendMessage, PgWireFrontendMessage,
    },
};
use pingora::{
    connectors::TransportConnector, tls::ClientTlsStream, upstreams::peer::BasicPeer, ErrorType,
};
use pingora::{
    protocols::{l4::stream::Stream as L4, Peek},
    Result,
};
use tokio_util::codec::{Decoder, Encoder, Framed};

pub struct PgWireMessageServerCodec {
    client_info: DefaultClient<()>,
}

impl PgWireMessageServerCodec {
    pub fn new(socket_addr: SocketAddr, is_secure: bool) -> Self {
        PgWireMessageServerCodec {
            client_info: DefaultClient::new(socket_addr, is_secure),
        }
    }
}

impl Decoder for PgWireMessageServerCodec {
    type Item = PgWireFrontendMessage;
    type Error = PgWireError;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.client_info.state() {
            PgWireConnectionState::AwaitingSslRequest => {
                if src.remaining() >= SslRequest::BODY_SIZE {
                    self.client_info
                        .set_state(PgWireConnectionState::AwaitingStartup);

                    if let Some(request) = SslRequest::decode(src)? {
                        return Ok(Some(PgWireFrontendMessage::SslRequest(Some(request))));
                    } else {
                        return Ok(Some(PgWireFrontendMessage::SslRequest(None)));
                    }
                }

                Ok(None)
            }

            PgWireConnectionState::AwaitingStartup => {
                if let Some(startup) = Startup::decode(src)? {
                    Ok(Some(PgWireFrontendMessage::Startup(startup)))
                } else {
                    Ok(None)
                }
            }

            _ => PgWireFrontendMessage::decode(src),
        }
    }
}

impl Encoder<PgWireBackendMessage> for PgWireMessageServerCodec {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        item: PgWireBackendMessage,
        dst: &mut bytes::BytesMut,
    ) -> Result<(), Self::Error> {
        item.encode(dst).map_err(Into::into)
    }
}


#[derive(Debug, PartialEq, Eq)]
pub enum SslNegotiationType {
    Postgres,
    Direct,
    None,
}

pub async fn check_ssl_direct_negotiation(tcp_socket: &mut L4) -> Result<bool> {
    let mut buf = [0u8; 1];

    let peeked = match tcp_socket.try_peek(&mut buf).await {
        Ok(p) => p,
        Err(err) => {
            tracing::error!("Peeking next byte on tcp for ssl direct negotation failed: {err:?}");
            return Err(pingora::Error::new(ErrorType::ReadError));
        }
    };
    assert!(peeked, "try_peek returned false");
    Ok(buf[0] == 0x16)
}
