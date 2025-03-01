use bytes::Buf;
use futures::{SinkExt, StreamExt};
use pgwire::{
    api::{ClientInfo, DefaultClient, PgWireConnectionState},
    error::PgWireError,
    messages::{
        response::SslResponse,
        startup::{SslRequest, Startup},
        Message, PgWireBackendMessage, PgWireFrontendMessage,
    },
};
use pingora::protocols::Stream;
use tokio_util::codec::{Decoder, Encoder, Framed};

pub struct PgWireMessageServerCodec<S> {
    client_info: DefaultClient<S>,
}

impl<S> PgWireMessageServerCodec<S> {
    pub fn new(client: DefaultClient<S>) -> Self {
        PgWireMessageServerCodec {
            client_info: client,
        }
    }
}

impl<S> Decoder for PgWireMessageServerCodec<S> {
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
                        // this is not a real message, but to indicate that
                        //  client will not init ssl handshake
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

impl<S> Encoder<PgWireBackendMessage> for PgWireMessageServerCodec<S> {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        item: PgWireBackendMessage,
        dst: &mut bytes::BytesMut,
    ) -> Result<(), Self::Error> {
        item.encode(dst).map_err(Into::into)
    }
}

pub async fn check_ssl_direct_negotiation(socket: &mut Stream) -> Result<bool, std::io::Error> {
    let mut buf = [0u8; 1];

    let peeked = socket.try_peek(&mut buf).await?;
    assert!(peeked, "try_peek returned false");
    Ok(buf[0] == 0x16)
}

#[derive(Debug, PartialEq, Eq)]
pub enum SslNegotiationType {
    Postgres,
    Direct,
    None,
}

pub async fn peek_for_sslrequest<S>(
    socket: &mut Framed<Stream, PgWireMessageServerCodec<S>>,
) -> Result<SslNegotiationType, std::io::Error> {
    if check_ssl_direct_negotiation(socket.get_mut()).await? {
        Ok(SslNegotiationType::Direct)
    } else if let Some(Ok(PgWireFrontendMessage::SslRequest(Some(_)))) = socket.next().await {
        socket
            .send(PgWireBackendMessage::SslResponse(SslResponse::Accept))
            .await?;
        Ok(SslNegotiationType::Postgres)
    } else {
        Ok(SslNegotiationType::None)
    }
}

// fn setup_tls() -> Result<TlsAcceptor, IOError> {
//     let cert = certs(&mut BufReader::new(File::open("examples/ssl/server.crt")?))
//         .collect::<Result<Vec<CertificateDer>, IOError>>()?;

//     let key = pkcs8_private_keys(&mut BufReader::new(File::open("examples/ssl/server.key")?))
//         .map(|key| key.map(PrivateKeyDer::from))
//         .collect::<Result<Vec<PrivateKeyDer>, IOError>>()?
//         .remove(0);

//     let mut config = ServerConfig::builder()
//         .with_no_client_auth()
//         .with_single_cert(cert, key)
//         .map_err(|err| IOError::new(ErrorKind::InvalidInput, err))?;

//     config.alpn_protocols = vec![b"postgresql".to_vec()];

//     Ok(TlsAcceptor::from(Arc::new(config)))
// }
