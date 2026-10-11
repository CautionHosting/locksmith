pub mod models;
pub mod release;
mod openpgp;

pub mod custody;
pub mod bundle;
pub mod legacy;
mod recovery;
pub mod client;
pub mod server;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

const MAX_FRAME_BODY: u32 = 1024 * 1024;

// Protocol:
//
// Client sends nonce
// Server sends attested nonce and public key
// Client sends OpenPGP signed public key and encrypted payload

#[tracing::instrument(skip(socket), fields(send_type = std::any::type_name::<Sent>()))]
async fn send<Sent>(socket: &mut tokio::net::TcpStream, value: Sent) -> Result<(), tokio::io::Error>
where
    Sent: serde::Serialize + std::fmt::Debug,
{
    tracing::debug!(?value, "sending value");
    let request_string = serde_json::to_string(&value).expect("request is serializable");
    let framed_request = keyfork_frame::try_encode(request_string.as_bytes())
        .expect("requests should be less than u32::MAX bytes");
    socket.write_all(&framed_request).await?;

    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum ReceiveError {
    #[error("frame body length {length} is outside 32..={MAX_FRAME_BODY} [{location}]")]
    InvalidFrameLength {
        length: u32,
        location: &'static std::panic::Location<'static>,
    },

    #[error("could not receive payload")]
    ReceivePayload {
        #[from]
        source: keyfork_frame::DecodeError,
    },

    #[error("could not deserialize payload")]
    DeserializePayload {
        #[from]
        source: serde_json::Error,
    },
}

#[tracing::instrument(skip_all, fields(receive_type = std::any::type_name::<Receive>()))]
async fn receive<Receive>(socket: &mut (impl AsyncRead + Unpin)) -> Result<Receive, ReceiveError>
where
    Receive: serde::de::DeserializeOwned + std::fmt::Debug,
{
    tracing::debug!("receiving type");
    let length = socket.read_u32().await.map_err(keyfork_frame::DecodeError::from)?;
    if !(32..=MAX_FRAME_BODY).contains(&length) {
        return Err(ReceiveError::InvalidFrameLength {
            length,
            location: std::panic::Location::caller(),
        });
    }
    // Validate before the dependency allocates; replay its unchanged wire header.
    let prefix = length.to_be_bytes();
    let mut framed = prefix.as_slice().chain(socket);
    let response_bytes = keyfork_frame::asyncext::try_decode_from(&mut framed)
        .await?;

    let response: Receive = serde_json::from_slice(&response_bytes)?;
    tracing::debug!(?response, "received value");

    Ok(response)
}

#[derive(Debug, thiserror::Error)]
enum SendOrReceiveError {
    #[error(transparent)]
    Send(#[from] tokio::io::Error),

    #[error(transparent)]
    Receive(#[from] ReceiveError),
}

#[tracing::instrument(skip_all)]
async fn send_and_receive<Sent, Receive>(
    socket: &mut tokio::net::TcpStream,
    value: Sent,
) -> Result<Receive, SendOrReceiveError>
where
    Sent: serde::Serialize + std::fmt::Debug,
    Receive: serde::de::DeserializeOwned + std::fmt::Debug,
{
    send(socket, value).await?;
    receive(socket).await.map_err(Into::into)
}

#[cfg(test)]
mod framing_tests;
