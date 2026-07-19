pub mod bundle;
pub mod models;
mod openpgp;

pub mod client;
pub mod server;

use tokio::io::AsyncWriteExt;

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
async fn receive<Receive>(socket: &mut tokio::net::TcpStream) -> Result<Receive, ReceiveError>
where
    Receive: serde::de::DeserializeOwned + std::fmt::Debug,
{
    tracing::debug!("receiving type");
    let response_bytes = keyfork_frame::asyncext::try_decode_from(socket)
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
