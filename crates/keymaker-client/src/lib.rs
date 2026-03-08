pub use keymaker_models as models;
use reqwest::{Client, StatusCode, Url};

// NOTE: We don't really have a good way to convey error information to the client at this point in
// time. The Keymaker server responds with 4XX for things that are probably the client's fault and
// 5XX for things that are probably the server's fault. We don't really get much information beyond
// that.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not perform request")]
    ReqwestLocal {
        #[source]
        source: reqwest::Error,
    },

    #[error("server returned status code {status_code}")]
    ReqwestRemote {
        status_code: StatusCode,

        #[source]
        source: reqwest::Error,
    },
}

pub struct KeymakerClient {
    client: Client,
    base_url: Url,
}

impl KeymakerClient {
    #[must_use]
    pub fn new(client: Client, base_url: Url) -> Self {
        Self { client, base_url }
    }
}

impl KeymakerClient {
    /// Given a fully formed URL and a JSON serializable request, perform the request and return a
    /// JSON deserialized response.
    async fn execute<Request, Response>(
        &self,
        url: Url,
        request: Request,
    ) -> Result<Response, Error>
    where
        Request: serde::Serialize,
        Response: serde::de::DeserializeOwned,
    {
        let response = self.client.post(url).json(&request).send().await;

        let body = match response {
            Ok(o) => o,
            Err(source) => match source.status() {
                Some(status_code)
                    if status_code.is_server_error() || status_code.is_client_error() =>
                {
                    return Err(Error::ReqwestRemote {
                        status_code,
                        source,
                    });
                }
                _ => {
                    return Err(Error::ReqwestLocal { source });
                }
            },
        };

        let response: Response = body
            .json()
            .await
            .map_err(|source| Error::ReqwestLocal { source })?;

        Ok(response)
    }

    pub async fn generate_quorum(
        &self,
        request: models::generate_quorum::GenerateQuorumRequest,
    ) -> Result<models::generate_quorum::GenerateQuorumResponse, Error> {
        let url = self
            .base_url
            .clone()
            .join("/generate_quorum")
            .expect("for valid base URLs, /generate_quorum should be a valid extension");
        self.execute(url, request).await
    }
}
