use prost::Message;

use crate::async_codec;
use crate::endpoint::Endpoint;
use crate::error::TransportError;
use crate::frame::DEFAULT_MAX_FRAME_LEN;

#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub max_frame_len: usize,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
        }
    }
}

#[derive(Debug)]
pub struct RpcClient {
    endpoint: Endpoint,
    options: ClientOptions,
    io: ClientIo,
}

#[derive(Debug)]
enum ClientIo {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(windows)]
    Windows(crate::windows::WindowsStream),
}

impl RpcClient {
    pub async fn connect(endpoint: Endpoint) -> Result<Self, TransportError> {
        Self::connect_with_options(endpoint, ClientOptions::default()).await
    }

    pub async fn connect_with_options(
        endpoint: Endpoint,
        options: ClientOptions,
    ) -> Result<Self, TransportError> {
        let io = match &endpoint {
            Endpoint::Unix(_) => {
                #[cfg(unix)]
                {
                    ClientIo::Unix(crate::unix::connect(&endpoint).await?)
                }
                #[cfg(not(unix))]
                {
                    return Err(TransportError::UnsupportedEndpoint(
                        "unix endpoint is not available on this platform".to_string(),
                    ));
                }
            }
            Endpoint::NamedPipe(_) => {
                #[cfg(windows)]
                {
                    ClientIo::Windows(crate::windows::connect_named_pipe(&endpoint).await?)
                }
                #[cfg(not(windows))]
                {
                    return Err(TransportError::UnsupportedEndpoint(
                        "named pipe endpoint is not available on this platform".to_string(),
                    ));
                }
            }
        };

        Ok(Self {
            endpoint,
            options,
            io,
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub async fn roundtrip<Req, Resp>(&mut self, request: &Req) -> Result<Resp, TransportError>
    where
        Req: Message,
        Resp: Message + Default,
    {
        match &mut self.io {
            #[cfg(unix)]
            ClientIo::Unix(stream) => {
                async_codec::write_message(stream, request, self.options.max_frame_len).await?;
                async_codec::read_message(stream, self.options.max_frame_len).await
            }
            #[cfg(windows)]
            ClientIo::Windows(_stream) => Err(TransportError::UnsupportedEndpoint(
                "windows named pipe transport is reserved but not implemented yet".to_string(),
            )),
        }
    }
}
