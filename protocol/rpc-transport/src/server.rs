use prost::Message;

use crate::async_codec;
use crate::endpoint::Endpoint;
use crate::error::TransportError;
use crate::frame::DEFAULT_MAX_FRAME_LEN;

#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub max_frame_len: usize,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
        }
    }
}

#[derive(Debug)]
pub struct RpcServer {
    endpoint: Endpoint,
    options: ServerOptions,
    listener: ServerListener,
}

#[derive(Debug)]
enum ServerListener {
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
    #[cfg(windows)]
    Windows(crate::windows::WindowsListener),
}

#[derive(Debug)]
pub struct RpcConnection {
    max_frame_len: usize,
    stream: ConnectionStream,
}

#[derive(Debug)]
enum ConnectionStream {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(windows)]
    Windows(crate::windows::WindowsStream),
}

impl RpcServer {
    pub fn bind(endpoint: Endpoint) -> Result<Self, TransportError> {
        Self::bind_with_options(endpoint, ServerOptions::default())
    }

    pub fn bind_with_options(
        endpoint: Endpoint,
        options: ServerOptions,
    ) -> Result<Self, TransportError> {
        let listener = match &endpoint {
            Endpoint::Unix(_) => {
                #[cfg(unix)]
                {
                    ServerListener::Unix(crate::unix::bind(&endpoint)?)
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
                    ServerListener::Windows(crate::windows::bind_named_pipe(&endpoint)?)
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
            listener,
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub async fn accept(&self) -> Result<RpcConnection, TransportError> {
        let stream = match &self.listener {
            #[cfg(unix)]
            ServerListener::Unix(listener) => {
                ConnectionStream::Unix(crate::unix::accept(listener).await?)
            }
            #[cfg(windows)]
            ServerListener::Windows(listener) => {
                ConnectionStream::Windows(crate::windows::accept_named_pipe(listener).await?)
            }
        };

        Ok(RpcConnection {
            max_frame_len: self.options.max_frame_len,
            stream,
        })
    }
}

impl Drop for RpcServer {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Endpoint::Unix(_) = self.endpoint {
            let _ = crate::unix::cleanup(&self.endpoint);
        }
    }
}

impl RpcConnection {
    pub async fn read_message<M>(&mut self) -> Result<M, TransportError>
    where
        M: Message + Default,
    {
        match &mut self.stream {
            #[cfg(unix)]
            ConnectionStream::Unix(stream) => {
                async_codec::read_message(stream, self.max_frame_len).await
            }
            #[cfg(windows)]
            ConnectionStream::Windows(_stream) => Err(TransportError::UnsupportedEndpoint(
                "windows named pipe transport is reserved but not implemented yet".to_string(),
            )),
        }
    }

    pub async fn write_message<M>(&mut self, message: &M) -> Result<(), TransportError>
    where
        M: Message,
    {
        match &mut self.stream {
            #[cfg(unix)]
            ConnectionStream::Unix(stream) => {
                async_codec::write_message(stream, message, self.max_frame_len).await
            }
            #[cfg(windows)]
            ConnectionStream::Windows(_stream) => Err(TransportError::UnsupportedEndpoint(
                "windows named pipe transport is reserved but not implemented yet".to_string(),
            )),
        }
    }
}
