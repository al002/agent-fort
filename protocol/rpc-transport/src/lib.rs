pub mod async_codec;
pub mod client;
pub mod endpoint;
pub mod error;
pub mod frame;
pub mod server;
pub mod unix;
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

pub use client::{ClientOptions, RpcClient};
pub use endpoint::{Endpoint, EndpointKind};
pub use error::TransportError;
pub use frame::{DEFAULT_MAX_FRAME_LEN, FRAME_HEADER_LEN};
pub use server::{RpcConnection, RpcServer, ServerOptions};

#[cfg(test)]
mod tests {
    use crate::async_codec;
    use af_rpc_proto::{PingRequest, PingResponse};

    #[tokio::test]
    async fn ping_roundtrip_over_duplex_codec() {
        let (mut client_io, mut server_io) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let _request: PingRequest = async_codec::read_message(&mut server_io, 4096)
                .await
                .expect("server should read request");

            let response = PingResponse {
                status: "ok".to_string(),
                daemon_instance_id: "daemon-1".to_string(),
            };
            async_codec::write_message(&mut server_io, &response, 4096)
                .await
                .expect("server should write response");
        });

        async_codec::write_message(&mut client_io, &PingRequest {}, 4096)
            .await
            .expect("client should write request");
        let response: PingResponse = async_codec::read_message(&mut client_io, 4096)
            .await
            .expect("client should read response");
        server_task.await.expect("server task should finish");

        assert_eq!(response.status, "ok");
        assert_eq!(response.daemon_instance_id, "daemon-1");
    }
}
