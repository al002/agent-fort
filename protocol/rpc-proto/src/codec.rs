use prost::{DecodeError, Message};

pub fn encode_message<M>(message: &M) -> Vec<u8>
where
    M: Message,
{
    message.encode_to_vec()
}

pub fn decode_message<M>(bytes: &[u8]) -> Result<M, DecodeError>
where
    M: Message + Default,
{
    M::decode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PingRequest, PingResponse};

    #[test]
    fn ping_request_round_trip() {
        let request = PingRequest {};
        let encoded = encode_message(&request);
        let decoded = decode_message::<PingRequest>(&encoded).expect("decode should succeed");
        assert_eq!(decoded, request);
    }

    #[test]
    fn ping_response_round_trip() {
        let response = PingResponse {
            status: "ok".to_string(),
            daemon_instance_id: "daemon-1".to_string(),
        };
        let encoded = encode_message(&response);
        let decoded = decode_message::<PingResponse>(&encoded).expect("decode should succeed");
        assert_eq!(decoded.status, "ok");
        assert_eq!(decoded.daemon_instance_id, "daemon-1");
    }
}
