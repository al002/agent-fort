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
    use crate::{MicrovmHealthRequest, MicrovmHealthResponse};

    #[test]
    fn health_request_round_trip() {
        let request = MicrovmHealthRequest {};
        let encoded = encode_message(&request);
        let decoded = decode_message::<MicrovmHealthRequest>(&encoded).expect("decode request");
        assert_eq!(decoded, request);
    }

    #[test]
    fn health_response_round_trip() {
        let response = MicrovmHealthResponse {
            ok: true,
            error_code: None,
            error_message: None,
        };
        let encoded = encode_message(&response);
        let decoded = decode_message::<MicrovmHealthResponse>(&encoded).expect("decode response");
        assert_eq!(decoded, response);
    }
}
