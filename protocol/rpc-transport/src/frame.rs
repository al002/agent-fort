use crate::error::TransportError;

pub const FRAME_HEADER_LEN: usize = 4;
pub const DEFAULT_MAX_FRAME_LEN: usize = 8 * 1024 * 1024;

pub fn frame_header(
    frame_len: usize,
    max_frame_len: usize,
) -> Result<[u8; FRAME_HEADER_LEN], TransportError> {
    if frame_len > max_frame_len {
        return Err(TransportError::FrameTooLarge {
            size: frame_len,
            max: max_frame_len,
        });
    }

    let frame_len = u32::try_from(frame_len).map_err(|_| TransportError::FrameTooLarge {
        size: frame_len,
        max: u32::MAX as usize,
    })?;

    Ok(frame_len.to_be_bytes())
}

pub fn decode_frame_len(
    header: [u8; FRAME_HEADER_LEN],
    max_frame_len: usize,
) -> Result<usize, TransportError> {
    let frame_len = u32::from_be_bytes(header) as usize;
    if frame_len > max_frame_len {
        return Err(TransportError::FrameTooLarge {
            size: frame_len,
            max: max_frame_len,
        });
    }

    Ok(frame_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_len_roundtrip() {
        let header = frame_header(1024, DEFAULT_MAX_FRAME_LEN).expect("header should encode");
        let decoded =
            decode_frame_len(header, DEFAULT_MAX_FRAME_LEN).expect("header should decode");
        assert_eq!(decoded, 1024);
    }

    #[test]
    fn rejects_large_frame() {
        let error = frame_header(DEFAULT_MAX_FRAME_LEN + 1, DEFAULT_MAX_FRAME_LEN)
            .expect_err("must reject");
        assert!(matches!(error, TransportError::FrameTooLarge { .. }));
    }
}
