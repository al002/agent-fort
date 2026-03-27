use std::io::{Read, Write};

use thiserror::Error;

pub mod control;
pub mod guest;

pub type Result<T> = std::result::Result<T, Error>;

pub const VERSION: u32 = 1;
pub const HEADER_LEN: usize = 4;
pub const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error("frame too large: {0}")]
    FrameTooLarge(usize),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
}

pub fn write_frame(writer: &mut impl Write, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(Error::FrameTooLarge(payload.len()));
    }

    let len = u32::try_from(payload.len()).map_err(|_| Error::FrameTooLarge(payload.len()))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)?;
    Ok(())
}

pub fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header)?;

    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME_LEN {
        return Err(Error::FrameTooLarge(len));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"abc").expect("write frame");
        let mut cursor = std::io::Cursor::new(buf);
        let payload = read_frame(&mut cursor).expect("read frame");
        assert_eq!(payload, b"abc");
    }

    #[test]
    fn rejects_large_frame() {
        let payload = vec![0u8; MAX_FRAME_LEN + 1];
        let error = write_frame(&mut Vec::new(), &payload).expect_err("must reject");
        assert!(matches!(error, Error::FrameTooLarge(_)));
    }
}
