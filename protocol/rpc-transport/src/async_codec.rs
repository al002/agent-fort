use af_rpc_proto::codec::{decode_message, encode_message};
use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::TransportError;
use crate::frame::{FRAME_HEADER_LEN, decode_frame_len, frame_header};

pub async fn write_frame<W>(
    writer: &mut W,
    payload: &[u8],
    max_frame_len: usize,
) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin,
{
    let header = frame_header(payload.len(), max_frame_len)?;
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R>(reader: &mut R, max_frame_len: usize) -> Result<Vec<u8>, TransportError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let frame_len = decode_frame_len(header, max_frame_len)?;

    let mut payload = vec![0u8; frame_len];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

pub async fn write_message<W, M>(
    writer: &mut W,
    message: &M,
    max_frame_len: usize,
) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin,
    M: Message,
{
    let payload = encode_message(message);
    write_frame(writer, &payload, max_frame_len).await
}

pub async fn read_message<R, M>(reader: &mut R, max_frame_len: usize) -> Result<M, TransportError>
where
    R: AsyncRead + Unpin,
    M: Message + Default,
{
    let payload = read_frame(reader, max_frame_len).await?;
    let message = decode_message::<M>(&payload)?;
    Ok(message)
}
