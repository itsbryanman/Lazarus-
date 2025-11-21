use crate::error::{LazarusError, Result};
use zstd::stream::decode_all as zstd_decode;
use zstd::stream::encode_all as zstd_encode;

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
const JPEG_MAGIC: &[u8] = b"\xFF\xD8\xFF";
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
const HEADER_MAGIC: &[u8] = b"LZC1";
const FLAG_RAW: u8 = 0;
const FLAG_ZSTD: u8 = 1;
const ZSTD_LEVEL: i32 = 3;

/// Return true if the provided data should be compressed with zstd.
pub fn should_compress(data: &[u8]) -> bool {
    if data.len() >= PNG_MAGIC.len() && data.starts_with(PNG_MAGIC) {
        return false;
    }
    if data.len() >= JPEG_MAGIC.len() && data.starts_with(JPEG_MAGIC) {
        return false;
    }
    if data.len() >= ZIP_MAGIC.len() && data.starts_with(ZIP_MAGIC) {
        return false;
    }
    true
}

/// Encode a chunk of data, optionally compressing it with zstd. The returned buffer includes a
/// magic header and encoding flag so decoders can determine how to restore the original bytes.
pub fn encode_chunk(chunk: &[u8]) -> Result<Vec<u8>> {
    let compress = should_compress(chunk);
    let (flag, payload) = if compress {
        (
            FLAG_ZSTD,
            zstd_encode(chunk, ZSTD_LEVEL)
                .map_err(|e| LazarusError::Storage(format!("Compression failed: {}", e)))?,
        )
    } else {
        (FLAG_RAW, chunk.to_vec())
    };

    let mut buffer = Vec::with_capacity(HEADER_MAGIC.len() + 1 + payload.len());
    buffer.extend_from_slice(HEADER_MAGIC);
    buffer.push(flag);
    buffer.extend_from_slice(&payload);
    Ok(buffer)
}

/// Decode a chunk previously produced by `encode_chunk`. Older repositories without a header are
/// assumed to be zstd-compressed.
pub fn decode_chunk(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.starts_with(HEADER_MAGIC) {
        if payload.len() <= HEADER_MAGIC.len() {
            return Err(LazarusError::Storage(
                "Chunk header missing encoding flag".to_string(),
            ));
        }
        let flag = payload[HEADER_MAGIC.len()];
        let body = &payload[HEADER_MAGIC.len() + 1..];
        match flag {
            FLAG_RAW => Ok(body.to_vec()),
            FLAG_ZSTD => zstd_decode(body)
                .map_err(|e| LazarusError::Storage(format!("Decompression failed: {}", e))),
            _ => Err(LazarusError::Storage(format!(
                "Unknown compression flag: {}",
                flag
            ))),
        }
    } else {
        zstd_decode(payload)
            .map_err(|e| LazarusError::Storage(format!("Legacy chunk decode failed: {}", e)))
    }
}
