use tokio::io::{AsyncRead, AsyncReadExt};

/// Stream chunks from an [`AsyncRead`] implementation without loading the entire input into memory.
pub struct StreamingChunker<R> {
    reader: R,
    chunk_size: usize,
}

impl<R: AsyncRead + Unpin> StreamingChunker<R> {
    pub fn new(reader: R, chunk_size: usize) -> Self {
        assert!(chunk_size > 0, "chunk size must be non-zero");
        Self { reader, chunk_size }
    }

    /// Read the next chunk from the underlying reader. Returns `Ok(None)` when EOF is reached.
    pub async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let mut buffer = vec![0u8; self.chunk_size];
        let read = self.reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.truncate(read);
        Ok(Some(buffer))
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}
