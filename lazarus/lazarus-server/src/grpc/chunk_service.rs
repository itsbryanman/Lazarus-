use lazarus_common::lazarus::agent::*;
use lazarus_core::storage::backend::StorageBackend;
use lazarus_core::storage::local::LocalStorage;
use std::path::Path;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

pub struct ChunkServiceImpl {
    storage: LocalStorage,
}

impl ChunkServiceImpl {
    pub fn new(data_dir: String) -> Self {
        let storage = LocalStorage::new(Path::new(&data_dir).join("data"));
        Self { storage }
    }
}

#[tonic::async_trait]
impl chunk_service_server::ChunkService for ChunkServiceImpl {
    async fn check_chunks_exist(
        &self,
        request: Request<tonic::Streaming<ChunkHash>>,
    ) -> Result<Response<Self::CheckChunksExistStream>, Status> {
        let mut stream = request.into_inner();
        let storage = self.storage.clone();

        let (tx, rx) = tokio::sync::mpsc::channel(128);

        tokio::spawn(async move {
            while let Ok(Some(chunk_hash)) = stream.message().await {
                let shard_dir = &chunk_hash.hash[..2];
                let key = format!("{}/{}", shard_dir, chunk_hash.hash);

                // Use `storage.get` to check existence. `get` returns an error if not found.
                let exists = storage.get(&key).await.is_ok();

                let response = ChunkExistenceResponse {
                    hash: chunk_hash.hash,
                    exists,
                };

                if tx.send(Ok(response)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        ))
    }

    type CheckChunksExistStream =
        tokio_stream::wrappers::ReceiverStream<Result<ChunkExistenceResponse, Status>>;

    async fn upload_chunk(
        &self,
        request: Request<tonic::Streaming<ChunkUpload>>,
    ) -> Result<Response<ChunkUploadResponse>, Status> {
        let mut stream = request.into_inner();
        let mut chunks_uploaded = 0;

        while let Some(chunk) = stream.message().await? {
            info!("Received chunk upload: {}", chunk.hash);
            let shard_dir = &chunk.hash[..2];
            let key = format!("{}/{}", shard_dir, chunk.hash);

            // Save the chunk using the storage backend
            if let Err(e) = self.storage.put(&key, &chunk.data).await {
                warn!("Failed to store chunk {}: {}", chunk.hash, e);
                return Ok(Response::new(ChunkUploadResponse {
                    chunks_uploaded,
                    success: false,
                }));
            } else {
                chunks_uploaded += 1;
            }
        }

        Ok(Response::new(ChunkUploadResponse {
            chunks_uploaded,
            success: true,
        }))
    }

    async fn download_chunk(
        &self,
        request: Request<ChunkDownloadRequest>,
    ) -> Result<Response<Self::DownloadChunkStream>, Status> {
        let req = request.into_inner();
        let storage = self.storage.clone();

        let (tx, rx) = tokio::sync::mpsc::channel(128);

        tokio::spawn(async move {
            let shard_dir = &req.hash[..2];
            let key = format!("{}/{}", shard_dir, req.hash);

            match storage.get(&key).await {
                Ok(data) => {
                    // Send the data in one go (for simplicity)
                    // For large chunks, this could be streamed in smaller parts
                    let _ = tx.send(Ok(ChunkData { data })).await;
                }
                Err(e) => {
                    warn!("Failed to retrieve chunk {}: {}", req.hash, e);
                    let status = Status::not_found(format!("Chunk {} not found: {}", req.hash, e));
                    let _ = tx.send(Err(status)).await;
                }
            }
        });

        Ok(Response::new(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        ))
    }

    type DownloadChunkStream = tokio_stream::wrappers::ReceiverStream<Result<ChunkData, Status>>;
}
