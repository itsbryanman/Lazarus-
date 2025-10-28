use crate::proto::*;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

pub struct ChunkServiceImpl {
    data_dir: String,
}

impl ChunkServiceImpl {
    pub fn new(data_dir: String) -> Self {
        Self { data_dir }
    }
}

#[tonic::async_trait]
impl chunk_service_server::ChunkService for ChunkServiceImpl {
    async fn check_chunks_exist(
        &self,
        request: Request<tonic::Streaming<ChunkHash>>,
    ) -> Result<Response<Self::CheckChunksExistStream>, Status> {
        let mut stream = request.into_inner();

        let (tx, rx) = tokio::sync::mpsc::channel(128);

        tokio::spawn(async move {
            while let Ok(Some(chunk_hash)) = stream.message().await {
                // In a real implementation, check if chunk exists in storage
                let exists = false; // Placeholder

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
            // In a real implementation, save chunk to storage
            chunks_uploaded += 1;
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
        let _req = request.into_inner();

        // In a real implementation, read chunk from storage
        warn!("Chunk download not yet fully implemented");

        let (tx, rx) = tokio::sync::mpsc::channel(128);

        tokio::spawn(async move {
            // Placeholder
            let _ = tx.send(Ok(ChunkData { data: vec![] })).await;
        });

        Ok(Response::new(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        ))
    }

    type DownloadChunkStream = tokio_stream::wrappers::ReceiverStream<Result<ChunkData, Status>>;
}
