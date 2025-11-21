/// Content-Defined Chunking (CDC) implementation using FastCDC algorithm
/// This provides variable-size chunking for better deduplication compared to fixed-size chunking

const MIN_CHUNK_SIZE: usize = 2 * 1024; // 2KB
const AVG_CHUNK_SIZE: usize = 8 * 1024; // 8KB
const MAX_CHUNK_SIZE: usize = 16 * 1024; // 16KB

const MASK_S: u64 = 0x0003590703530000;
const MASK_L: u64 = 0x0000d90003530000;

pub struct CdcChunker<'a> {
    data: &'a [u8],
    position: usize,
    mask: u64,
}

impl<'a> CdcChunker<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self::with_sizes(data, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE)
    }

    pub fn with_sizes(data: &'a [u8], _min_size: usize, avg_size: usize, _max_size: usize) -> Self {
        // Select mask based on average chunk size
        let mask = if avg_size <= 4 * 1024 { MASK_S } else { MASK_L };

        Self {
            data,
            position: 0,
            mask,
        }
    }

    fn find_chunk_boundary(&self, start: usize, min_size: usize, max_size: usize) -> usize {
        if start + min_size >= self.data.len() {
            return self.data.len();
        }

        let search_start = start + min_size;
        let search_end = (start + max_size).min(self.data.len());

        let mut hash: u64 = 0;
        let window_start = search_start.saturating_sub(64);

        // Initialize rolling hash
        for i in window_start..search_start {
            if i < self.data.len() {
                hash = hash
                    .wrapping_shl(1)
                    .wrapping_add(GEAR[self.data[i] as usize]);
            }
        }

        // Find boundary using rolling hash
        for i in search_start..search_end {
            hash = hash
                .wrapping_shl(1)
                .wrapping_add(GEAR[self.data[i] as usize]);

            if (hash & self.mask) == 0 {
                return i + 1;
            }
        }

        search_end
    }
}

impl<'a> Iterator for CdcChunker<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.data.len() {
            return None;
        }

        let mut chunk_end = self.find_chunk_boundary(self.position, MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);

        // Attempt to keep the trailing chunk within the desired bounds. When the remainder is
        // too small we either absorb it into the current chunk (if doing so keeps us under the
        // maximum size) or move the boundary backward so the remainder grows to the minimum.
        let chunk_len = chunk_end - self.position;
        let remainder = self.data.len().saturating_sub(chunk_end);
        if remainder > 0 && remainder < MIN_CHUNK_SIZE {
            if chunk_len + remainder <= MAX_CHUNK_SIZE {
                chunk_end = self.data.len();
            } else {
                let shortage = MIN_CHUNK_SIZE - remainder;
                chunk_end -= shortage;
            }
        }

        let chunk = &self.data[self.position..chunk_end];
        self.position = chunk_end;

        Some(chunk)
    }
}

// Gear hash table for rolling hash (simplified version)
const GEAR: [u64; 252] = [
    0x5c95c078, 0x22408989, 0x2d48a214, 0x12842087, 0x530f8afb, 0x474536b9, 0x2963b4f1, 0x44cb738b,
    0x4ea7403d, 0x4d606b6e, 0x074ec5d3, 0x3af39d18, 0x726003ca, 0x37a62a74, 0x51a2f58e, 0x7506358e,
    0x5d4ab128, 0x4d4ae17b, 0x41e85924, 0x470c36f7, 0x4741cade, 0x01e0dc5c, 0x3f1d9f0a, 0x5c9e72fc,
    0x6c46b90e, 0x5afa3e0b, 0x6f1f9823, 0x2e59b392, 0x1d50712d, 0x5e9b5623, 0x1e4cc50f, 0x2887e65b,
    0x45e5d58d, 0x1c818917, 0x4ef66d54, 0x6ae3c37f, 0x1f24b7a3, 0x3a15b507, 0x5e99ebc7, 0x1f0c9d53,
    0x0df0b6a6, 0x7f0c8b2f, 0x50e83f12, 0x218c0b78, 0x5d55f4a0, 0x3c87c926, 0x5984b06e, 0x7e6b1a7e,
    0x1fab891d, 0x77af7d9f, 0x5cefe1da, 0x229ff0d8, 0x1a8e3e4d, 0x1e52ff8e, 0x3f0f822d, 0x5c656895,
    0x0b654598, 0x76cbef15, 0x6e5d0ba9, 0x00e6f096, 0x02a6b7a5, 0x2dbfea28, 0x738dd94e, 0x5349e3bc,
    0x13c8e77a, 0x42f0f8b7, 0x42af1e0c, 0x5fd9d5c6, 0x408c0e6a, 0x0be1f1a8, 0x3a1f5b56, 0x5a9d8a02,
    0x03ec0689, 0x2d8f6ad9, 0x4d0a5246, 0x66e25e18, 0x5b4e2d51, 0x7cfe4c48, 0x627e5c99, 0x2e13b9ee,
    0x7aacfd74, 0x5d05b4af, 0x01f0e7aa, 0x0b9ea743, 0x37a4c6b8, 0x51e71693, 0x40e82a1a, 0x218d16bf,
    0x71d79b8e, 0x49e9fc88, 0x71af8403, 0x7c26940c, 0x1f6a0eb3, 0x0933eb5d, 0x34aa65a2, 0x588c1fb9,
    0x7ff35a23, 0x15f48aad, 0x3dca3c61, 0x08b80f4d, 0x7a0d4887, 0x2e53e428, 0x0a156c8f, 0x3e2dd77f,
    0x7cd9b5c7, 0x1bd23bd9, 0x6829ce09, 0x19abf9e8, 0x1a0fa0df, 0x3e1e95a9, 0x47f77cc1, 0x3ef8c68f,
    0x5c8b6d04, 0x69dda3af, 0x7c26ce46, 0x77df7e5e, 0x66116e58, 0x5f80bb88, 0x091e6d44, 0x5cdad5a2,
    0x57c2d4b0, 0x27fcb732, 0x25f8cc6d, 0x3f1e0d9d, 0x0c53cb09, 0x1e877d7d, 0x49c44630, 0x74ed97a5,
    0x2e4b8a0a, 0x5eca5f18, 0x7e39d43d, 0x1a92cfd0, 0x6bb59d71, 0x6de0fb37, 0x4f85eb83, 0x68e4c3f3,
    0x4d3c6dbd, 0x2f34e32e, 0x3e8c6c23, 0x45bbdee5, 0x7b59e6ce, 0x5ec3a41e, 0x20a7f7b4, 0x0bad9395,
    0x43d4cb8a, 0x6f0f1c9a, 0x1e8f4a14, 0x14b1859f, 0x53c5cfeb, 0x0e95af51, 0x33b23d48, 0x19c9eb88,
    0x3fcdbaf3, 0x4c5c8584, 0x3b48f727, 0x5cd30f69, 0x26f9d6ca, 0x08b97a93, 0x46b8e0c2, 0x2c5a0f59,
    0x31cd37a0, 0x1e9b2669, 0x5c6c2e9e, 0x0f3a49d6, 0x77a71b1c, 0x5e0bb6fa, 0x5fc9e8c4, 0x28b2f3c9,
    0x5f21a1c3, 0x15cde79e, 0x71ef3d4b, 0x67129a6b, 0x72e58a2f, 0x4aef75c0, 0x24eacbfc, 0x08e20fc7,
    0x51c07b6d, 0x6858e1c2, 0x0aa2ddaf, 0x1b12c9c0, 0x01da6b38, 0x09d4b410, 0x4b1c46ee, 0x4f95c7c1,
    0x23784300, 0x3bee0317, 0x38e8ec22, 0x1c8cdd8e, 0x0a71a03f, 0x7e02cdc5, 0x07c9e53c, 0x12ec1e9a,
    0x31c7b0f7, 0x5a9d0e8c, 0x4e2b0bb7, 0x29ed5b31, 0x5a26cbb9, 0x1ddd67d7, 0x4e8e3f15, 0x07de7ab1,
    0x56c7dd77, 0x49e6d6f0, 0x74be6088, 0x5f9e9f11, 0x68f1e47b, 0x60cbe1b7, 0x40e08495, 0x1a3d5fcf,
    0x2e7f8f7a, 0x5f3cf80c, 0x5bd4fa0f, 0x1f3ebb7d, 0x33a5c2f8, 0x52a3e7db, 0x1bca4f31, 0x2b8c7ec2,
    0x0dab54f5, 0x1e99bb78, 0x33c93e26, 0x5e9c0d4d, 0x3e13dbe1, 0x11638903, 0x5984e79f, 0x5fc4ea18,
    0x746b4fca, 0x7ae77e7f, 0x32c5a60d, 0x0a08e8f0, 0x3cafd0c7, 0x7dc50e90, 0x1a0ec9dd, 0x599ffc82,
    0x7f38ea1a, 0x22b89cb5, 0x25b3c4f9, 0x4fd8d4d0, 0x780cfbdf, 0x09f9f4c3, 0x7cb90cd7, 0x4c85a1e0,
    0x5db3c8c1, 0x0930f038, 0x65ed17b8, 0x24e11a8f, 0x6a60ef01, 0x3f6d0e05, 0x3cd6d41f, 0x07bfd41b,
    0x41cb4bd3, 0x52fb60b8, 0x0f84c2e0, 0x0b2e0e49,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdc_chunking() {
        let data = vec![0u8; 100_000]; // 100KB of zeros
        let chunker = CdcChunker::new(&data);

        let chunks: Vec<_> = chunker.collect();

        // Should produce multiple chunks
        assert!(chunks.len() > 1);

        // Each chunk should be within bounds
        for chunk in &chunks {
            assert!(chunk.len() >= MIN_CHUNK_SIZE || chunk.len() == data.len());
            assert!(chunk.len() <= MAX_CHUNK_SIZE || chunk.len() == data.len());
        }

        // All chunks combined should equal original data
        let total_len: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total_len, data.len());
    }

    #[test]
    fn test_cdc_deterministic() {
        let data = vec![42u8; 50_000];

        let chunker1 = CdcChunker::new(&data);
        let chunks1: Vec<_> = chunker1.collect();

        let chunker2 = CdcChunker::new(&data);
        let chunks2: Vec<_> = chunker2.collect();

        // Same input should produce same chunks
        assert_eq!(chunks1.len(), chunks2.len());
        for (c1, c2) in chunks1.iter().zip(chunks2.iter()) {
            assert_eq!(c1.len(), c2.len());
        }
    }
}
