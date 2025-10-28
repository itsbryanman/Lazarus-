pub struct FixedSizeChunker<'a> {
    data: &'a [u8],
    chunk_size: usize,
    current_pos: usize,
}

impl<'a> FixedSizeChunker<'a> {
    pub fn new(data: &'a [u8], chunk_size: usize) -> Self {
        FixedSizeChunker {
            data,
            chunk_size,
            current_pos: 0,
        }
    }
}

impl<'a> Iterator for FixedSizeChunker<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_pos >= self.data.len() {
            return None;
        }

        let end = std::cmp::min(self.current_pos + self.chunk_size, self.data.len());
        let chunk = &self.data[self.current_pos..end];
        self.current_pos = end;
        Some(chunk)
    }
}
