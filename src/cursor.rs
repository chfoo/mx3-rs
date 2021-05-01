pub struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub fn read(&mut self, dest_buffer: &mut [u8]) -> usize {
        let mut bytes_read = 0usize;

        #[allow(clippy::needless_range_loop)]
        for dest_index in 0..dest_buffer.len() {
            if self.position < self.data.len() {
                dest_buffer[dest_index] = self.data[self.position];
                bytes_read += 1;
                self.position += 1;
            } else {
                break;
            }
        }

        bytes_read
    }

    pub fn read_exact(&mut self, dest_buffer: &mut [u8]) -> Result<usize, usize> {
        let bytes_read = self.read(dest_buffer);

        if bytes_read == dest_buffer.len() {
            Ok(bytes_read)
        } else {
            Err(bytes_read)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cursor_read() {
        let data = b"Hello world";
        let mut cursor = Cursor::new(data);

        let mut buffer = [0u8; 5];
        assert_eq!(cursor.read(&mut buffer), 5);
        assert_eq!(&buffer, b"Hello");

        assert_eq!(cursor.read(&mut buffer), 5);
        assert_eq!(&buffer, b" worl");

        assert_eq!(cursor.read(&mut buffer), 1);
        assert_eq!(&buffer, b"dworl");
    }

    #[test]
    fn test_cursor_read_exact() {
        let data = b"Hello world";
        let mut cursor = Cursor::new(data);

        let mut buffer = [0u8; 5];
        assert_eq!(cursor.read(&mut buffer), 5);
        assert_eq!(&buffer, b"Hello");

        assert_eq!(cursor.read_exact(&mut buffer), Ok(5));
        assert_eq!(&buffer, b" worl");

        assert_eq!(cursor.read_exact(&mut buffer), Err(1));
    }
}
