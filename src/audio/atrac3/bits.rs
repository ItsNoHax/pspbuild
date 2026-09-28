//! MSB-first bit reading and writing over a frame's bytes.

use super::tables::{VLC_LENGTHS, canonical_codes};

/// Ran past the end of the bits available to a sound unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overrun;

/// Reads bits most significant first.
pub struct BitReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BitReader { data, position: 0 }
    }

    /// Bits consumed so far.
    pub fn position(&self) -> usize {
        self.position
    }

    pub fn bit(&mut self) -> Result<u32, Overrun> {
        let byte = *self.data.get(self.position / 8).ok_or(Overrun)?;
        let bit = (byte >> (7 - self.position % 8)) & 1;
        self.position += 1;
        Ok(u32::from(bit))
    }

    pub fn bits(&mut self, count: u32) -> Result<u32, Overrun> {
        let mut value = 0;
        for _ in 0..count {
            value = (value << 1) | self.bit()?;
        }
        Ok(value)
    }

    /// A two's-complement signed value of `count` bits.
    pub fn signed(&mut self, count: u32) -> Result<i32, Overrun> {
        let raw = self.bits(count)? as i32;
        let shift = 32 - count;
        Ok((raw << shift) >> shift)
    }
}

/// Writes bits most significant first.
#[derive(Default)]
pub struct BitWriter {
    bytes: Vec<u8>,
    length: usize,
}

impl BitWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, value: u32, count: u32) {
        for i in (0..count).rev() {
            if self.length.is_multiple_of(8) {
                self.bytes.push(0);
            }
            let bit = ((value >> i) & 1) as u8;
            let last = self.bytes.last_mut().expect("pushed above");
            *last |= bit << (7 - self.length % 8);
            self.length += 1;
        }
    }

    pub fn put_signed(&mut self, value: i32, count: u32) {
        self.put((value as u32) & ((1u32 << count) - 1), count);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Decoding tables for the seven spectral Huffman codes.
pub struct VlcTables {
    /// Per table: `(code, length, symbol)` sorted by length, for a simple
    /// bit-at-a-time canonical decode.
    tables: Vec<Vec<(u32, u8, usize)>>,
    /// Per table: `(code, length)` indexed by symbol, for encoding.
    codes: Vec<Vec<(u32, u8)>>,
}

impl VlcTables {
    pub fn new() -> Self {
        let codes: Vec<_> = VLC_LENGTHS.iter().map(|l| canonical_codes(l)).collect();
        let tables = codes
            .iter()
            .map(|table| {
                let mut entries: Vec<_> = table
                    .iter()
                    .enumerate()
                    .map(|(symbol, &(code, length))| (code, length, symbol))
                    .collect();
                entries.sort_by_key(|&(code, length, _)| (length, code));
                entries
            })
            .collect();
        VlcTables { tables, codes }
    }

    /// Read one symbol of the table for `selector` (1 to 7).
    pub fn read(&self, reader: &mut BitReader<'_>, selector: usize) -> Result<usize, Overrun> {
        let table = &self.tables[selector - 1];
        let mut code = 0u32;
        let mut length = 0u8;
        for &(entry_code, entry_length, symbol) in table {
            while length < entry_length {
                code = (code << 1) | reader.bit()?;
                length += 1;
            }
            if code == entry_code {
                return Ok(symbol);
            }
        }
        // Unreachable for a complete code, which every table is.
        Err(Overrun)
    }

    /// The code for `symbol` under `selector`.
    pub fn code(&self, selector: usize, symbol: usize) -> (u32, u8) {
        self.codes[selector - 1][symbol]
    }
}

impl Default for VlcTables {
    fn default() -> Self {
        Self::new()
    }
}

/// The tables, built once.
pub fn vlc_tables() -> &'static VlcTables {
    static TABLES: std::sync::OnceLock<VlcTables> = std::sync::OnceLock::new();
    TABLES.get_or_init(VlcTables::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_round_trip() {
        let mut w = BitWriter::new();
        w.put(0b101, 3);
        w.put_signed(-3, 4);
        w.put(0x28, 6);
        w.put(1, 1);
        let bytes = w.into_bytes();
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.bits(3), Ok(0b101));
        assert_eq!(r.signed(4), Ok(-3));
        assert_eq!(r.bits(6), Ok(0x28));
        assert_eq!(r.bit(), Ok(1));
    }

    #[test]
    fn every_symbol_decodes_to_itself() {
        let tables = vlc_tables();
        for selector in 1..=7 {
            let mut w = BitWriter::new();
            let n = VLC_LENGTHS[selector - 1].len();
            for symbol in 0..n {
                let (code, length) = tables.code(selector, symbol);
                w.put(code, u32::from(length));
            }
            let bytes = w.into_bytes();
            let mut r = BitReader::new(&bytes);
            for symbol in 0..n {
                assert_eq!(tables.read(&mut r, selector), Ok(symbol));
            }
        }
    }
}
