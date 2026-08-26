//! LZRC decompression.
//!
//! The compression NPUMDIMG applies to a block before encrypting it: LZ77
//! matches coded with an adaptive binary range coder, in the same family as
//! LZMA but with its own model layout and its own irregularities.
//!
//! # Scope: decompression only
//!
//! Reading an archive needs the decoder. Writing one does not need the
//! encoder: compression is optional and per block, and a block stored raw is
//! as valid as a compressed one — the reference implementation itself falls
//! back to raw whenever compression saves less than 10%. An encoder would only
//! make archives smaller, so it is a size optimisation rather than a
//! correctness requirement, and it is not implemented here.
//!
//! # Format
//!
//! ```text
//! 0x00  u8       lc      literal context bits; bit 7 set means "stored raw"
//! 0x01  u32be    code    initial range-coder code, or the length when raw
//! 0x05  ...      the coded stream, or the raw bytes
//! ```
//!
//! # The model
//!
//! Five adaptive probability tables, every entry starting at 0x80 — an even
//! chance — and moving toward whichever bit is actually seen:
//!
//! | table | shape | selects on |
//! | --- | --- | --- |
//! | `bm_literal` | 8 × 256 | high bits of the previous byte, then a bit tree |
//! | `bm_match` | 8 × 8 | coder state, then how many length bits follow |
//! | `bm_len` | 8 × 31 | coder state and a position-dependent slot |
//! | `bm_dist_bits` | 8 × 39 | the length-bit count |
//! | `bm_dist` | 18 × 8 | the distance-bit count |
//!
//! # Where the reference reads out of bounds
//!
//! Two index computations in the reference can exceed the array they index,
//! running into whichever table follows in memory. Both need a match distance
//! of at least a megabyte to trigger, and a block is 32 KiB, so neither is
//! reachable from a well-formed stream — but a corrupt one could reach both.
//!
//! This implementation returns an error there instead. That is a deliberate
//! divergence: reproducing the reference exactly would mean reproducing a
//! buffer overrun, and the only inputs that tell the two apart are inputs no
//! valid archive contains.

use crate::error::{Error, Result};

/// Bit 7 of `lc` marks a block that was stored rather than compressed.
const STORED_FLAG: u8 = 0x80;

/// Bytes of header before the coded stream.
const HEADER_LEN: usize = 5;

/// The length code that ends a stream.
const END_MARKER: i32 = 0xFF;

/// Decompress an LZRC block.
///
/// `out_len` is the exact size the block is expected to expand to, which the
/// caller knows from the archive's geometry rather than from the stream.
pub fn decompress(input: &[u8], out_len: usize) -> Result<Vec<u8>> {
    if input.len() < HEADER_LEN {
        return Err(Error::TooShort {
            expected: HEADER_LEN,
            actual: input.len(),
        });
    }

    let lc = input[0];
    let code = u32::from_be_bytes(input[1..5].try_into().expect("4 bytes"));

    // A stored block carries its length where a compressed one carries the
    // coder's initial code.
    if lc & STORED_FLAG != 0 {
        let len = code as usize;
        let end = HEADER_LEN.checked_add(len).ok_or_else(|| {
            Error::Compression("stored LZRC block declares an impossible length".into())
        })?;
        if end > input.len() || len > out_len {
            return Err(Error::Compression(format!(
                "stored LZRC block declares {len} bytes, with {} available and room for {out_len}",
                input.len() - HEADER_LEN
            )));
        }
        return Ok(input[HEADER_LEN..end].to_vec());
    }

    Decoder::new(lc, code, &input[HEADER_LEN..], out_len).run()
}

/// Adaptive probability tables, plus the range coder's state.
struct Decoder<'a> {
    input: &'a [u8],
    in_ptr: usize,
    output: Vec<u8>,
    out_len: usize,

    range: u32,
    code: u32,
    lc: u8,

    bm_literal: [[u8; 256]; 8],
    bm_dist_bits: [[u8; 39]; 8],
    bm_dist: [[u8; 8]; 18],
    bm_match: [[u8; 8]; 8],
    bm_len: [[u8; 31]; 8],
}

impl<'a> Decoder<'a> {
    fn new(lc: u8, code: u32, input: &'a [u8], out_len: usize) -> Self {
        Decoder {
            input,
            in_ptr: 0,
            output: Vec::with_capacity(out_len),
            out_len,
            range: 0xFFFF_FFFF,
            code,
            lc,
            bm_literal: [[0x80; 256]; 8],
            bm_dist_bits: [[0x80; 39]; 8],
            bm_dist: [[0x80; 8]; 18],
            bm_match: [[0x80; 8]; 8],
            bm_len: [[0x80; 31]; 8],
        }
    }

    /// Pull the next byte into the coder's window.
    ///
    /// The reference reads the input here without a bounds check. A range
    /// coder legitimately reads a little beyond the bytes that encode the
    /// final symbol, so running off the end is not by itself corruption;
    /// feeding zeros is the conventional way to handle it and keeps a valid
    /// stream decoding while leaving the output-length check to catch a
    /// genuinely truncated one.
    fn next_byte(&mut self) -> u8 {
        let byte = self.input.get(self.in_ptr).copied().unwrap_or(0);
        self.in_ptr += 1;
        byte
    }

    fn normalize(&mut self) {
        if self.range < 0x0100_0000 {
            self.range <<= 8;
            let byte = self.next_byte();
            self.code = (self.code << 8).wrapping_add(u32::from(byte));
        }
    }

    /// Decode one bit against an adaptive probability, and adapt it.
    ///
    /// The probability moves down by a eighth on every use and back up by 31
    /// when the bit turns out to be 1, so a table entry tracks how often that
    /// context has produced a 1.
    fn bit(&mut self, prob: &mut u8) -> u32 {
        self.normalize();

        let bound = (self.range >> 8) * u32::from(*prob);
        *prob -= *prob >> 3;

        if self.code < bound {
            self.range = bound;
            *prob += 31;
            1
        } else {
            self.code -= bound;
            self.range -= bound;
            0
        }
    }

    /// Walk a binary tree of probabilities until the accumulated index passes
    /// `limit`. Returns that index, which the caller offsets by `limit`.
    fn bit_tree(&mut self, table: Table, row: usize, base: usize, limit: u32) -> Result<u32> {
        let mut number = 1u32;
        loop {
            let index = base + number as usize;
            let mut prob = self.read_prob(table, row, index)?;
            let bit = self.bit(&mut prob);
            self.write_prob(table, row, index, prob);

            number = (number << 1) + bit;
            if number >= limit {
                return Ok(number);
            }
        }
    }

    /// Decode an `n`-bit number: the low three bits and the top two come from
    /// adaptive probabilities, everything between is read at a flat 50/50.
    fn number(&mut self, table: Table, row: usize, base: usize, n: u32) -> Result<u32> {
        let mut number = 1u32;

        if n > 3 {
            number = (number << 1) + self.adaptive_bit(table, row, base + 3)?;
            if n > 4 {
                number = (number << 1) + self.adaptive_bit(table, row, base + 3)?;
                if n > 5 {
                    // The middle bits are direct: no context, no adaptation,
                    // and — as in the reference — no renormalisation inside
                    // this loop, only the one before it.
                    self.normalize();
                    for _ in 0..n - 5 {
                        self.range >>= 1;
                        number <<= 1;
                        if self.code < self.range {
                            number += 1;
                        } else {
                            self.code -= self.range;
                        }
                    }
                }
            }
        }

        if n > 0 {
            number = (number << 1) + self.adaptive_bit(table, row, base)?;
            if n > 1 {
                number = (number << 1) + self.adaptive_bit(table, row, base + 1)?;
                if n > 2 {
                    number = (number << 1) + self.adaptive_bit(table, row, base + 2)?;
                }
            }
        }

        Ok(number)
    }

    fn adaptive_bit(&mut self, table: Table, row: usize, index: usize) -> Result<u32> {
        let mut prob = self.read_prob(table, row, index)?;
        let bit = self.bit(&mut prob);
        self.write_prob(table, row, index, prob);
        Ok(bit)
    }

    fn read_prob(&self, table: Table, row: usize, index: usize) -> Result<u8> {
        let slot = match table {
            Table::Literal => self.bm_literal.get(row).and_then(|r| r.get(index)),
            Table::DistBits => self.bm_dist_bits.get(row).and_then(|r| r.get(index)),
            Table::Dist => self.bm_dist.get(row).and_then(|r| r.get(index)),
            Table::Match => self.bm_match.get(row).and_then(|r| r.get(index)),
            Table::Len => self.bm_len.get(row).and_then(|r| r.get(index)),
        };
        slot.copied().ok_or_else(|| {
            Error::Compression(format!(
                "LZRC stream indexes {table:?}[{row}][{index}], which is out of range; \
                 the stream is corrupt"
            ))
        })
    }

    fn write_prob(&mut self, table: Table, row: usize, index: usize, value: u8) {
        // Only ever called with indices `read_prob` has already accepted.
        let slot = match table {
            Table::Literal => self.bm_literal.get_mut(row).and_then(|r| r.get_mut(index)),
            Table::DistBits => self
                .bm_dist_bits
                .get_mut(row)
                .and_then(|r| r.get_mut(index)),
            Table::Dist => self.bm_dist.get_mut(row).and_then(|r| r.get_mut(index)),
            Table::Match => self.bm_match.get_mut(row).and_then(|r| r.get_mut(index)),
            Table::Len => self.bm_len.get_mut(row).and_then(|r| r.get_mut(index)),
        };
        if let Some(slot) = slot {
            *slot = value;
        }
    }

    fn put(&mut self, byte: u8) -> Result<()> {
        if self.output.len() == self.out_len {
            return Err(Error::Compression(
                "LZRC stream produces more output than the block can hold".into(),
            ));
        }
        self.output.push(byte);
        Ok(())
    }

    fn run(mut self) -> Result<Vec<u8>> {
        let mut state = 0usize;
        let mut last_byte = 0u8;

        while self.output.len() < self.out_len {
            let mut step = 0usize;

            if self.adaptive_bit(Table::Match, state, step)? == 0 {
                // A literal. The context is the top bits of the previous byte.
                state = state.saturating_sub(1);

                let context =
                    usize::from(last_byte.checked_shr(u32::from(self.lc)).unwrap_or(0)) & 0x07;
                let byte = self.bit_tree(Table::Literal, context, 0, 0x100)? - 0x100;
                self.put(byte as u8)?;
            } else {
                // A match. Its length is coded as a count of bits followed by
                // that many bits.
                let mut len_bits = 0u32;
                for _ in 0..7 {
                    step += 1;
                    if self.adaptive_bit(Table::Match, state, step)? == 0 {
                        break;
                    }
                    len_bits += 1;
                }

                let match_len = if len_bits == 0 {
                    1
                } else {
                    let out_ptr = self.output.len() as u32;
                    let len_state = ((len_bits - 1) << 2) + ((out_ptr << (len_bits - 1)) & 0x03);
                    let len = self.number(Table::Len, state, len_state as usize, len_bits)? as i32;
                    if len == END_MARKER {
                        return Ok(self.output);
                    }
                    len as u32
                };

                // Longer matches get a wider distance alphabet.
                let (dist_state, limit) = if match_len > 2 { (7, 44) } else { (0, 8) };
                let dist_bits =
                    self.bit_tree(Table::DistBits, len_bits as usize, dist_state, limit)? - limit;

                let match_dist = if dist_bits > 0 {
                    self.number(Table::Dist, dist_bits as usize, 0, dist_bits)?
                } else {
                    1
                };

                let out_ptr = self.output.len();
                if match_dist as usize > out_ptr || match_dist == 0 {
                    return Err(Error::Compression(format!(
                        "LZRC match reaches {match_dist} bytes back with only {out_ptr} decoded"
                    )));
                }

                // Copied one byte at a time on purpose: a match may overlap
                // itself, reading bytes this very loop is writing, which is how
                // a run is encoded. Anything that copies the source as a slice
                // first would silently mis-decode those.
                let start = out_ptr - match_dist as usize;
                for src in (start..).take(match_len as usize + 1) {
                    let byte = self.output[src];
                    self.put(byte)?;
                }

                state = 6 + (self.output.len() + 1) % 2;
            }

            last_byte = *self.output.last().expect("a round always emits a byte");
        }

        Ok(self.output)
    }
}

/// Which probability table an index refers to.
#[derive(Debug, Clone, Copy)]
enum Table {
    Literal,
    DistBits,
    Dist,
    Match,
    Len,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_block_is_copied_out() {
        let mut input = vec![0x80, 0, 0, 0, 4];
        input.extend_from_slice(b"data");
        assert_eq!(decompress(&input, 4).unwrap(), b"data");
    }

    #[test]
    fn a_stored_block_that_overruns_its_input_is_refused() {
        let input = vec![0x80, 0, 0, 0x10, 0, 1, 2, 3];
        assert!(decompress(&input, 65536).is_err());
    }

    #[test]
    fn a_stored_block_larger_than_the_output_is_refused() {
        let mut input = vec![0x80, 0, 0, 0, 8];
        input.extend_from_slice(b"12345678");
        assert!(decompress(&input, 4).is_err());
    }

    #[test]
    fn a_truncated_header_is_an_error_not_a_panic() {
        for len in 0..HEADER_LEN {
            assert!(decompress(&vec![0u8; len], 100).is_err(), "len {len}");
        }
    }

    /// Whatever the stream says, the decoder must not run past the block size
    /// it was given or panic on malformed input.
    #[test]
    fn arbitrary_input_never_panics_or_overruns() {
        for seed in 0..64u32 {
            let input: Vec<u8> = (0..256u32)
                .map(|i| (i.wrapping_mul(2654435761).wrapping_add(seed) >> 13) as u8)
                .collect();
            for out_len in [0usize, 1, 16, 4096] {
                if let Ok(out) = decompress(&input, out_len) {
                    assert!(out.len() <= out_len, "seed {seed} overran");
                }
            }
        }
    }
}
