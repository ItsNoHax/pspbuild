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

    model: Model,
}

/// The five adaptive probability tables, shared by both directions.
///
/// Encoding and decoding must adapt identically or the two desynchronise after
/// the first symbol, so they use one implementation rather than two that agree
/// by inspection.
struct Model {
    bm_literal: [[u8; 256]; 8],
    bm_dist_bits: [[u8; 39]; 8],
    bm_dist: [[u8; 8]; 18],
    bm_match: [[u8; 8]; 8],
    bm_len: [[u8; 31]; 8],
}

impl Model {
    fn new() -> Self {
        // Every entry starts at an even chance.
        Model {
            bm_literal: [[0x80; 256]; 8],
            bm_dist_bits: [[0x80; 39]; 8],
            bm_dist: [[0x80; 8]; 18],
            bm_match: [[0x80; 8]; 8],
            bm_len: [[0x80; 31]; 8],
        }
    }

    fn get(&self, table: Table, row: usize, index: usize) -> Result<u8> {
        let slot = match table {
            Table::Literal => self.bm_literal.get(row).and_then(|r| r.get(index)),
            Table::DistBits => self.bm_dist_bits.get(row).and_then(|r| r.get(index)),
            Table::Dist => self.bm_dist.get(row).and_then(|r| r.get(index)),
            Table::Match => self.bm_match.get(row).and_then(|r| r.get(index)),
            Table::Len => self.bm_len.get(row).and_then(|r| r.get(index)),
        };
        slot.copied().ok_or_else(|| {
            Error::Compression(format!(
                "LZRC stream indexes {table:?}[{row}][{index}], which is out of range"
            ))
        })
    }

    fn set(&mut self, table: Table, row: usize, index: usize, value: u8) {
        // Only ever called with indices `get` has already accepted.
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
            model: Model::new(),
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
        self.model.get(table, row, index)
    }

    fn write_prob(&mut self, table: Table, row: usize, index: usize, value: u8) {
        self.model.set(table, row, index, value);
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

/// Compress a block.
///
/// Returns the LZRC stream. The caller decides whether it is worth using —
/// NPUMDIMG stores a block raw unless compression saves enough to be worth the
/// decode cost, and a raw block is equally valid.
///
/// # This does not reproduce the reference's output
///
/// Only the *decoder* is pinned by the format. Any parse of the input into
/// literals and matches decodes to the same bytes, so an encoder is free to
/// choose differently, and this one does: the reference threads a 65280-byte
/// sliding window with its own hash chains and wraparound arithmetic, while
/// this keeps the whole block addressable and searches that. Output is
/// therefore not byte-comparable with `sign_np`'s, and comparing it would be
/// measuring a choice rather than a requirement.
///
/// What must hold is that [`decompress`] — which *is* pinned, against 4,216
/// genuine Sony blocks — reads back exactly what went in.
pub fn compress(input: &[u8]) -> Result<Vec<u8>> {
    Encoder::new(input).run()
}

/// The literal context width. The reference uses 5 and the value is written
/// into the stream, so a decoder does not need to agree in advance.
const LITERAL_CONTEXT_BITS: u8 = 5;

/// Longest match the length code can express. 255 is the end marker.
const MAX_MATCH: usize = 254;

/// Shortest run worth coding as a match rather than as literals.
const MIN_MATCH: usize = 2;

/// A match shorter than this is only worth coding when it is also close by;
/// beyond this distance the code costs more than the literals it replaces.
const SHORT_MATCH_LIMIT: usize = 4;
const SHORT_MATCH_MAX_DIST: usize = 255;

/// Positions are chained by their first three bytes.
const HASH_BITS: usize = 16;
const HASH_SIZE: usize = 1 << HASH_BITS;

/// How far back to follow a chain. Bounded so a block of repeated bytes cannot
/// turn the search quadratic.
const MAX_CHAIN: usize = 64;

struct Encoder<'a> {
    input: &'a [u8],
    in_ptr: usize,
    output: Vec<u8>,

    range: u32,
    code: u32,
    /// The byte waiting to be emitted, plus room for a carry into it.
    /// `NO_PENDING` means nothing is waiting yet.
    out_code: u32,

    model: Model,

    /// Most recent position for each three-byte hash, and the chain behind it.
    head: Vec<i32>,
    chain: Vec<i32>,
}

/// `out_code` before the first byte is staged.
const NO_PENDING: u32 = 0xFFFF_FFFF;

impl<'a> Encoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        let mut output = Vec::with_capacity(input.len() / 2 + 64);
        output.push(LITERAL_CONTEXT_BITS);

        Encoder {
            input,
            in_ptr: 0,
            output,
            range: 0xFFFF_FFFF,
            code: 0,
            out_code: NO_PENDING,
            model: Model::new(),
            head: vec![-1; HASH_SIZE],
            chain: vec![-1; input.len().max(1)],
        }
    }

    /// Stage the top byte of `code` for output, emitting the previous one and
    /// propagating any carry it picked up.
    fn normalize(&mut self) {
        if self.range >= 0x0100_0000 {
            return;
        }
        if self.out_code != NO_PENDING {
            // A carry out of the staged byte has to ripple back through the
            // bytes already written, each 0xFF becoming 0x00 in turn.
            if self.out_code > 0xFF {
                let mut p = self.output.len();
                loop {
                    p -= 1;
                    let old = self.output[p];
                    self.output[p] = old.wrapping_add(1);
                    if old != 0xFF {
                        break;
                    }
                }
            }
            self.output.push((self.out_code & 0xFF) as u8);
        }
        self.out_code = (self.code >> 24) & 0xFF;
        self.range <<= 8;
        self.code <<= 8;
    }

    /// Encode one bit against an adaptive probability, adapting it exactly as
    /// the decoder does.
    fn bit(&mut self, table: Table, row: usize, index: usize, bit: bool) -> Result<()> {
        self.normalize();

        let mut prob = self.model.get(table, row, index)?;
        let bound = (self.range >> 8) * u32::from(prob);
        prob -= prob >> 3;

        if bit {
            self.range = bound;
            prob += 31;
        } else {
            let (code, carried) = self.code.overflowing_add(bound);
            self.code = code;
            if carried {
                self.out_code = self.out_code.wrapping_add(1);
            }
            self.range -= bound;
        }
        self.model.set(table, row, index, prob);
        Ok(())
    }

    /// Emit a value through the same bit tree the decoder walks.
    fn bit_tree(
        &mut self,
        table: Table,
        row: usize,
        base: usize,
        limit: u32,
        value: u32,
    ) -> Result<()> {
        let number = value + limit;
        let mut n = 31 - number.leading_zeros();
        loop {
            let prefix = (number >> n) as usize;
            let bit = (number >> (n - 1)) & 1 == 1;
            self.bit(table, row, base + prefix, bit)?;
            n -= 1;
            if n == 0 {
                return Ok(());
            }
        }
    }

    /// Emit an `n`-bit number: the top two bits and the low three adaptively,
    /// the middle at a flat 50/50.
    fn number(&mut self, table: Table, row: usize, base: usize, n: u32, value: u32) -> Result<()> {
        let nth = |i: u32| (value >> i) & 1 == 1;
        let mut consumed = 1u32;

        if n > 3 {
            self.bit(table, row, base + 3, nth(n - consumed))?;
            consumed += 1;
            if n > 4 {
                self.bit(table, row, base + 3, nth(n - consumed))?;
                consumed += 1;
                if n > 5 {
                    self.normalize();
                    for i in 3..n - 2 {
                        self.range >>= 1;
                        // A zero bit is coded by advancing past the low half.
                        if !nth(n - i) {
                            let (code, carried) = self.code.overflowing_add(self.range);
                            self.code = code;
                            if carried {
                                self.out_code = self.out_code.wrapping_add(1);
                            }
                        }
                    }
                    consumed = n - 2;
                }
            }
        }

        if n > 0 {
            self.bit(table, row, base, nth(n - consumed))?;
            if n > 1 {
                self.bit(table, row, base + 1, nth(n - consumed - 1))?;
                if n > 2 {
                    self.bit(table, row, base + 2, nth(n - consumed - 2))?;
                }
            }
        }
        Ok(())
    }

    fn flush(&mut self) {
        self.normalize();
        self.output.push((self.out_code & 0xFF) as u8);
        self.output.push((self.code >> 24) as u8);
        self.output.push((self.code >> 16) as u8);
        self.output.push((self.code >> 8) as u8);
        self.output.push(self.code as u8);
    }

    fn hash_at(&self, pos: usize) -> usize {
        let b = &self.input[pos..];
        let v = (u32::from(b[0]) << 16) ^ (u32::from(b[1]) << 8) ^ u32::from(b[2]);
        (v.wrapping_mul(2654435761) >> (32 - HASH_BITS)) as usize
    }

    fn insert(&mut self, pos: usize) {
        if pos + 3 > self.input.len() {
            return;
        }
        let h = self.hash_at(pos);
        self.chain[pos] = self.head[h];
        self.head[h] = pos as i32;
    }

    /// Longest match for the data at `pos`, as `(length, distance)`.
    fn find_match(&self, pos: usize) -> Option<(usize, usize)> {
        let remaining = self.input.len() - pos;
        if remaining < MIN_MATCH || pos + 3 > self.input.len() {
            return None;
        }

        let limit = remaining.min(MAX_MATCH);
        let mut best_len = 0usize;
        let mut best_dist = 0usize;

        let mut candidate = self.head[self.hash_at(pos)];
        for _ in 0..MAX_CHAIN {
            if candidate < 0 {
                break;
            }
            let p = candidate as usize;
            candidate = self.chain[p];
            if p >= pos {
                break;
            }

            let mut len = 0;
            while len < limit && self.input[p + len] == self.input[pos + len] {
                len += 1;
            }
            if len > best_len {
                best_len = len;
                best_dist = pos - p;
                if len == limit {
                    break;
                }
            }
        }

        if best_len < MIN_MATCH {
            return None;
        }
        // A short match far away costs more than the literals it saves, and
        // the format's own encoder declines it for the same reason.
        if best_len < SHORT_MATCH_LIMIT && best_dist > SHORT_MATCH_MAX_DIST {
            return None;
        }
        Some((best_len, best_dist))
    }

    fn run(mut self) -> Result<Vec<u8>> {
        let mut state = 0usize;
        let mut last_byte = 0u8;

        loop {
            if self.in_ptr == self.input.len() {
                self.encode_end(state)?;
                self.flush();
                return Ok(self.output);
            }

            match self.find_match(self.in_ptr) {
                Some((len, dist)) => {
                    self.encode_match(state, len, dist)?;
                    for i in 0..len {
                        self.insert(self.in_ptr + i);
                    }
                    self.in_ptr += len;
                    state = 6 + (self.in_ptr + 1) % 2;
                }
                None => {
                    let byte = self.input[self.in_ptr];
                    self.bit(Table::Match, state, 0, false)?;
                    state = state.saturating_sub(1);

                    let context = usize::from(last_byte >> LITERAL_CONTEXT_BITS) & 0x07;
                    self.bit_tree(Table::Literal, context, 0, 0x100, u32::from(byte))?;

                    self.insert(self.in_ptr);
                    self.in_ptr += 1;
                }
            }
            last_byte = self.input[self.in_ptr - 1];
        }
    }

    /// The length prefix: a run of 1 bits saying how many length bits follow.
    fn encode_length_bits(&mut self, state: usize, coded_len: usize) -> Result<u32> {
        let mut step = 0usize;
        let mut len_bits = 0u32;
        let mut terminated = false;

        for i in 1..8 {
            step += 1;
            if coded_len < (1 << i) {
                terminated = true;
                break;
            }
            self.bit(Table::Match, state, step, true)?;
            len_bits += 1;
        }
        if terminated {
            self.bit(Table::Match, state, step, false)?;
        }
        Ok(len_bits)
    }

    fn encode_match(&mut self, state: usize, len: usize, dist: usize) -> Result<()> {
        self.bit(Table::Match, state, 0, true)?;

        // The length is coded one less than it is, so a two-byte match needs
        // no length bits at all.
        let coded_len = len - 1;
        let len_bits = self.encode_length_bits(state, coded_len)?;

        if len_bits > 0 {
            let len_state = ((len_bits - 1) << 2) + ((self.in_ptr as u32) << (len_bits - 1)) % 4;
            self.number(
                Table::Len,
                state,
                len_state as usize,
                len_bits,
                coded_len as u32,
            )?;
        }

        // Longer matches get a wider distance alphabet.
        let (dist_state, limit) = if coded_len > 2 { (7, 44) } else { (0, 8) };
        let dist_bits = 31 - (dist as u32).leading_zeros();
        self.bit_tree(
            Table::DistBits,
            len_bits as usize,
            dist_state,
            limit,
            dist_bits,
        )?;

        if dist_bits > 0 {
            self.number(Table::Dist, dist_bits as usize, 0, dist_bits, dist as u32)?;
        }
        Ok(())
    }

    /// The end of the stream is a match whose length code is 0xFF.
    fn encode_end(&mut self, state: usize) -> Result<()> {
        self.bit(Table::Match, state, 0, true)?;

        // 0xFF needs all seven length bits, so the prefix is never terminated.
        let mut step = 0usize;
        for _ in 1..8 {
            step += 1;
            self.bit(Table::Match, state, step, true)?;
        }

        let len_bits = 7u32;
        let len_state = ((len_bits - 1) << 2) + ((self.in_ptr as u32) << (len_bits - 1)) % 4;
        self.number(Table::Len, state, len_state as usize, len_bits, 0xFF)
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

    /// Anything the encoder produces must come back out of the decoder.
    ///
    /// This is the only correctness property an encoder has to satisfy, and it
    /// is a strong one here: the decoder on the other side of it is the same
    /// code that reads Sony's archives, pinned against 4,216 of their blocks.
    #[test]
    fn everything_round_trips_through_the_decoder() {
        for (name, data) in sample_inputs() {
            let packed = compress(&data).unwrap_or_else(|e| panic!("{name}: {e}"));
            let unpacked = decompress(&packed, data.len())
                .unwrap_or_else(|e| panic!("{name}: {} bytes did not decode: {e}", packed.len()));
            assert_eq!(unpacked, data, "{name} did not survive the round trip");
        }
    }

    /// Compressible input has to actually compress, or the encoder is correct
    /// and useless.
    #[test]
    fn compressible_input_gets_smaller() {
        let zeros = vec![0u8; 32768];
        let packed = compress(&zeros).unwrap();
        assert!(
            packed.len() < zeros.len() / 20,
            "32 KiB of zeros compressed to {} bytes",
            packed.len()
        );

        // Text-like data with real redundancy.
        let text = "the quick brown fox jumps over the lazy dog. "
            .repeat(700)
            .into_bytes();
        let packed = compress(&text).unwrap();
        assert!(
            packed.len() < text.len() / 8,
            "repetitive text compressed to {} of {} bytes",
            packed.len(),
            text.len()
        );
    }

    /// Incompressible input must still round-trip, even though it will grow.
    #[test]
    fn random_input_round_trips_even_though_it_grows() {
        let noise: Vec<u8> = (0..8192u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let packed = compress(&noise).unwrap();
        assert_eq!(decompress(&packed, noise.len()).unwrap(), noise);
    }

    /// A run longer than the longest codable match has to be split rather than
    /// silently truncated.
    #[test]
    fn runs_longer_than_the_maximum_match_are_split() {
        let data = vec![0xABu8; MAX_MATCH * 3 + 17];
        let packed = compress(&data).unwrap();
        assert_eq!(decompress(&packed, data.len()).unwrap(), data);
    }

    /// Overlapping matches — a run coded as a match reaching one byte back —
    /// are how the format expresses repetition, so they must survive.
    #[test]
    fn overlapping_matches_survive() {
        let mut data = vec![1u8, 2, 3];
        while data.len() < 4096 {
            let b = data[data.len() - 3];
            data.push(b);
        }
        let packed = compress(&data).unwrap();
        assert_eq!(decompress(&packed, data.len()).unwrap(), data);
    }

    fn sample_inputs() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x42]),
            ("two bytes", vec![0x42, 0x42]),
            ("three identical", vec![7u8; 3]),
            ("all zeros", vec![0u8; 32768]),
            ("all one value", vec![0xFFu8; 5000]),
            (
                "counting",
                (0..32768u32).map(|i| i as u8).collect::<Vec<u8>>(),
            ),
            ("two halves the same", {
                let half: Vec<u8> = (0..4096u32).map(|i| (i * 7) as u8).collect();
                let mut v = half.clone();
                v.extend_from_slice(&half);
                v
            }),
            ("sparse", {
                let mut v = vec![0u8; 20000];
                for i in (0..v.len()).step_by(997) {
                    v[i] = 0xA5;
                }
                v
            }),
            (
                "noise",
                (0..4096u32)
                    .map(|i| (i.wrapping_mul(1103515245).wrapping_add(12345) >> 16) as u8)
                    .collect::<Vec<u8>>(),
            ),
        ]
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
