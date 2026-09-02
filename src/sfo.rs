//! `PARAM.SFO`, the PSP's parameter table.
//!
//! Every PBP carries one. It is a flat key/value store the firmware reads to
//! decide what the container is and whether it may be launched at all — most
//! importantly `CATEGORY`, which selects the security pipeline (see
//! [`Category`]).
//!
//! ```text
//! 0x00  magic "\0PSF"
//! 0x04  version                  0x00000101
//! 0x08  key_table_start          offset of the key table
//! 0x0C  data_table_start         offset of the data table
//! 0x10  entry_count
//! 0x14  index[entry_count]       16 bytes each
//! ```
//!
//! Each index entry is:
//!
//! ```text
//! 0x00  u16  key_offset          relative to key_table_start
//! 0x02  u16  format              0x0004 raw, 0x0204 UTF-8, 0x0404 u32
//! 0x04  u32  data_len            bytes actually used
//! 0x08  u32  data_max_len        bytes reserved in the data table
//! 0x0C  u32  data_offset         relative to data_table_start
//! ```
//!
//! Entries store `data_max_len` alongside `data_len` because the reserved size
//! is chosen by whoever wrote the file, not implied by the value. Preserving it
//! is what lets an existing `PARAM.SFO` be parsed and re-emitted byte for byte.

use crate::error::{Error, Result};
use crate::format::{read_u16, read_u32, write_u16, write_u32};

/// `PARAM.SFO` magic, `"\0PSF"`.
pub const SFO_MAGIC: [u8; 4] = [0x00, b'P', b'S', b'F'];

/// The only version the PSP emits.
pub const SFO_VERSION: u32 = 0x0000_0101;

/// Size of the fixed header.
pub const HEADER_SIZE: usize = 0x14;

/// Size of one index-table entry.
pub const INDEX_ENTRY_SIZE: usize = 0x10;

/// Value format codes.
pub mod format_code {
    /// Raw bytes, not NUL-terminated.
    pub const RAW: u16 = 0x0004;
    /// UTF-8, NUL-terminated.
    pub const UTF8: u16 = 0x0204;
    /// Little-endian `u32`.
    pub const U32: u16 = 0x0404;
}

/// The `CATEGORY` value, which selects the PSP's security pipeline.
///
/// This is deliberately a distinct type from an encryption tag or a key: the
/// category says *which pipeline* the firmware runs, not which cryptographic
/// material it uses. Keeping them separate is what stops a build from silently
/// crossing from one pipeline to the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Category {
    /// `MG` — a memory-stick game: homebrew, and every demo observed. The
    /// executable is an encrypted PRX in `DATA.PSP` and `DATA.PSAR` is empty.
    Mg,
    /// `UG` — a UMD game. What a retail disc's own `PARAM.SFO` declares; not a
    /// PBP container at all.
    Ug,
    /// `EG` — a PSP game downloaded from the Store. `DATA.PSP` is an NPDRM
    /// container and `DATA.PSAR` holds an `NPUMDIMG` encrypted UMD image.
    Eg,
    /// `ME` — a PSOne classic downloaded from the Store. NPDRM like `EG`, but
    /// `DATA.PSAR` holds a `PSISOIMG` PlayStation disc image rather than a
    /// `NPUMDIMG`, and it runs under the PS1 emulator.
    Me,
    /// Any other category, preserved verbatim (`MS`, `PG`, ...).
    Other(String),
}

impl Category {
    /// The on-disk string.
    pub fn as_str(&self) -> &str {
        match self {
            Category::Mg => "MG",
            Category::Ug => "UG",
            Category::Eg => "EG",
            Category::Me => "ME",
            Category::Other(s) => s,
        }
    }

    /// Whether this category's content is protected by NPDRM.
    ///
    /// `EG` and `ME` are both Store downloads and both carry a `KEYS.BIN`
    /// version key alongside the EBOOT. Neither is supported yet, but they are
    /// a different problem from `MG`, and saying so is more useful than
    /// reporting them as unrecognised.
    pub fn is_npdrm(&self) -> bool {
        matches!(self, Category::Eg | Category::Me)
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for Category {
    fn from(value: &str) -> Self {
        match value {
            "MG" => Category::Mg,
            "UG" => Category::Ug,
            "EG" => Category::Eg,
            "ME" => Category::Me,
            other => Category::Other(other.to_owned()),
        }
    }
}

/// One key/value pair.
///
/// The value is kept as raw bytes plus its format code so that any file can be
/// round-tripped exactly, including values this crate has no typed reading for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfoEntry {
    pub key: String,
    /// One of [`format_code`].
    pub format: u16,
    /// The bytes actually used, of length `data_len`.
    pub data: Vec<u8>,
    /// Bytes reserved in the data table. Always `>= data.len()`.
    pub max_len: u32,
}

impl SfoEntry {
    /// A NUL-terminated UTF-8 entry, reserving exactly what it needs.
    pub fn text(key: impl Into<String>, value: &str) -> Self {
        let mut data = value.as_bytes().to_vec();
        data.push(0);
        // The PSP's own files round the reservation up to 4 bytes.
        let max_len = crate::format::align_up(data.len() as u64, 4) as u32;
        SfoEntry {
            key: key.into(),
            format: format_code::UTF8,
            data,
            max_len,
        }
    }

    /// A NUL-terminated UTF-8 entry with an explicit reservation.
    ///
    /// Some keys are conventionally given a fixed reservation regardless of the
    /// value's length; `TITLE` is reserved 128 bytes, for instance.
    pub fn text_padded(key: impl Into<String>, value: &str, max_len: u32) -> Result<Self> {
        let mut entry = Self::text(key, value);
        if (entry.data.len() as u32) > max_len {
            return Err(Error::InvalidSfo(format!(
                "value for {} is {} bytes, which exceeds its {max_len}-byte reservation",
                entry.key,
                entry.data.len()
            )));
        }
        entry.max_len = max_len;
        Ok(entry)
    }

    /// A `u32` entry.
    pub fn int(key: impl Into<String>, value: u32) -> Self {
        SfoEntry {
            key: key.into(),
            format: format_code::U32,
            data: value.to_le_bytes().to_vec(),
            max_len: 4,
        }
    }

    /// The value as text, if it is a string entry.
    pub fn as_text(&self) -> Option<String> {
        if self.format != format_code::UTF8 && self.format != format_code::RAW {
            return None;
        }
        let end = self
            .data
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.data.len());
        Some(String::from_utf8_lossy(&self.data[..end]).into_owned())
    }

    /// The value as a `u32`, if it is an integer entry.
    pub fn as_u32(&self) -> Option<u32> {
        if self.format != format_code::U32 || self.data.len() < 4 {
            return None;
        }
        Some(u32::from_le_bytes(
            self.data[..4].try_into().expect("4 bytes"),
        ))
    }
}

/// A parsed `PARAM.SFO`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sfo {
    pub version: u32,
    /// Entries in key order, which is the order the file stores them in.
    pub entries: Vec<SfoEntry>,
}

impl Sfo {
    /// Whether `data` looks like a `PARAM.SFO`.
    pub fn is_sfo(data: &[u8]) -> bool {
        data.len() >= HEADER_SIZE && data[..4] == SFO_MAGIC
    }

    /// Parse a `PARAM.SFO`.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Error::TooShort {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }
        if data[..4] != SFO_MAGIC {
            return Err(Error::InvalidSfo("not a PARAM.SFO (bad magic)".into()));
        }
        let version = read_u32(data, 0x04)?;
        let key_table = read_u32(data, 0x08)? as usize;
        let data_table = read_u32(data, 0x0C)? as usize;
        let count = read_u32(data, 0x10)? as usize;

        // Each entry costs 16 bytes of index; a count that could not fit is a
        // truncated or hostile file rather than something to allocate for.
        let index_end = HEADER_SIZE
            .checked_add(count.checked_mul(INDEX_ENTRY_SIZE).ok_or_else(|| {
                Error::InvalidSfo(format!("entry count {count} overflows the index table"))
            })?)
            .ok_or_else(|| Error::InvalidSfo("index table overflows the file".into()))?;
        if index_end > data.len() {
            return Err(Error::InvalidSfo(format!(
                "index table needs {index_end} bytes but the file is {}",
                data.len()
            )));
        }
        if key_table > data.len() || data_table > data.len() {
            return Err(Error::InvalidSfo(
                "key or data table starts outside the file".into(),
            ));
        }

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let base = HEADER_SIZE + i * INDEX_ENTRY_SIZE;
            let key_offset = read_u16(data, base)? as usize;
            let format = read_u16(data, base + 0x02)?;
            let data_len = read_u32(data, base + 0x04)? as usize;
            let max_len = read_u32(data, base + 0x08)?;
            let data_offset = read_u32(data, base + 0x0C)? as usize;

            let key_start = key_table
                .checked_add(key_offset)
                .ok_or_else(|| Error::InvalidSfo(format!("entry {i} key offset overflows")))?;
            let key_bytes = data.get(key_start..).ok_or_else(|| {
                Error::InvalidSfo(format!("entry {i} key starts outside the file"))
            })?;
            let key_end = key_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(key_bytes.len());
            let key = String::from_utf8_lossy(&key_bytes[..key_end]).into_owned();

            let value_start = data_table
                .checked_add(data_offset)
                .ok_or_else(|| Error::InvalidSfo(format!("entry {key} data offset overflows")))?;
            let value_end = value_start
                .checked_add(data_len)
                .ok_or_else(|| Error::InvalidSfo(format!("entry {key} data length overflows")))?;
            let value = data.get(value_start..value_end).ok_or_else(|| {
                Error::InvalidSfo(format!(
                    "entry {key} data runs to {value_end}, past the {}-byte file",
                    data.len()
                ))
            })?;

            if max_len < data_len as u32 {
                return Err(Error::InvalidSfo(format!(
                    "entry {key} reserves {max_len} bytes but declares {data_len}"
                )));
            }

            entries.push(SfoEntry {
                key,
                format,
                data: value.to_vec(),
                max_len,
            });
        }

        Ok(Sfo { version, entries })
    }

    /// Look up an entry by key.
    pub fn get(&self, key: &str) -> Option<&SfoEntry> {
        self.entries.iter().find(|e| e.key == key)
    }

    /// A string value by key.
    pub fn get_text(&self, key: &str) -> Option<String> {
        self.get(key).and_then(SfoEntry::as_text)
    }

    /// An integer value by key.
    pub fn get_u32(&self, key: &str) -> Option<u32> {
        self.get(key).and_then(SfoEntry::as_u32)
    }

    /// The `CATEGORY`, which selects the security pipeline.
    pub fn category(&self) -> Option<Category> {
        self.get_text("CATEGORY")
            .map(|c| Category::from(c.as_str()))
    }

    /// Insert or replace an entry, keeping the table in key order.
    pub fn set(&mut self, entry: SfoEntry) {
        match self.entries.iter().position(|e| e.key == entry.key) {
            Some(i) => self.entries[i] = entry,
            None => {
                let at = self
                    .entries
                    .iter()
                    .position(|e| e.key > entry.key)
                    .unwrap_or(self.entries.len());
                self.entries.insert(at, entry);
            }
        }
    }

    /// Serialise the table.
    ///
    /// Keys are emitted in sorted order, which is how the PSP's own files are
    /// laid out, and every offset is recomputed from the entries themselves.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut entries: Vec<&SfoEntry> = self.entries.iter().collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key));

        let key_table_start = HEADER_SIZE + entries.len() * INDEX_ENTRY_SIZE;

        // Lay the key table out first so the index can point into it.
        let mut key_table = Vec::new();
        let mut key_offsets = Vec::with_capacity(entries.len());
        for entry in &entries {
            key_offsets.push(key_table.len() as u16);
            key_table.extend_from_slice(entry.key.as_bytes());
            key_table.push(0);
        }
        // The data table is 4-byte aligned relative to the file start.
        while !(key_table_start + key_table.len()).is_multiple_of(4) {
            key_table.push(0);
        }
        let data_table_start = key_table_start + key_table.len();

        let mut data_table = Vec::new();
        let mut data_offsets = Vec::with_capacity(entries.len());
        for entry in &entries {
            data_offsets.push(data_table.len() as u32);
            data_table.extend_from_slice(&entry.data);
            data_table.resize(
                data_table.len() + (entry.max_len as usize - entry.data.len()),
                0,
            );
        }

        let mut out = Vec::with_capacity(data_table_start + data_table.len());
        out.extend_from_slice(&SFO_MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&(key_table_start as u32).to_le_bytes());
        out.extend_from_slice(&(data_table_start as u32).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());

        let mut index = vec![0u8; entries.len() * INDEX_ENTRY_SIZE];
        for (i, entry) in entries.iter().enumerate() {
            let base = i * INDEX_ENTRY_SIZE;
            write_u16(&mut index, base, key_offsets[i]);
            write_u16(&mut index, base + 0x02, entry.format);
            write_u32(&mut index, base + 0x04, entry.data.len() as u32);
            write_u32(&mut index, base + 0x08, entry.max_len);
            write_u32(&mut index, base + 0x0C, data_offsets[i]);
        }
        out.extend_from_slice(&index);
        out.extend_from_slice(&key_table);
        out.extend_from_slice(&data_table);
        out
    }
}

impl Default for Sfo {
    fn default() -> Self {
        Sfo {
            version: SFO_VERSION,
            entries: Vec::new(),
        }
    }
}

/// Build the `PARAM.SFO` for an MG homebrew EBOOT.
///
/// These are the keys the firmware reads for a memory-stick game. Values follow
/// what homebrew toolchains have shipped for years:
///
/// - `BOOTABLE` 1, or the launcher refuses to start it
/// - `CATEGORY` `MG`, selecting the memory-stick-game pipeline
/// - `DISC_ID` a placeholder disc ID; retail firmware refuses to boot an MG
///   EBOOT that omits this (see below)
/// - `DISC_VERSION` `1.00`, alongside `DISC_ID`
/// - `MEMSIZE` 0, meaning the module does not ask for extra RAM
/// - `PARENTAL_LEVEL` 1, the least restrictive
/// - `PSP_SYSTEM_VER` the minimum firmware, `1.00` for plain homebrew
/// - `REGION` 32768, the "all regions" bitmask
/// - `TITLE` the name shown in the XMB
///
/// `DISC_ID`/`DISC_VERSION` were originally treated as disc-only fields, preserved
/// when rebuilding on an existing container but never invented here. That was
/// wrong: hardware testing on a retail PSP 3000 (6.61 OFW) showed an otherwise
/// byte-identical, already-booting MG payload fails with "the data is corrupted"
/// once these two keys are stripped from its `PARAM.SFO`. `UCJS10041`/`1.00` is
/// the same placeholder `cargo-psp`'s `mksfo` has defaulted to for years.
pub fn mg_param_sfo(title: &str) -> Result<Sfo> {
    Ok(Sfo {
        version: SFO_VERSION,
        entries: vec![
            SfoEntry::int("BOOTABLE", 1),
            SfoEntry::text_padded("CATEGORY", Category::Mg.as_str(), 4)?,
            SfoEntry::text_padded("DISC_ID", "UCJS10041", 12)?,
            SfoEntry::text_padded("DISC_VERSION", "1.00", 8)?,
            SfoEntry::int("MEMSIZE", 0),
            SfoEntry::int("PARENTAL_LEVEL", 1),
            SfoEntry::text_padded("PSP_SYSTEM_VER", "1.00", 8)?,
            SfoEntry::int("REGION", 32768),
            SfoEntry::text_padded("TITLE", title, 128)?,
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_built_table() {
        let sfo = mg_param_sfo("Test Homebrew").unwrap();
        let parsed = Sfo::parse(&sfo.to_bytes()).unwrap();
        assert_eq!(parsed, sfo);
    }

    #[test]
    fn reads_back_typed_values() {
        let sfo = mg_param_sfo("My Game").unwrap();
        let parsed = Sfo::parse(&sfo.to_bytes()).unwrap();
        assert_eq!(parsed.get_text("TITLE").as_deref(), Some("My Game"));
        assert_eq!(parsed.get_text("CATEGORY").as_deref(), Some("MG"));
        assert_eq!(parsed.get_u32("BOOTABLE"), Some(1));
        assert_eq!(parsed.get_u32("REGION"), Some(32768));
        assert_eq!(parsed.category(), Some(Category::Mg));
        // Wrong-typed reads say no rather than reinterpreting the bytes.
        assert_eq!(parsed.get_u32("TITLE"), None);
        assert_eq!(parsed.get_text("BOOTABLE"), None);
        assert_eq!(parsed.get_text("MISSING"), None);
    }

    #[test]
    fn reserved_size_survives_a_round_trip() {
        // TITLE reserves 128 bytes regardless of how short the title is; a
        // rebuild that shrank it would not match the PSP's own layout.
        let sfo = mg_param_sfo("x").unwrap();
        let parsed = Sfo::parse(&sfo.to_bytes()).unwrap();
        assert_eq!(parsed.get("TITLE").unwrap().max_len, 128);
        assert_eq!(parsed.get("TITLE").unwrap().data.len(), 2);
        assert_eq!(parsed.to_bytes(), sfo.to_bytes());
    }

    #[test]
    fn a_title_that_does_not_fit_is_rejected() {
        let long = "a".repeat(200);
        assert!(mg_param_sfo(&long).is_err());
        // Exactly filling the reservation, NUL included, is fine.
        assert!(SfoEntry::text_padded("K", &"a".repeat(127), 128).is_ok());
        assert!(SfoEntry::text_padded("K", &"a".repeat(128), 128).is_err());
    }

    #[test]
    fn set_replaces_and_keeps_key_order() {
        let mut sfo = mg_param_sfo("Original").unwrap();
        sfo.set(SfoEntry::text_padded("TITLE", "Replaced", 128).unwrap());
        assert_eq!(sfo.get_text("TITLE").as_deref(), Some("Replaced"));
        assert_eq!(sfo.entries.len(), 9);

        sfo.set(SfoEntry::int("APP_VER", 3));
        assert_eq!(sfo.entries.len(), 10);
        let keys: Vec<&str> = sfo.entries.iter().map(|e| e.key.as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "entries drifted out of key order");
    }

    #[test]
    fn category_maps_known_values_and_preserves_others() {
        // All four have been seen in the wild: MG on homebrew and demos, UG on
        // a retail UMD, ME on PSOne classics from the Store. EG is the one
        // still lacking a sample.
        for (text, expected) in [
            ("MG", Category::Mg),
            ("UG", Category::Ug),
            ("EG", Category::Eg),
            ("ME", Category::Me),
        ] {
            assert_eq!(Category::from(text), expected);
            assert_eq!(expected.as_str(), text);
            assert_eq!(expected.to_string(), text);
        }

        assert_eq!(Category::from("PG"), Category::Other("PG".into()));
        assert_eq!(Category::Other("PG".into()).as_str(), "PG");
    }

    #[test]
    fn store_downloads_are_flagged_as_npdrm() {
        // EG and ME both come from the Store and both ship a KEYS.BIN version
        // key. MG and UG do not.
        assert!(Category::Eg.is_npdrm());
        assert!(Category::Me.is_npdrm());
        assert!(!Category::Mg.is_npdrm());
        assert!(!Category::Ug.is_npdrm());
        assert!(!Category::Other("PG".into()).is_npdrm());
    }

    #[test]
    fn detects_sfo_data() {
        assert!(Sfo::is_sfo(&mg_param_sfo("t").unwrap().to_bytes()));
        assert!(!Sfo::is_sfo(b"\0PBP"));
        assert!(!Sfo::is_sfo(b""));
    }

    #[test]
    fn rejects_malformed_tables() {
        assert!(Sfo::parse(b"").is_err());
        assert!(Sfo::parse(b"\0PSFxxxxxxxxxxxxxxxx").is_err());

        // An entry count far larger than the file can hold must not allocate.
        let mut bytes = mg_param_sfo("t").unwrap().to_bytes();
        write_u32(&mut bytes, 0x10, 0xFFFF_FFFF);
        assert!(Sfo::parse(&bytes).is_err());

        // A data offset past the end of the file.
        let mut bytes = mg_param_sfo("t").unwrap().to_bytes();
        write_u32(&mut bytes, HEADER_SIZE + 0x0C, 0xFFFF_0000);
        assert!(Sfo::parse(&bytes).is_err());

        // A table start outside the file.
        let mut bytes = mg_param_sfo("t").unwrap().to_bytes();
        write_u32(&mut bytes, 0x08, 0xFFFF_FFFF);
        assert!(Sfo::parse(&bytes).is_err());

        // data_len larger than the reservation is contradictory.
        let mut bytes = mg_param_sfo("t").unwrap().to_bytes();
        write_u32(&mut bytes, HEADER_SIZE + 0x04, 0xFF);
        assert!(Sfo::parse(&bytes).is_err());
    }

    #[test]
    fn truncated_tables_never_panic() {
        let full = mg_param_sfo("truncate me").unwrap().to_bytes();
        for cut in 0..full.len() {
            let _ = Sfo::parse(&full[..cut]);
        }
    }
}
