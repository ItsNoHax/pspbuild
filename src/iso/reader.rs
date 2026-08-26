//! An ISO9660 reader, scoped to what PSP UMD images actually use.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Error, Result};

/// ISO9660 logical sector size. PSP UMDs never use anything else.
pub const SECTOR_SIZE: u64 = 2048;

/// Sector holding the first volume descriptor.
const FIRST_DESCRIPTOR_SECTOR: u64 = 16;

/// Volume descriptor type codes.
const VD_PRIMARY: u8 = 0x01;
const VD_TERMINATOR: u8 = 0xFF;

/// `CD001`, the ISO9660 standard identifier.
const STANDARD_ID: &[u8; 5] = b"CD001";

/// Size of a directory record's fixed part, before the name.
const DIR_RECORD_FIXED: usize = 33;

/// How deep the directory walk will go.
///
/// ISO9660 itself specifies eight levels. A malformed or hostile image can
/// describe a cycle, and the walk has to terminate regardless of what the
/// image claims.
const MAX_DEPTH: usize = 16;

/// Upper bound on directory entries, so a corrupt image cannot make the reader
/// allocate without limit.
const MAX_ENTRIES: usize = 200_000;

/// Largest directory extent that will be read, 16 MiB.
const MAX_DIR_EXTENT: u64 = 16 * 1024 * 1024;

/// What the primary volume descriptor says about the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    /// System identifier. `PSP GAME` on a UMD.
    pub system_id: String,
    /// Volume identifier. Frequently blank on a UMD.
    pub volume_id: String,
    /// Size of the volume in logical blocks.
    pub volume_blocks: u32,
    /// Logical block size. Always 2048 here.
    pub block_size: u16,
}

/// One file or directory in the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsoEntry {
    /// Absolute path, `/` separated, version suffix stripped.
    pub path: String,
    /// Starting logical block.
    pub lba: u32,
    /// Size in bytes.
    pub size: u32,
    pub is_dir: bool,
}

impl IsoEntry {
    /// The sectors this entry occupies.
    pub fn block_count(&self) -> u32 {
        u32::try_from(u64::from(self.size).div_ceil(SECTOR_SIZE)).unwrap_or(u32::MAX)
    }
}

/// A mounted ISO9660 image.
///
/// The directory tree is read once at open time; file contents are read on
/// demand. Nothing proportional to the image size is held in memory.
#[derive(Debug)]
pub struct Iso<R> {
    source: R,
    volume: VolumeInfo,
    /// Entries by lookup key, see [`normalise`].
    entries: BTreeMap<String, IsoEntry>,
}

impl Iso<File> {
    /// Open an image from disk.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|e| Error::io(path, e))?;
        Iso::new(file)
    }
}

impl<R: Read + Seek> Iso<R> {
    /// Give the underlying reader back.
    ///
    /// Useful when a caller has finished with the filesystem view and wants to
    /// go on reading the image as raw bytes — building an archive from it, for
    /// instance — without opening it a second time.
    pub fn into_inner(self) -> R {
        self.source
    }

    /// Mount an image, reading its volume descriptors and directory tree.
    pub fn new(mut source: R) -> Result<Self> {
        let volume = read_primary_descriptor(&mut source)?;
        if volume.block_size as u64 != SECTOR_SIZE {
            return Err(Error::InvalidIso(format!(
                "logical block size is {}, but only {SECTOR_SIZE} is supported",
                volume.block_size
            )));
        }

        // The root directory record sits inside the primary descriptor.
        let mut root = [0u8; 34];
        source
            .seek(SeekFrom::Start(FIRST_DESCRIPTOR_SECTOR * SECTOR_SIZE + 156))
            .map_err(Error::BareIo)?;
        source.read_exact(&mut root).map_err(Error::BareIo)?;
        let root_lba = both_endian_u32(&root[2..10])?;
        let root_size = both_endian_u32(&root[10..18])?;

        let mut entries = BTreeMap::new();
        walk(&mut source, root_lba, root_size, "", 0, &mut entries)?;

        Ok(Iso {
            source,
            volume,
            entries,
        })
    }

    /// What the primary volume descriptor says.
    pub fn volume(&self) -> &VolumeInfo {
        &self.volume
    }

    /// Every entry, in path order.
    pub fn entries(&self) -> impl Iterator<Item = &IsoEntry> {
        self.entries.values()
    }

    /// Look up an entry. Matching ignores case and any `;1` version suffix,
    /// which is how these paths are written in practice.
    pub fn entry(&self, path: &str) -> Option<&IsoEntry> {
        self.entries.get(&normalise(path))
    }

    /// Whether a path exists.
    pub fn exists(&self, path: &str) -> bool {
        self.entry(path).is_some()
    }

    /// Size of a file, or `None` if it is absent or is a directory.
    pub fn file_size(&self, path: &str) -> Option<u64> {
        self.entry(path)
            .filter(|e| !e.is_dir)
            .map(|e| u64::from(e.size))
    }

    /// Read a whole file.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        let entry = self
            .entry(path)
            .ok_or_else(|| Error::IsoMissingFile(path.to_owned()))?;
        if entry.is_dir {
            return Err(Error::InvalidIso(format!("{path} is a directory")));
        }
        let (lba, size) = (entry.lba, entry.size);
        self.read_at(lba, u64::from(size))
    }

    /// Read a file if it is present, returning `None` when it is not.
    ///
    /// Optional assets use this: a UMD without `SND0.AT3` is normal, not an
    /// error, and the caller should not have to distinguish "absent" from
    /// "unreadable" by inspecting an error type.
    pub fn read_optional(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        match self.entry(path) {
            Some(entry) if !entry.is_dir => {
                let (lba, size) = (entry.lba, entry.size);
                self.read_at(lba, u64::from(size)).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Read `count` raw sectors starting at `lba`.
    ///
    /// This is how the EG pipeline consumes the image: the archive is built
    /// from sectors, not from files.
    pub fn read_blocks(&mut self, lba: u32, count: u32) -> Result<Vec<u8>> {
        self.read_at(lba, u64::from(count) * SECTOR_SIZE)
    }

    /// Total size of the image as the volume descriptor declares it.
    pub fn volume_size(&self) -> u64 {
        u64::from(self.volume.volume_blocks) * SECTOR_SIZE
    }

    fn read_at(&mut self, lba: u32, len: u64) -> Result<Vec<u8>> {
        let offset = u64::from(lba)
            .checked_mul(SECTOR_SIZE)
            .ok_or_else(|| Error::InvalidIso(format!("block {lba} overflows")))?;
        let len = usize::try_from(len)
            .map_err(|_| Error::InvalidIso(format!("{len} bytes is too large to read")))?;

        self.source
            .seek(SeekFrom::Start(offset))
            .map_err(Error::BareIo)?;
        let mut out = vec![0u8; len];
        self.source.read_exact(&mut out).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::InvalidIso(format!(
                    "image ends before block {lba} + {len} bytes; it is truncated"
                ))
            } else {
                Error::BareIo(e)
            }
        })?;
        Ok(out)
    }
}

/// Read and validate the primary volume descriptor.
fn read_primary_descriptor<R: Read + Seek>(source: &mut R) -> Result<VolumeInfo> {
    // Scan the descriptor set rather than assuming the primary is first. It
    // always is on a UMD, but the terminator is what bounds the search.
    for index in 0..8u64 {
        let sector = FIRST_DESCRIPTOR_SECTOR + index;
        source
            .seek(SeekFrom::Start(sector * SECTOR_SIZE))
            .map_err(Error::BareIo)?;
        let mut buf = [0u8; 190];
        if source.read_exact(&mut buf).is_err() {
            break;
        }
        if &buf[1..6] != STANDARD_ID {
            return Err(Error::InvalidIso(format!(
                "sector {sector} is not a volume descriptor (expected \"CD001\")"
            )));
        }
        match buf[0] {
            VD_PRIMARY => {
                return Ok(VolumeInfo {
                    system_id: trimmed(&buf[8..40]),
                    volume_id: trimmed(&buf[40..72]),
                    volume_blocks: both_endian_u32(&buf[80..88])?,
                    block_size: both_endian_u16(&buf[128..132])?,
                });
            }
            VD_TERMINATOR => break,
            _ => continue,
        }
    }
    Err(Error::InvalidIso(
        "no primary volume descriptor found".into(),
    ))
}

/// Walk a directory extent, recursing into subdirectories.
fn walk<R: Read + Seek>(
    source: &mut R,
    lba: u32,
    size: u32,
    prefix: &str,
    depth: usize,
    out: &mut BTreeMap<String, IsoEntry>,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::InvalidIso(format!(
            "directory nesting exceeds {MAX_DEPTH} levels; the image describes a cycle"
        )));
    }
    if u64::from(size) > MAX_DIR_EXTENT {
        return Err(Error::InvalidIso(format!(
            "directory extent at block {lba} claims {size} bytes"
        )));
    }

    let offset = u64::from(lba) * SECTOR_SIZE;
    source
        .seek(SeekFrom::Start(offset))
        .map_err(Error::BareIo)?;
    let mut data = vec![0u8; size as usize];
    if source.read_exact(&mut data).is_err() {
        return Err(Error::InvalidIso(format!(
            "directory extent at block {lba} runs past the end of the image"
        )));
    }

    // Collect first, recurse after, so the borrow of `data` ends before the
    // recursive call needs the reader again.
    let mut subdirs = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            // Records never straddle a sector; a zero length means padding to
            // the next sector boundary.
            let next = (pos / SECTOR_SIZE as usize + 1) * SECTOR_SIZE as usize;
            if next <= pos {
                break;
            }
            pos = next;
            continue;
        }
        if len < DIR_RECORD_FIXED || pos + len > data.len() {
            return Err(Error::InvalidIso(format!(
                "directory record at block {lba}+{pos} claims {len} bytes"
            )));
        }
        let record = &data[pos..pos + len];

        let ext_lba = both_endian_u32(&record[2..10])?;
        let ext_size = both_endian_u32(&record[10..18])?;
        let is_dir = record[25] & 0x02 != 0;
        let name_len = record[32] as usize;
        if DIR_RECORD_FIXED + name_len > len {
            return Err(Error::InvalidIso(format!(
                "directory record at block {lba}+{pos} has a {name_len}-byte name in {len} bytes"
            )));
        }
        let name_bytes = &record[DIR_RECORD_FIXED..DIR_RECORD_FIXED + name_len];

        // A one-byte name of 0x00 is "." and 0x01 is ".."; both are skipped,
        // and skipping ".." is also what stops the walk looping.
        let is_special = name_len == 1 && (name_bytes[0] == 0 || name_bytes[0] == 1);
        if !is_special {
            let name = decode_name(name_bytes);
            let path = format!("{prefix}/{name}");
            if out.len() >= MAX_ENTRIES {
                return Err(Error::InvalidIso(format!(
                    "image declares more than {MAX_ENTRIES} entries"
                )));
            }
            out.insert(
                normalise(&path),
                IsoEntry {
                    path: path.clone(),
                    lba: ext_lba,
                    size: ext_size,
                    is_dir,
                },
            );
            if is_dir {
                subdirs.push((ext_lba, ext_size, path));
            }
        }
        pos += len;
    }

    for (lba, size, path) in subdirs {
        walk(source, lba, size, &path, depth + 1, out)?;
    }
    Ok(())
}

/// Decode an ISO9660 file identifier, dropping the `;1` version suffix.
fn decode_name(bytes: &[u8]) -> String {
    let name = String::from_utf8_lossy(bytes);
    match name.split_once(';') {
        Some((stem, _version)) => stem.to_owned(),
        None => name.into_owned(),
    }
}

/// The lookup key for a path: uppercase, no version suffix, no trailing slash.
fn normalise(path: &str) -> String {
    let path = path.strip_suffix('/').unwrap_or(path);
    let path = match path.split_once(';') {
        Some((stem, _)) => stem,
        None => path,
    };
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    path.to_uppercase()
}

/// Read an ISO9660 both-endian `u32`, checking the two halves agree.
fn both_endian_u32(field: &[u8]) -> Result<u32> {
    if field.len() < 8 {
        return Err(Error::InvalidIso("truncated both-endian field".into()));
    }
    let le = u32::from_le_bytes(field[..4].try_into().expect("4 bytes"));
    let be = u32::from_be_bytes(field[4..8].try_into().expect("4 bytes"));
    if le != be {
        return Err(Error::InvalidIso(format!(
            "both-endian field disagrees: {le:#X} little-endian, {be:#X} big-endian"
        )));
    }
    Ok(le)
}

/// Read an ISO9660 both-endian `u16`.
fn both_endian_u16(field: &[u8]) -> Result<u16> {
    if field.len() < 4 {
        return Err(Error::InvalidIso("truncated both-endian field".into()));
    }
    let le = u16::from_le_bytes(field[..2].try_into().expect("2 bytes"));
    let be = u16::from_be_bytes(field[2..4].try_into().expect("2 bytes"));
    if le != be {
        return Err(Error::InvalidIso(format!(
            "both-endian field disagrees: {le:#X} little-endian, {be:#X} big-endian"
        )));
    }
    Ok(le)
}

/// Trim the trailing spaces ISO9660 pads its text fields with.
fn trimmed(field: &[u8]) -> String {
    String::from_utf8_lossy(field).trim_end().to_owned()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Cursor;

    /// A file to place in a synthetic image.
    pub(crate) struct TestFile {
        pub path: &'static str,
        pub data: Vec<u8>,
    }

    /// Build a minimal but valid ISO9660 image in memory.
    ///
    /// Only one directory level is generated, which is enough to exercise the
    /// record walk, the both-endian fields and the sector padding without
    /// depending on a real 1 GB image.
    pub(crate) fn synthetic_iso(files: &[TestFile]) -> Vec<u8> {
        fn both_u32(v: u32) -> [u8; 8] {
            let mut out = [0u8; 8];
            out[..4].copy_from_slice(&v.to_le_bytes());
            out[4..].copy_from_slice(&v.to_be_bytes());
            out
        }
        fn both_u16(v: u16) -> [u8; 4] {
            let mut out = [0u8; 4];
            out[..2].copy_from_slice(&v.to_le_bytes());
            out[2..].copy_from_slice(&v.to_be_bytes());
            out
        }
        fn record(name: &[u8], lba: u32, size: u32, is_dir: bool) -> Vec<u8> {
            let len = DIR_RECORD_FIXED + name.len();
            // Records are padded to an even length.
            let padded = len + (len % 2);
            let mut r = vec![0u8; padded];
            r[0] = padded as u8;
            r[2..10].copy_from_slice(&both_u32(lba));
            r[10..18].copy_from_slice(&both_u32(size));
            r[25] = if is_dir { 0x02 } else { 0x00 };
            r[28..32].copy_from_slice(&both_u16(1));
            r[32] = name.len() as u8;
            r[DIR_RECORD_FIXED..DIR_RECORD_FIXED + name.len()].copy_from_slice(name);
            r
        }

        const ROOT_LBA: u32 = 20;
        const DATA_LBA: u32 = 24;

        // Lay the file data out, one file per sector run.
        let mut data_sectors: Vec<u8> = Vec::new();
        let mut placed = Vec::new();
        for file in files {
            let lba = DATA_LBA + (data_sectors.len() / SECTOR_SIZE as usize) as u32;
            placed.push((file, lba));
            let mut chunk = file.data.clone();
            let pad = chunk.len().next_multiple_of(SECTOR_SIZE as usize) - chunk.len();
            chunk.extend(std::iter::repeat_n(0u8, pad));
            data_sectors.extend_from_slice(&chunk);
        }

        // Root directory extent: "." and ".." then one record per file.
        let mut root = Vec::new();
        root.extend_from_slice(&record(&[0], ROOT_LBA, SECTOR_SIZE as u32, true));
        root.extend_from_slice(&record(&[1], ROOT_LBA, SECTOR_SIZE as u32, true));
        for (file, lba) in &placed {
            let name = file.path.trim_start_matches('/').as_bytes();
            root.extend_from_slice(&record(name, *lba, file.data.len() as u32, false));
        }
        root.resize(SECTOR_SIZE as usize, 0);

        let total_blocks = DATA_LBA + (data_sectors.len() / SECTOR_SIZE as usize) as u32;
        let mut iso = vec![0u8; (FIRST_DESCRIPTOR_SECTOR * SECTOR_SIZE) as usize];

        // Primary volume descriptor.
        let mut pvd = vec![0u8; SECTOR_SIZE as usize];
        pvd[0] = VD_PRIMARY;
        pvd[1..6].copy_from_slice(STANDARD_ID);
        pvd[6] = 1;
        pvd[8..40].copy_from_slice(b"PSP GAME                        ");
        pvd[40..72].copy_from_slice(b"TESTVOL                         ");
        pvd[80..88].copy_from_slice(&both_u32(total_blocks));
        pvd[128..132].copy_from_slice(&both_u16(SECTOR_SIZE as u16));
        pvd[156..156 + 34].copy_from_slice(&{
            let mut r = record(&[0], ROOT_LBA, SECTOR_SIZE as u32, true);
            r.resize(34, 0);
            r[0] = 34;
            r
        });
        iso.extend_from_slice(&pvd);

        // Terminator.
        let mut term = vec![0u8; SECTOR_SIZE as usize];
        term[0] = VD_TERMINATOR;
        term[1..6].copy_from_slice(STANDARD_ID);
        term[6] = 1;
        iso.extend_from_slice(&term);

        iso.resize((ROOT_LBA as u64 * SECTOR_SIZE) as usize, 0);
        iso.extend_from_slice(&root);
        iso.resize((DATA_LBA as u64 * SECTOR_SIZE) as usize, 0);
        iso.extend_from_slice(&data_sectors);
        iso
    }

    /// A synthetic image with the directory layout a PSP UMD has.
    ///
    /// The flat [`synthetic_iso`] cannot express `/PSP_GAME/...`, and the EG
    /// pipeline reads nothing else, so this builds the two levels it needs:
    /// a root holding `PSP_GAME` and `UMD_DATA.BIN`, and a `PSP_GAME` holding
    /// the assets and a `SYSDIR` with the executable.
    pub(crate) fn synthetic_psp_iso() -> Vec<u8> {
        fn both_u32(v: u32) -> [u8; 8] {
            let mut out = [0u8; 8];
            out[..4].copy_from_slice(&v.to_le_bytes());
            out[4..].copy_from_slice(&v.to_be_bytes());
            out
        }
        fn both_u16(v: u16) -> [u8; 4] {
            let mut out = [0u8; 4];
            out[..2].copy_from_slice(&v.to_le_bytes());
            out[2..].copy_from_slice(&v.to_be_bytes());
            out
        }
        fn record(name: &[u8], lba: u32, size: u32, is_dir: bool) -> Vec<u8> {
            let len = DIR_RECORD_FIXED + name.len();
            let padded = len + (len % 2);
            let mut r = vec![0u8; padded];
            r[0] = padded as u8;
            r[2..10].copy_from_slice(&both_u32(lba));
            r[10..18].copy_from_slice(&both_u32(size));
            r[25] = if is_dir { 0x02 } else { 0x00 };
            r[28..32].copy_from_slice(&both_u16(1));
            r[32] = name.len() as u8;
            r[DIR_RECORD_FIXED..DIR_RECORD_FIXED + name.len()].copy_from_slice(name);
            r
        }

        // A UMD's own PARAM.SFO says UG; the EG pipeline has to rewrite it.
        let mut sfo = crate::sfo::mg_param_sfo("Synthetic Disc").expect("template");
        sfo.set(crate::sfo::SfoEntry::text_padded("CATEGORY", "UG", 4).expect("fits"));
        sfo.set(crate::sfo::SfoEntry::text_padded("DISC_ID", "ABCD12345", 16).expect("fits"));
        let param_sfo = sfo.to_bytes();

        const ROOT_LBA: u32 = 20;
        const GAME_LBA: u32 = 21;
        const SYSDIR_LBA: u32 = 22;
        const DATA_LBA: u32 = 24;

        // Files, each starting on its own sector.
        let files: Vec<(&str, Vec<u8>, u32)> = {
            let entries: Vec<(&str, Vec<u8>)> = vec![
                ("PARAM.SFO", param_sfo),
                ("ICON0.PNG", vec![0x89; 600]),
                ("PIC1.PNG", vec![0x77; 900]),
                ("EBOOT.BIN", vec![0xAB; 5000]),
                (
                    "UMD_DATA.BIN",
                    b"ABCD-12345|0000000000000000|0001|G".to_vec(),
                ),
            ];
            let mut out = Vec::new();
            let mut lba = DATA_LBA;
            for (name, data) in entries {
                let sectors = data.len().div_ceil(SECTOR_SIZE as usize) as u32;
                out.push((name, data, lba));
                lba += sectors;
            }
            out
        };
        let find = |name: &str| files.iter().find(|(n, _, _)| *n == name).expect("present");

        let dir_extent = |entries: &[(&[u8], u32, u32, bool)], self_lba: u32, parent: u32| {
            let mut d = Vec::new();
            d.extend_from_slice(&record(&[0], self_lba, SECTOR_SIZE as u32, true));
            d.extend_from_slice(&record(&[1], parent, SECTOR_SIZE as u32, true));
            for (name, lba, size, is_dir) in entries {
                d.extend_from_slice(&record(name, *lba, *size, *is_dir));
            }
            d.resize(SECTOR_SIZE as usize, 0);
            d
        };

        let umd = find("UMD_DATA.BIN");
        let root = dir_extent(
            &[
                (b"PSP_GAME", GAME_LBA, SECTOR_SIZE as u32, true),
                (b"UMD_DATA.BIN", umd.2, umd.1.len() as u32, false),
            ],
            ROOT_LBA,
            ROOT_LBA,
        );

        let sfo_f = find("PARAM.SFO");
        let icon = find("ICON0.PNG");
        let pic1 = find("PIC1.PNG");
        let game = dir_extent(
            &[
                (b"SYSDIR", SYSDIR_LBA, SECTOR_SIZE as u32, true),
                (b"PARAM.SFO", sfo_f.2, sfo_f.1.len() as u32, false),
                (b"ICON0.PNG", icon.2, icon.1.len() as u32, false),
                (b"PIC1.PNG", pic1.2, pic1.1.len() as u32, false),
            ],
            GAME_LBA,
            ROOT_LBA,
        );

        let eboot = find("EBOOT.BIN");
        let sysdir = dir_extent(
            &[(b"EBOOT.BIN", eboot.2, eboot.1.len() as u32, false)],
            SYSDIR_LBA,
            GAME_LBA,
        );

        let mut data_sectors: Vec<u8> = Vec::new();
        for (_, data, _) in &files {
            let mut chunk = data.clone();
            chunk.resize(chunk.len().next_multiple_of(SECTOR_SIZE as usize), 0);
            data_sectors.extend_from_slice(&chunk);
        }
        let total_blocks = DATA_LBA + (data_sectors.len() / SECTOR_SIZE as usize) as u32;

        let mut iso = vec![0u8; (FIRST_DESCRIPTOR_SECTOR * SECTOR_SIZE) as usize];

        let mut pvd = vec![0u8; SECTOR_SIZE as usize];
        pvd[0] = VD_PRIMARY;
        pvd[1..6].copy_from_slice(STANDARD_ID);
        pvd[6] = 1;
        pvd[8..40].copy_from_slice(b"PSP GAME                        ");
        pvd[40..72].copy_from_slice(b"                                ");
        pvd[80..88].copy_from_slice(&both_u32(total_blocks));
        pvd[128..132].copy_from_slice(&both_u16(SECTOR_SIZE as u16));
        pvd[156..156 + 34].copy_from_slice(&{
            let mut r = record(&[0], ROOT_LBA, SECTOR_SIZE as u32, true);
            r.resize(34, 0);
            r[0] = 34;
            r
        });
        iso.extend_from_slice(&pvd);

        let mut term = vec![0u8; SECTOR_SIZE as usize];
        term[0] = VD_TERMINATOR;
        term[1..6].copy_from_slice(STANDARD_ID);
        term[6] = 1;
        iso.extend_from_slice(&term);

        iso.resize((ROOT_LBA as u64 * SECTOR_SIZE) as usize, 0);
        iso.extend_from_slice(&root);
        iso.extend_from_slice(&game);
        iso.extend_from_slice(&sysdir);
        iso.resize((DATA_LBA as u64 * SECTOR_SIZE) as usize, 0);
        iso.extend_from_slice(&data_sectors);
        iso
    }

    #[test]
    fn the_synthetic_psp_image_has_the_umd_layout() {
        let mut iso = Iso::new(Cursor::new(synthetic_psp_iso())).unwrap();
        assert_eq!(iso.volume().system_id, "PSP GAME");
        assert!(iso.exists("/PSP_GAME/PARAM.SFO"));
        assert!(iso.exists("/PSP_GAME/SYSDIR/EBOOT.BIN"));
        assert!(iso.exists("/UMD_DATA.BIN"));
        assert!(!iso.exists("/PSP_GAME/SND0.AT3"));

        let sfo = crate::sfo::Sfo::parse(&iso.read_file("/PSP_GAME/PARAM.SFO").unwrap()).unwrap();
        assert_eq!(sfo.get_text("CATEGORY").as_deref(), Some("UG"));
    }

    fn sample() -> Vec<u8> {
        synthetic_iso(&[
            TestFile {
                path: "/PARAM.SFO",
                data: b"\0PSF pretend parameter table".to_vec(),
            },
            TestFile {
                path: "/EBOOT.BIN",
                data: vec![0xAB; 3000],
            },
        ])
    }

    #[test]
    fn reads_the_volume_descriptor() {
        let iso = Iso::new(Cursor::new(sample())).unwrap();
        assert_eq!(iso.volume().system_id, "PSP GAME");
        assert_eq!(iso.volume().volume_id, "TESTVOL");
        assert_eq!(iso.volume().block_size, 2048);
        assert_eq!(iso.volume_size(), iso.volume().volume_blocks as u64 * 2048);
    }

    #[test]
    fn finds_and_reads_files() {
        let mut iso = Iso::new(Cursor::new(sample())).unwrap();

        assert!(iso.exists("/PARAM.SFO"));
        assert!(iso.exists("/EBOOT.BIN"));
        assert!(!iso.exists("/NOPE.BIN"));

        assert_eq!(iso.file_size("/PARAM.SFO"), Some(28));
        assert_eq!(iso.file_size("/EBOOT.BIN"), Some(3000));
        assert_eq!(iso.file_size("/NOPE.BIN"), None);

        assert_eq!(iso.read_file("/PARAM.SFO").unwrap().len(), 28);
        assert_eq!(&iso.read_file("/PARAM.SFO").unwrap()[..4], b"\0PSF");
        // A file spanning two sectors comes back at its exact length, not
        // rounded up to the sector it occupies.
        let eboot = iso.read_file("/EBOOT.BIN").unwrap();
        assert_eq!(eboot.len(), 3000);
        assert!(eboot.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn lookup_ignores_case_and_version_suffixes() {
        let iso = Iso::new(Cursor::new(sample())).unwrap();
        assert!(iso.exists("/param.sfo"));
        assert!(iso.exists("/PARAM.SFO;1"));
        assert!(iso.exists("PARAM.SFO"));
        assert!(iso.exists("/PaRaM.SfO;1"));
    }

    #[test]
    fn missing_files_are_distinguishable_from_unreadable_ones() {
        let mut iso = Iso::new(Cursor::new(sample())).unwrap();

        assert!(matches!(
            iso.read_file("/SND0.AT3").unwrap_err(),
            Error::IsoMissingFile(path) if path == "/SND0.AT3"
        ));
        // The optional read says "absent" without constructing an error.
        assert_eq!(iso.read_optional("/SND0.AT3").unwrap(), None);
        assert!(iso.read_optional("/PARAM.SFO").unwrap().is_some());
    }

    #[test]
    fn reads_raw_sectors() {
        let mut iso = Iso::new(Cursor::new(sample())).unwrap();
        let entry = iso.entry("/EBOOT.BIN").unwrap().clone();
        assert_eq!(entry.block_count(), 2, "3000 bytes spans two sectors");

        let blocks = iso.read_blocks(entry.lba, entry.block_count()).unwrap();
        assert_eq!(blocks.len(), 2 * 2048);
        // The file's bytes are at the front, padding after.
        assert_eq!(&blocks[..3000], &vec![0xABu8; 3000][..]);
        assert!(blocks[3000..].iter().all(|&b| b == 0));
    }

    #[test]
    fn entries_are_enumerable() {
        let iso = Iso::new(Cursor::new(sample())).unwrap();
        let paths: Vec<&str> = iso.entries().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"/PARAM.SFO"));
        assert!(paths.contains(&"/EBOOT.BIN"));
        // "." and ".." are not entries.
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn rejects_things_that_are_not_iso_images() {
        assert!(Iso::new(Cursor::new(vec![0u8; 100])).is_err());
        assert!(Iso::new(Cursor::new(vec![0u8; 40 * 2048])).is_err());
        assert!(Iso::new(Cursor::new(b"not an iso".to_vec())).is_err());
    }

    #[test]
    fn rejects_a_disagreeing_both_endian_field() {
        // Corrupt the big-endian half of the volume size. A reader that only
        // looked at the little-endian half would sail past this.
        let mut bytes = sample();
        let at = (FIRST_DESCRIPTOR_SECTOR * SECTOR_SIZE) as usize + 84;
        bytes[at..at + 4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        let err = Iso::new(Cursor::new(bytes)).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidIso(m) if m.contains("both-endian")),
            "got {err}"
        );
    }

    #[test]
    fn rejects_an_unsupported_block_size() {
        let mut bytes = sample();
        let at = (FIRST_DESCRIPTOR_SECTOR * SECTOR_SIZE) as usize + 128;
        bytes[at..at + 2].copy_from_slice(&512u16.to_le_bytes());
        bytes[at + 2..at + 4].copy_from_slice(&512u16.to_be_bytes());
        let err = Iso::new(Cursor::new(bytes)).unwrap_err();
        assert!(err.to_string().contains("512"), "got {err}");
    }

    #[test]
    fn a_record_whose_name_overruns_it_is_rejected() {
        // A length byte cannot exceed a 2048-byte extent on its own, so the
        // guard that matters is the name length: a record claiming a 255-byte
        // name inside 34 bytes would otherwise slice out of bounds.
        let mut bytes = sample();
        let at = (20 * SECTOR_SIZE) as usize;
        bytes[at + 32] = 0xFF;
        let err = Iso::new(Cursor::new(bytes)).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidIso(m) if m.contains("name")),
            "got {err}"
        );
    }

    #[test]
    fn a_record_running_past_the_end_of_its_extent_is_rejected() {
        // A record length is one byte, so it can only overrun a densely packed
        // extent. Shrink the root extent to 40 bytes, leaving room for the "."
        // record and a second one that claims far more than remains.
        let mut bytes = sample();

        let pvd_root_size = (FIRST_DESCRIPTOR_SECTOR * SECTOR_SIZE) as usize + 156 + 10;
        bytes[pvd_root_size..pvd_root_size + 4].copy_from_slice(&40u32.to_le_bytes());
        bytes[pvd_root_size + 4..pvd_root_size + 8].copy_from_slice(&40u32.to_be_bytes());

        let extent = (20 * SECTOR_SIZE) as usize;
        bytes[extent + 34] = 200;

        let err = Iso::new(Cursor::new(bytes)).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidIso(m) if m.contains("claims 200 bytes")),
            "got {err}"
        );
    }

    #[test]
    fn a_truncated_image_errors_rather_than_panicking() {
        let full = sample();
        for cut in (0..full.len()).step_by(521) {
            let _ = Iso::new(Cursor::new(full[..cut].to_vec()));
        }
        // Reading past the end of a truncated image is an error, not a panic.
        let mut iso = Iso::new(Cursor::new(sample())).unwrap();
        assert!(iso.read_blocks(u32::MAX - 1, 4).is_err());
        assert!(iso.read_blocks(1_000_000, 1).is_err());
    }

    #[test]
    fn reading_a_directory_as_a_file_is_an_error() {
        let mut iso = Iso::new(Cursor::new(sample())).unwrap();
        // The synthetic image is flat, so construct the case directly.
        iso.entries.insert(
            "/DIR".into(),
            IsoEntry {
                path: "/DIR".into(),
                lba: 20,
                size: 2048,
                is_dir: true,
            },
        );
        assert!(iso.read_file("/DIR").is_err());
        assert_eq!(iso.file_size("/DIR"), None);
        assert!(iso.exists("/DIR"));
    }
}
