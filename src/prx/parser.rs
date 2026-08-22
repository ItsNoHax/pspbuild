//! Parsing of the *input* PRX: a MIPS ELF carrying a PSP module.
//!
//! Only the parts needed to populate a `~PSP` header are decoded. Everything is
//! bounds-checked; a malformed file is an error, never a panic.

use crate::error::{Error, Result};
use crate::format::{cstr_from_field, read_array, read_u8, read_u16, read_u32};

/// ELF magic.
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
/// 32-bit ELF class.
const ELFCLASS32: u8 = 1;
/// Little-endian ELF data encoding.
const ELFDATA2LSB: u8 = 1;
/// `e_machine` for MIPS.
const EM_MIPS: u16 = 8;
/// `e_type` for a Sony PRX.
const ET_SCE_PRX: u16 = 0xFFA0;
/// `e_type` for a plain executable, which `psp-prxgen` also accepts.
const ET_EXEC: u16 = 2;
/// `p_type` for a loadable segment.
const PT_LOAD: u32 = 1;

/// The maximum number of segments a `~PSP` header can describe.
pub const MAX_SEGMENTS: usize = 4;

/// A loadable segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub address: u32,
    pub file_size: u32,
    pub mem_size: u32,
    pub align: u32,
}

/// What we need from an input module in order to build a `~PSP` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    /// Module name from the `.rodata.sceModuleInfo` structure.
    pub name: String,
    /// Module attributes from the module-info structure.
    pub attributes: u16,
    pub version_lo: u8,
    pub version_hi: u8,
    /// Entry point (`e_entry`).
    pub entry: u32,
    /// File offset of the module-info structure.
    pub modinfo_offset: u32,
    pub segments: Vec<Segment>,
    /// Total size of the input file.
    pub elf_size: u32,
    /// Whether the input is a relocatable PRX rather than a plain executable.
    pub is_prx: bool,
}

impl ModuleInfo {
    /// Combined uninitialised size across all segments.
    pub fn bss_size(&self) -> u32 {
        self.segments
            .iter()
            .map(|s| s.mem_size.saturating_sub(s.file_size))
            .sum()
    }
}

/// Parse a PSP module from an ELF image.
pub fn parse_module(data: &[u8]) -> Result<ModuleInfo> {
    // --- ELF identification ---
    let magic: [u8; 4] = read_array(data, 0)
        .map_err(|_| Error::InvalidPrxHeader("file is too small to be an ELF".into()))?;
    if magic != ELF_MAGIC {
        return Err(Error::InvalidPrxHeader(
            "not an ELF file (bad magic)".into(),
        ));
    }
    if read_u8(data, 4)? != ELFCLASS32 {
        return Err(Error::InvalidPrxHeader(
            "only 32-bit ELF files are supported".into(),
        ));
    }
    if read_u8(data, 5)? != ELFDATA2LSB {
        return Err(Error::InvalidPrxHeader(
            "only little-endian ELF files are supported".into(),
        ));
    }

    let e_type = read_u16(data, 0x10)?;
    let e_machine = read_u16(data, 0x12)?;
    if e_machine != EM_MIPS {
        return Err(Error::InvalidPrxHeader(format!(
            "unexpected machine {e_machine:#06X}, expected MIPS"
        )));
    }
    if e_type != ET_SCE_PRX && e_type != ET_EXEC {
        return Err(Error::InvalidPrxHeader(format!(
            "unexpected ELF type {e_type:#06X}, expected a PRX or executable"
        )));
    }

    let e_entry = read_u32(data, 0x18)?;
    let e_phoff = read_u32(data, 0x1C)? as usize;
    let e_phentsize = read_u16(data, 0x2A)? as usize;
    let e_phnum = read_u16(data, 0x2C)? as usize;

    if e_phnum == 0 {
        return Err(Error::InvalidPrxHeader("ELF has no program headers".into()));
    }
    if e_phentsize < 32 {
        return Err(Error::InvalidPrxHeader(format!(
            "program header entry size {e_phentsize} is too small"
        )));
    }

    // --- Program headers ---
    let mut segments = Vec::new();
    let mut modinfo_offset = None;

    for i in 0..e_phnum {
        let base =
            e_phoff
                .checked_add(i.checked_mul(e_phentsize).ok_or_else(|| {
                    Error::InvalidPrxHeader("program header table overflows".into())
                })?)
                .ok_or_else(|| Error::InvalidPrxHeader("program header table overflows".into()))?;

        let p_type = read_u32(data, base)?;
        if p_type != PT_LOAD {
            continue;
        }
        let p_paddr = read_u32(data, base + 0x0C)?;
        let segment = Segment {
            address: read_u32(data, base + 0x08)?, // p_vaddr
            file_size: read_u32(data, base + 0x10)?,
            mem_size: read_u32(data, base + 0x14)?,
            align: read_u32(data, base + 0x1C)?,
        };

        // In a PRX the first loadable segment's p_paddr carries the file offset
        // of the module-info structure; the top bit is a flag.
        if modinfo_offset.is_none() {
            modinfo_offset = Some(p_paddr & 0x7FFF_FFFF);
        }
        segments.push(segment);
    }

    if segments.is_empty() {
        return Err(Error::InvalidPrxHeader(
            "ELF has no loadable segments".into(),
        ));
    }
    if segments.len() > MAX_SEGMENTS {
        return Err(Error::InvalidPrxHeader(format!(
            "{} loadable segments, but a ~PSP header describes at most {MAX_SEGMENTS}",
            segments.len()
        )));
    }

    let modinfo_offset = modinfo_offset.expect("set alongside the first segment");

    // --- Module info ---
    let (name, attributes, version_lo, version_hi) =
        read_module_info(data, modinfo_offset as usize)?;

    Ok(ModuleInfo {
        name,
        attributes,
        version_lo,
        version_hi,
        entry: e_entry,
        modinfo_offset,
        segments,
        elf_size: u32::try_from(data.len()).map_err(|_| Error::PayloadTooLarge {
            size: data.len() as u64,
            max: u32::MAX as u64,
        })?,
        is_prx: e_type == ET_SCE_PRX,
    })
}

/// Read the `PspModuleInfo` structure: attributes, version, then a 28-byte name.
fn read_module_info(data: &[u8], offset: usize) -> Result<(String, u16, u8, u8)> {
    let attributes = read_u16(data, offset).map_err(|_| {
        Error::InvalidPrxHeader(format!(
            "module info offset {offset:#X} is outside the file"
        ))
    })?;
    let version_lo = read_u8(data, offset + 2)?;
    let version_hi = read_u8(data, offset + 3)?;
    let name_field: [u8; 28] = read_array(data, offset + 4)
        .map_err(|_| Error::InvalidPrxHeader("module info name field is truncated".into()))?;
    Ok((
        cstr_from_field(&name_field),
        attributes,
        version_lo,
        version_hi,
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a minimal but well-formed PSP PRX for testing.
    pub(crate) fn synthetic_prx(name: &str, payload_len: usize) -> Vec<u8> {
        let phoff = 52usize;
        let modinfo_off = 0x100usize;
        let mut data = vec![0u8; 0x100 + 0x40 + payload_len];

        data[0..4].copy_from_slice(&ELF_MAGIC);
        data[4] = ELFCLASS32;
        data[5] = ELFDATA2LSB;
        data[6] = 1;
        data[0x10..0x12].copy_from_slice(&ET_SCE_PRX.to_le_bytes());
        data[0x12..0x14].copy_from_slice(&EM_MIPS.to_le_bytes());
        data[0x18..0x1C].copy_from_slice(&0x1_0258u32.to_le_bytes()); // e_entry
        data[0x1C..0x20].copy_from_slice(&(phoff as u32).to_le_bytes());
        data[0x28..0x2A].copy_from_slice(&52u16.to_le_bytes()); // e_ehsize
        data[0x2A..0x2C].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
        data[0x2C..0x2E].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

        // One PT_LOAD segment.
        data[phoff..phoff + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        data[phoff + 4..phoff + 8].copy_from_slice(&0x120u32.to_le_bytes()); // p_offset
        data[phoff + 8..phoff + 12].copy_from_slice(&0u32.to_le_bytes()); // p_vaddr
        data[phoff + 12..phoff + 16].copy_from_slice(&(modinfo_off as u32).to_le_bytes());
        data[phoff + 16..phoff + 20].copy_from_slice(&0x3000u32.to_le_bytes()); // p_filesz
        data[phoff + 20..phoff + 24].copy_from_slice(&0x5000u32.to_le_bytes()); // p_memsz
        data[phoff + 28..phoff + 32].copy_from_slice(&0x10u32.to_le_bytes()); // p_align

        // Module info.
        data[modinfo_off..modinfo_off + 2].copy_from_slice(&0u16.to_le_bytes());
        data[modinfo_off + 2] = 1; // version lo
        data[modinfo_off + 3] = 1; // version hi
        let n = name.len().min(27);
        data[modinfo_off + 4..modinfo_off + 4 + n].copy_from_slice(&name.as_bytes()[..n]);
        data
    }

    #[test]
    fn parses_a_synthetic_prx() {
        let data = synthetic_prx("my_module", 1024);
        let m = parse_module(&data).unwrap();
        assert_eq!(m.name, "my_module");
        assert_eq!(m.entry, 0x1_0258);
        assert_eq!(m.modinfo_offset, 0x100);
        assert_eq!(m.segments.len(), 1);
        assert_eq!(m.segments[0].file_size, 0x3000);
        assert_eq!(m.bss_size(), 0x2000);
        assert!(m.is_prx);
        assert_eq!(m.elf_size as usize, data.len());
    }

    #[test]
    fn rejects_non_elf_input() {
        assert!(parse_module(b"not an elf at all").is_err());
        assert!(parse_module(&[]).is_err());
        assert!(parse_module(&[0x7F, b'E']).is_err());
    }

    #[test]
    fn rejects_wrong_class_endianness_and_machine() {
        let base = synthetic_prx("m", 16);

        let mut d = base.clone();
        d[4] = 2; // 64-bit
        assert!(parse_module(&d).is_err());

        let mut d = base.clone();
        d[5] = 2; // big endian
        assert!(parse_module(&d).is_err());

        let mut d = base.clone();
        d[0x12..0x14].copy_from_slice(&3u16.to_le_bytes()); // x86
        assert!(parse_module(&d).is_err());
    }

    #[test]
    fn rejects_missing_segments() {
        let mut d = synthetic_prx("m", 16);
        d[0x2C..0x2E].copy_from_slice(&0u16.to_le_bytes()); // e_phnum = 0
        assert!(parse_module(&d).is_err());

        let mut d = synthetic_prx("m", 16);
        d[52..56].copy_from_slice(&7u32.to_le_bytes()); // not PT_LOAD
        assert!(parse_module(&d).is_err());
    }

    #[test]
    fn rejects_out_of_range_offsets_without_panicking() {
        // Program header table far past EOF.
        let mut d = synthetic_prx("m", 16);
        d[0x1C..0x20].copy_from_slice(&0xFFFF_F000u32.to_le_bytes());
        assert!(parse_module(&d).is_err());

        // Module info offset past EOF.
        let mut d = synthetic_prx("m", 16);
        d[52 + 12..52 + 16].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
        assert!(parse_module(&d).is_err());

        // Absurd program header count.
        let mut d = synthetic_prx("m", 16);
        d[0x2C..0x2E].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert!(parse_module(&d).is_err());
    }

    #[test]
    fn truncated_files_error_cleanly() {
        let full = synthetic_prx("mod", 512);
        for cut in [1usize, 8, 32, 52, 64, 100, 200] {
            // Must not panic at any truncation point.
            let _ = parse_module(&full[..cut.min(full.len())]);
        }
    }
}
