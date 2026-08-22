//! The `~PSP` module header.
//!
//! The encrypted PRX begins with a 0x150-byte header. Its first 0x80 bytes are
//! plain module metadata; the remainder carries the KIRK key block, the size
//! metadata, the tag and the integrity hash.
//!
//! ```text
//! 0x00  signature "~PSP"       0x3C  seg_align[4]: u16
//! 0x04  mod_attribute: u16     0x44  seg_address[4]: u32
//! 0x06  comp_attribute: u16    0x54  seg_size[4]: u32
//! 0x08  module_ver_lo: u8      0x64  reserved[5]: u32
//! 0x09  module_ver_hi: u8      0x78  devkit_version: u32
//! 0x0A  modname[28]            0x7C  decrypt_mode: u8
//! 0x26  mod_version: u8        0x7D  padding: u8
//! 0x27  nsegments: u8          0x7E  overlap_size: u16
//! 0x28  elf_size: u32          ----  end of the metadata region (0x80)
//! 0x2C  psp_size: u32
//! 0x30  boot_entry: u32
//! 0x34  modinfo_offset: u32
//! 0x38  bss_size: u32
//! ```
//!
//! The 0x00..0x80 region is significant beyond being metadata: KIRK stores a
//! verbatim copy of it as the container's "predata", so it is covered by the
//! data CMAC.

use crate::error::{Error, Result};
use crate::format::{
    cstr_from_field, read_array, read_u8, read_u16, read_u32, write_u16, write_u32,
};

/// Size of the plain metadata region, and of the KIRK predata.
pub const METADATA_SIZE: usize = 0x80;

/// Size of the complete encrypted-PRX header.
pub const PSP_HEADER_SIZE: usize = 0x150;

/// The `~PSP` magic.
pub const PSP_MAGIC: [u8; 4] = [0x7E, 0x50, 0x53, 0x50];

/// `comp_attribute` bit indicating a gzip-compressed payload.
pub const COMP_ATTRIBUTE_GZIP: u16 = 1;

/// The `~PSP` metadata region (0x00..0x80), typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PspModuleHeader {
    pub mod_attribute: u16,
    pub comp_attribute: u16,
    pub module_ver_lo: u8,
    pub module_ver_hi: u8,
    /// Module name, NUL-padded to 28 bytes on disk.
    pub modname: String,
    pub mod_version: u8,
    pub nsegments: u8,
    /// Size of the decrypted ELF.
    pub elf_size: u32,
    /// Size of the whole `~PSP` image.
    pub psp_size: u32,
    pub boot_entry: u32,
    pub modinfo_offset: u32,
    pub bss_size: u32,
    pub seg_align: [u16; 4],
    pub seg_address: [u32; 4],
    pub seg_size: [u32; 4],
    pub devkit_version: u32,
    pub decrypt_mode: u8,
    pub overlap_size: u16,
    /// Reserved words, preserved verbatim across a parse/build cycle.
    pub(crate) reserved: [u32; 5],
    /// Byte 0x7D, preserved verbatim.
    pub(crate) padding: u8,
}

impl Default for PspModuleHeader {
    fn default() -> Self {
        PspModuleHeader {
            mod_attribute: 0,
            comp_attribute: 0,
            module_ver_lo: 1,
            module_ver_hi: 1,
            modname: String::new(),
            mod_version: 1,
            nsegments: 1,
            elf_size: 0,
            psp_size: 0,
            boot_entry: 0,
            modinfo_offset: 0,
            bss_size: 0,
            seg_align: [0; 4],
            seg_address: [0; 4],
            seg_size: [0; 4],
            devkit_version: 0,
            decrypt_mode: 0,
            overlap_size: 0,
            reserved: [0; 5],
            padding: 0,
        }
    }
}

impl PspModuleHeader {
    /// Parse the metadata region from the start of `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < METADATA_SIZE {
            return Err(Error::TooShort {
                expected: METADATA_SIZE,
                actual: buf.len(),
            });
        }
        let magic: [u8; 4] = read_array(buf, 0)?;
        if magic != PSP_MAGIC {
            return Err(Error::InvalidPrxHeader(format!(
                "bad magic {magic:02X?}, expected ~PSP"
            )));
        }

        let mut seg_align = [0u16; 4];
        let mut seg_address = [0u32; 4];
        let mut seg_size = [0u32; 4];
        let mut reserved = [0u32; 5];
        for i in 0..4 {
            seg_align[i] = read_u16(buf, 0x3C + i * 2)?;
            seg_address[i] = read_u32(buf, 0x44 + i * 4)?;
            seg_size[i] = read_u32(buf, 0x54 + i * 4)?;
        }
        for (i, slot) in reserved.iter_mut().enumerate() {
            *slot = read_u32(buf, 0x64 + i * 4)?;
        }

        Ok(PspModuleHeader {
            mod_attribute: read_u16(buf, 0x04)?,
            comp_attribute: read_u16(buf, 0x06)?,
            module_ver_lo: read_u8(buf, 0x08)?,
            module_ver_hi: read_u8(buf, 0x09)?,
            modname: cstr_from_field(&read_array::<28>(buf, 0x0A)?),
            mod_version: read_u8(buf, 0x26)?,
            nsegments: read_u8(buf, 0x27)?,
            elf_size: read_u32(buf, 0x28)?,
            psp_size: read_u32(buf, 0x2C)?,
            boot_entry: read_u32(buf, 0x30)?,
            modinfo_offset: read_u32(buf, 0x34)?,
            bss_size: read_u32(buf, 0x38)?,
            seg_align,
            seg_address,
            seg_size,
            devkit_version: read_u32(buf, 0x78)?,
            decrypt_mode: read_u8(buf, 0x7C)?,
            padding: read_u8(buf, 0x7D)?,
            overlap_size: read_u16(buf, 0x7E)?,
            reserved,
        })
    }

    /// Serialise the metadata region.
    pub fn to_bytes(&self) -> [u8; METADATA_SIZE] {
        let mut buf = [0u8; METADATA_SIZE];
        buf[0..4].copy_from_slice(&PSP_MAGIC);
        write_u16(&mut buf, 0x04, self.mod_attribute);
        write_u16(&mut buf, 0x06, self.comp_attribute);
        buf[0x08] = self.module_ver_lo;
        buf[0x09] = self.module_ver_hi;

        let name = self.modname.as_bytes();
        let n = name.len().min(27); // always leave a NUL terminator
        buf[0x0A..0x0A + n].copy_from_slice(&name[..n]);

        buf[0x26] = self.mod_version;
        buf[0x27] = self.nsegments;
        write_u32(&mut buf, 0x28, self.elf_size);
        write_u32(&mut buf, 0x2C, self.psp_size);
        write_u32(&mut buf, 0x30, self.boot_entry);
        write_u32(&mut buf, 0x34, self.modinfo_offset);
        write_u32(&mut buf, 0x38, self.bss_size);
        for i in 0..4 {
            write_u16(&mut buf, 0x3C + i * 2, self.seg_align[i]);
            write_u32(&mut buf, 0x44 + i * 4, self.seg_address[i]);
            write_u32(&mut buf, 0x54 + i * 4, self.seg_size[i]);
        }
        for (i, word) in self.reserved.iter().enumerate() {
            write_u32(&mut buf, 0x64 + i * 4, *word);
        }
        write_u32(&mut buf, 0x78, self.devkit_version);
        buf[0x7C] = self.decrypt_mode;
        buf[0x7D] = self.padding;
        write_u16(&mut buf, 0x7E, self.overlap_size);
        buf
    }

    /// Whether the payload is gzip-compressed.
    pub fn is_compressed(&self) -> bool {
        self.comp_attribute & COMP_ATTRIBUTE_GZIP != 0
    }

    /// Set or clear the gzip compression flag.
    pub fn set_compressed(&mut self, compressed: bool) {
        if compressed {
            self.comp_attribute |= COMP_ATTRIBUTE_GZIP;
        } else {
            self.comp_attribute &= !COMP_ATTRIBUTE_GZIP;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PspModuleHeader {
        PspModuleHeader {
            modname: "test_module".into(),
            elf_size: 0x1234,
            psp_size: 0x2345,
            boot_entry: 0x88000000,
            nsegments: 2,
            seg_size: [1, 2, 3, 4],
            ..Default::default()
        }
    }

    #[test]
    fn round_trips_through_bytes() {
        let h = sample();
        assert_eq!(PspModuleHeader::parse(&h.to_bytes()).unwrap(), h);
    }

    #[test]
    fn writes_the_psp_magic() {
        assert_eq!(&sample().to_bytes()[..4], b"~PSP");
    }

    #[test]
    fn rejects_foreign_magic() {
        let mut buf = sample().to_bytes();
        buf[0] = b'X';
        assert!(matches!(
            PspModuleHeader::parse(&buf).unwrap_err(),
            Error::InvalidPrxHeader(_)
        ));
    }

    #[test]
    fn rejects_short_input() {
        assert!(PspModuleHeader::parse(&[]).is_err());
        assert!(PspModuleHeader::parse(&[0u8; 0x7F]).is_err());
    }

    #[test]
    fn module_name_is_always_nul_terminated() {
        let h = PspModuleHeader {
            modname: "x".repeat(64),
            ..Default::default()
        };
        let bytes = h.to_bytes();
        // 28-byte field at 0x0A: the final byte must remain NUL.
        assert_eq!(bytes[0x0A + 27], 0);
        assert_eq!(PspModuleHeader::parse(&bytes).unwrap().modname.len(), 27);
    }

    #[test]
    fn preserves_reserved_words() {
        let mut h = sample();
        h.reserved = [1, 2, 3, 4, 5];
        h.padding = 0x7F;
        let parsed = PspModuleHeader::parse(&h.to_bytes()).unwrap();
        assert_eq!(parsed.reserved, [1, 2, 3, 4, 5]);
        assert_eq!(parsed.padding, 0x7F);
    }

    #[test]
    fn compression_flag_round_trips() {
        let mut h = sample();
        assert!(!h.is_compressed());
        h.set_compressed(true);
        assert!(h.is_compressed());
        assert!(
            PspModuleHeader::parse(&h.to_bytes())
                .unwrap()
                .is_compressed()
        );
        h.set_compressed(false);
        assert!(!h.is_compressed());
    }
}
