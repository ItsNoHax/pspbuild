//! Shared helpers for the integration tests.
#![allow(dead_code)] // shared across test binaries; each uses a subset

/// Build a minimal but well-formed PSP PRX whose payload is `payload` bytes of
/// pseudo-random, poorly compressible data.
pub fn make_prx(name: &str, payload_len: usize) -> Vec<u8> {
    make_prx_with(name, payload_len, |i| {
        // A splitmix64 finaliser: well-distributed enough that gzip cannot
        // shrink it, without pulling in an RNG dependency.
        let mut z = (i as u64).wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        (z ^ (z >> 31)) as u8
    })
}

/// Build a PRX whose payload bytes come from `fill`.
pub fn make_prx_with(name: &str, payload_len: usize, fill: impl Fn(usize) -> u8) -> Vec<u8> {
    const PHOFF: usize = 52;
    const MODINFO: usize = 0x100;
    const BODY: usize = 0x140;

    let mut data = vec![0u8; BODY + payload_len];

    data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    data[4] = 1; // ELFCLASS32
    data[5] = 1; // little endian
    data[6] = 1; // version
    data[0x10..0x12].copy_from_slice(&0xFFA0u16.to_le_bytes()); // ET_SCE_PRX
    data[0x12..0x14].copy_from_slice(&8u16.to_le_bytes()); // EM_MIPS
    data[0x18..0x1C].copy_from_slice(&0x1_0258u32.to_le_bytes()); // e_entry
    data[0x1C..0x20].copy_from_slice(&(PHOFF as u32).to_le_bytes());
    data[0x28..0x2A].copy_from_slice(&52u16.to_le_bytes());
    data[0x2A..0x2C].copy_from_slice(&32u16.to_le_bytes());
    data[0x2C..0x2E].copy_from_slice(&1u16.to_le_bytes());

    // One PT_LOAD segment; p_paddr carries the module-info offset.
    data[PHOFF..PHOFF + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    data[PHOFF + 4..PHOFF + 8].copy_from_slice(&0x120u32.to_le_bytes());
    data[PHOFF + 8..PHOFF + 12].copy_from_slice(&0u32.to_le_bytes());
    data[PHOFF + 12..PHOFF + 16].copy_from_slice(&(MODINFO as u32).to_le_bytes());
    data[PHOFF + 16..PHOFF + 20].copy_from_slice(&(payload_len as u32).to_le_bytes());
    data[PHOFF + 20..PHOFF + 24].copy_from_slice(&((payload_len + 0x1000) as u32).to_le_bytes());
    data[PHOFF + 28..PHOFF + 32].copy_from_slice(&0x10u32.to_le_bytes());

    // Module info.
    data[MODINFO + 2] = 1;
    data[MODINFO + 3] = 1;
    let n = name.len().min(27);
    data[MODINFO + 4..MODINFO + 4 + n].copy_from_slice(&name.as_bytes()[..n]);

    for i in 0..payload_len {
        data[BODY + i] = fill(i);
    }
    data
}

/// Size of the `~PSP` header, i.e. the entire per-file overhead.
pub const PSP_HEADER_SIZE: usize = 0x150;
