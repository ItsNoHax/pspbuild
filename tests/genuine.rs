//! Differential tests against genuine Sony-produced files.
//!
//! These are the strongest checks in the suite: the inputs were produced by
//! Sony's own tooling, not by this crate, so passing them means the KIRK
//! container, both CMACs and the header layout agree with the real thing rather
//! than merely with themselves.
//!
//! The files cannot be redistributed, so the tests look for them and skip when
//! they are absent. Drop them in `plans/`, which is gitignored.

use std::path::PathBuf;

use pspbuild::psp::header::PspModuleHeader;
use pspbuild::psp::tag::TAG_DEMO_280;
use pspbuild::{Category, EncryptOptions, decrypt_prx, encrypt_prx, inspect_prx, verify_prx};

fn plans_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("plans")
}

/// Find a file under `plans/` whose name contains `needle`, case-insensitively.
fn find(needle: &str) -> Option<PathBuf> {
    fn walk(dir: &PathBuf, needle: &str, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, needle, out);
            } else if path
                .to_str()
                .is_some_and(|s| s.to_lowercase().contains(needle))
            {
                out.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(&plans_dir(), &needle.to_lowercase(), &mut found);
    found.sort();
    found.into_iter().next()
}

/// A genuine Sony demo EBOOT, encrypted under the same tag this tool emits.
fn ape_academy() -> Option<Vec<u8>> {
    let path = find("ape academy")?;
    std::fs::read(path).ok()
}

macro_rules! sony_eboot_or_skip {
    () => {
        match ape_academy() {
            Some(data) => data,
            None => {
                eprintln!("no genuine Sony EBOOT available; skipping");
                return;
            }
        }
    };
}

#[test]
fn a_genuine_sony_module_verifies_completely() {
    let eboot = sony_eboot_or_skip!();

    // Every check, against a file this crate did not produce. If the KIRK
    // container layout or either CMAC were subtly wrong, this is where it
    // would show, because Sony computed them and we are re-deriving them.
    let result = verify_prx(&eboot).expect("Sony EBOOT must verify");
    assert!(
        result.checks.iter().any(|c| c.contains("CMAC")),
        "CMAC check did not run"
    );
    assert!(result.module.is_some(), "recovered payload is not a module");
    assert_eq!(result.recovered_size, 7_657_824);
}

#[test]
fn a_genuine_sony_module_uses_the_tag_this_tool_emits() {
    let eboot = sony_eboot_or_skip!();
    let info = inspect_prx(&eboot).unwrap();

    // This is why the file is useful as a fixture at all.
    assert_eq!(info.tag, Some(TAG_DEMO_280.tag));
    assert!(info.encrypted);
    // Sony shipped this one uncompressed, which the size fields confirm.
    assert!(!info.compressed);
}

#[test]
fn the_demo_is_a_memory_stick_game_not_an_npdrm_download() {
    // Worth pinning: a downloadable *demo* is still CATEGORY=MG with an empty
    // DATA.PSAR. It is not an EG/NPDRM container and carries no NPUMDIMG, so
    // it does not serve as a fixture for that work.
    let eboot = sony_eboot_or_skip!();
    let pbp = pspbuild::pbp::Pbp::parse(&eboot).unwrap();

    assert_eq!(pbp.category(), Some(Category::Mg));
    assert!(pbp.data_psar().is_empty(), "an MG demo carries no archive");
    assert!(
        !eboot.windows(8).any(|w| w == b"NPUMDIMG"),
        "unexpectedly found NPUMDIMG in an MG container"
    );
}

#[test]
fn our_header_matches_sony_on_every_field_we_derive_from_the_elf() {
    let eboot = sony_eboot_or_skip!();
    let module = decrypt_prx(&eboot).expect("Sony module decrypts");

    let ours = encrypt_prx(
        &module,
        &EncryptOptions {
            compress: false,
            ..Default::default()
        },
    )
    .unwrap();

    let sony = PspModuleHeader::parse(pspbuild::pbp::Pbp::parse(&eboot).unwrap().data_psp())
        .expect("Sony header parses");
    let mine = PspModuleHeader::parse(&ours.data).expect("our header parses");

    // Sizing agrees exactly, which is the headline claim of this project: the
    // same module produces the same container size Sony's tooling produced.
    assert_eq!(mine.psp_size, sony.psp_size, "psp_size");
    assert_eq!(mine.elf_size, sony.elf_size, "elf_size");
    assert_eq!(ours.data.len(), sony.psp_size as usize);

    assert_eq!(mine.mod_attribute, sony.mod_attribute, "mod_attribute");
    assert_eq!(mine.comp_attribute, sony.comp_attribute, "comp_attribute");
    assert_eq!(mine.modname, sony.modname, "modname");
    assert_eq!(mine.nsegments, sony.nsegments, "nsegments");
    assert_eq!(mine.boot_entry, sony.boot_entry, "boot_entry");
    assert_eq!(mine.modinfo_offset, sony.modinfo_offset, "modinfo_offset");
    assert_eq!(mine.decrypt_mode, sony.decrypt_mode, "decrypt_mode");
    assert_eq!(mine.module_ver_lo, sony.module_ver_lo, "module_ver_lo");
    assert_eq!(mine.module_ver_hi, sony.module_ver_hi, "module_ver_hi");
    assert_eq!(mine.devkit_version, sony.devkit_version, "devkit_version");

    for i in 0..sony.nsegments.min(4) as usize {
        assert_eq!(mine.seg_align[i], sony.seg_align[i], "seg_align[{i}]");
        assert_eq!(mine.seg_address[i], sony.seg_address[i], "seg_address[{i}]");
    }
    // seg_size[0] agrees because Sony's first segment has p_filesz == p_memsz;
    // it does not distinguish the two rules. See the next test.
    assert_eq!(mine.seg_size[0], sony.seg_size[0], "seg_size[0]");
}

#[test]
fn the_two_fields_where_we_diverge_from_sony_are_known_and_unresolved() {
    // Pinned deliberately. These are open questions, not settled behaviour, and
    // this test exists so that changing either one is a visible decision rather
    // than a silent drift. See docs/FORMAT.md and docs/COMPATIBILITY.md.
    let eboot = sony_eboot_or_skip!();
    let module = decrypt_prx(&eboot).unwrap();
    let ours = encrypt_prx(
        &module,
        &EncryptOptions {
            compress: false,
            ..Default::default()
        },
    )
    .unwrap();

    let sony =
        PspModuleHeader::parse(pspbuild::pbp::Pbp::parse(&eboot).unwrap().data_psp()).unwrap();
    let mine = PspModuleHeader::parse(&ours.data).unwrap();

    // 1. seg_size beyond the first segment. Sony writes p_memsz (166332); this
    //    tool writes p_filesz (19744). Hardware confirmed p_filesz is required
    //    for a single-segment module, but that test could not reach segment 1.
    assert_eq!(sony.seg_size[1], 166_332, "Sony writes p_memsz");
    assert_eq!(mine.seg_size[1], 19_744, "we write p_filesz");

    // 2. bss_size. We write the summed (p_memsz - p_filesz) over PT_LOAD.
    //    Sony writes a value that is exactly the negation of the PT_PRXRELOC
    //    segment's p_filesz, which does not look like a bss size at all and
    //    suggests the field's meaning is not what its conventional name says.
    assert_eq!(mine.bss_size, 146_588, "sum of PT_LOAD bss");
    assert_eq!(sony.bss_size, 0xFFFA_3130, "Sony's value");
    assert_eq!(
        (sony.bss_size as i32).unsigned_abs(),
        380_624,
        "matches the PT_PRXRELOC filesz exactly"
    );
}

#[test]
fn we_produce_a_far_smaller_container_than_sony_shipped() {
    let eboot = sony_eboot_or_skip!();
    let module = decrypt_prx(&eboot).unwrap();

    // Sony shipped this demo uncompressed. Compression is the whole reason the
    // rebuilt container is a third of the size.
    let ours = encrypt_prx(&module, &EncryptOptions::default()).unwrap();
    assert!(ours.compressed);
    assert!(
        ours.data.len() * 2 < eboot.len(),
        "expected a large saving, got {} from {}",
        ours.data.len(),
        eboot.len()
    );
    // And it still round-trips to exactly what Sony encrypted.
    assert_eq!(decrypt_prx(&ours.data).unwrap(), module);
}
