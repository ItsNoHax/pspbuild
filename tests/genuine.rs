//! Differential tests against genuine Sony-produced files.
//!
//! These are the strongest checks in the suite: the inputs were produced by
//! Sony's own tooling, not by this crate, so passing them means the KIRK
//! container, both CMACs and the header layout agree with the real thing rather
//! than merely with themselves.
//!
//! The files cannot be redistributed, so the tests discover whatever is present
//! and skip when there is nothing. Drop EBOOTs in `plans/`, which is gitignored.
//!
//! Assertions are written as *rules* derived from each module's own ELF rather
//! than as constants from one file, so adding another EBOOT strengthens them
//! without any edits here.

use std::path::PathBuf;

use pspbuild::pbp::Pbp;
use pspbuild::psp::header::PspModuleHeader;
use pspbuild::psp::tag::TAG_DEMO_280;
use pspbuild::{Category, EncryptOptions, decrypt_prx, encrypt_prx, inspect_prx, verify_prx};

/// A genuine Sony EBOOT found on disk.
struct SonyEboot {
    name: String,
    eboot: Vec<u8>,
}

impl SonyEboot {
    fn data_psp(&self) -> Vec<u8> {
        Pbp::parse(&self.eboot).unwrap().data_psp().to_vec()
    }

    fn header(&self) -> PspModuleHeader {
        PspModuleHeader::parse(&self.data_psp()).expect("Sony header parses")
    }
}

/// One ELF program header, reduced to what matters here.
#[derive(Debug, Clone, Copy)]
struct Segment {
    kind: u32,
    filesz: u32,
    memsz: u32,
}

const PT_LOAD: u32 = 1;
const PT_PRXRELOC: u32 = 0x7000_00A0;

/// Parse the program headers of a decrypted module.
fn segments(elf: &[u8]) -> Vec<Segment> {
    let u32_at = |o: usize| u32::from_le_bytes(elf[o..o + 4].try_into().unwrap());
    let u16_at = |o: usize| u16::from_le_bytes(elf[o..o + 2].try_into().unwrap());

    let phoff = u32_at(0x1C) as usize;
    let phentsize = u16_at(0x2A) as usize;
    let phnum = u16_at(0x2C) as usize;

    (0..phnum)
        .map(|i| {
            let o = phoff + i * phentsize;
            Segment {
                kind: u32_at(o),
                filesz: u32_at(o + 0x10),
                memsz: u32_at(o + 0x14),
            }
        })
        .collect()
}

/// Every genuine Sony EBOOT under `plans/`, encrypted with the tag this tool
/// emits. Anything else found there is ignored rather than failing the run.
fn sony_eboots() -> Vec<SonyEboot> {
    fn walk(dir: &PathBuf, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("pbp"))
            {
                out.push(path);
            }
        }
    }

    let mut paths = Vec::new();
    walk(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("plans"),
        &mut paths,
    );
    paths.sort();

    paths
        .into_iter()
        .filter_map(|path| {
            let eboot = std::fs::read(&path).ok()?;
            // Only files this crate's tag applies to are usable as fixtures.
            let info = inspect_prx(&eboot).ok()?;
            if info.tag != Some(TAG_DEMO_280.tag) {
                return None;
            }
            let name = Pbp::parse(&eboot)
                .ok()
                .and_then(|p| p.param_sfo().ok())
                .and_then(|s| s.get_text("TITLE"))
                .unwrap_or_else(|| path.display().to_string());
            Some(SonyEboot { name, eboot })
        })
        .collect()
}

/// Run `body` over every discovered fixture, skipping if there are none.
fn for_each_sony(body: impl Fn(&SonyEboot)) {
    let fixtures = sony_eboots();
    if fixtures.is_empty() {
        eprintln!("no genuine Sony EBOOTs available; skipping");
        return;
    }
    for fixture in &fixtures {
        eprintln!("  checking {}", fixture.name);
        body(fixture);
    }
}

#[test]
fn every_sony_eboot_verifies_completely() {
    for_each_sony(|f| {
        // Sony computed the SHA-1 and both CMAC tags; this re-derives them. If
        // the container layout or either MAC were subtly wrong, it shows here
        // and nowhere else, because every other test checks us against us.
        let result = verify_prx(&f.eboot).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        assert!(
            result.checks.iter().any(|c| c.contains("CMAC")),
            "{}: CMAC check did not run",
            f.name
        );
        assert!(
            result.module.is_some(),
            "{}: payload is not a module",
            f.name
        );
    });
}

#[test]
fn none_of_the_available_fixtures_are_eg() {
    // Demos and firmware updates are all CATEGORY=MG with an empty DATA.PSAR.
    // Recorded so the absence of an EG fixture stays visible rather than being
    // rediscovered each time one of these files is mistaken for one.
    for_each_sony(|f| {
        let pbp = Pbp::parse(&f.eboot).unwrap();
        assert_eq!(pbp.category(), Some(Category::Mg), "{}", f.name);
        assert!(pbp.data_psar().is_empty(), "{}: unexpected archive", f.name);
        assert!(
            !f.eboot.windows(8).any(|w| w == b"NPUMDIMG"),
            "{}: found NPUMDIMG in an MG container",
            f.name
        );
    });
}

#[test]
fn our_header_matches_sony_on_every_field_the_loader_derives_from_the_elf() {
    for_each_sony(|f| {
        let module = decrypt_prx(&f.eboot).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        let ours = encrypt_prx(
            &module,
            &EncryptOptions {
                compress: false,
                ..Default::default()
            },
        )
        .unwrap();

        let sony = f.header();
        let mine = PspModuleHeader::parse(&ours.data).unwrap();
        let at = |field: &str| format!("{}: {field}", f.name);

        // Sizing agrees exactly: the same module produces the same container
        // size Sony's own tooling produced. That is the headline claim.
        assert_eq!(mine.psp_size, sony.psp_size, "{}", at("psp_size"));
        assert_eq!(mine.elf_size, sony.elf_size, "{}", at("elf_size"));
        assert_eq!(ours.data.len(), sony.psp_size as usize, "{}", at("length"));

        assert_eq!(
            mine.mod_attribute,
            sony.mod_attribute,
            "{}",
            at("mod_attribute")
        );
        assert_eq!(
            mine.comp_attribute,
            sony.comp_attribute,
            "{}",
            at("comp_attribute")
        );
        assert_eq!(mine.modname, sony.modname, "{}", at("modname"));
        assert_eq!(mine.nsegments, sony.nsegments, "{}", at("nsegments"));
        assert_eq!(mine.boot_entry, sony.boot_entry, "{}", at("boot_entry"));
        assert_eq!(
            mine.modinfo_offset,
            sony.modinfo_offset,
            "{}",
            at("modinfo_offset")
        );
        assert_eq!(
            mine.decrypt_mode,
            sony.decrypt_mode,
            "{}",
            at("decrypt_mode")
        );
        assert_eq!(
            mine.module_ver_lo,
            sony.module_ver_lo,
            "{}",
            at("module_ver_lo")
        );
        assert_eq!(
            mine.module_ver_hi,
            sony.module_ver_hi,
            "{}",
            at("module_ver_hi")
        );
        assert_eq!(
            mine.devkit_version,
            sony.devkit_version,
            "{}",
            at("devkit_version")
        );

        for i in 0..sony.nsegments.min(4) as usize {
            assert_eq!(mine.seg_align[i], sony.seg_align[i], "{}", at("seg_align"));
            assert_eq!(
                mine.seg_address[i],
                sony.seg_address[i],
                "{}",
                at("seg_address")
            );
        }
        // seg_size[0] is the one size field the loader enforces, and both agree
        // on it. See docs/FORMAT.md section 8a.
        assert_eq!(mine.seg_size[0], sony.seg_size[0], "{}", at("seg_size[0]"));
    });
}

#[test]
fn sony_writes_p_memsz_for_segments_after_the_first() {
    // A rule, checked against each module's own ELF. Both known fixtures obey
    // it, and this crate deliberately writes p_filesz instead — the loader
    // accepts either, confirmed by booting a rebuilt module on hardware.
    for_each_sony(|f| {
        let module = decrypt_prx(&f.eboot).unwrap();
        let loads: Vec<_> = segments(&module)
            .into_iter()
            .filter(|s| s.kind == PT_LOAD)
            .collect();
        let sony = f.header();

        for (i, seg) in loads.iter().enumerate().skip(1) {
            assert_eq!(
                sony.seg_size[i], seg.memsz,
                "{}: seg_size[{i}] is not p_memsz",
                f.name
            );
        }

        // Sony's own segment 0 always has filesz == memsz in the samples seen,
        // so it never distinguishes the two rules. Assert that rather than
        // silently relying on it — if a fixture ever breaks this, seg_size[0]
        // becomes directly observable and worth re-examining.
        if let Some(first) = loads.first() {
            assert_eq!(
                first.filesz, first.memsz,
                "{}: segment 0 differs — this fixture CAN distinguish the \
                 seg_size[0] rule, so check what Sony wrote",
                f.name
            );
        }
    });
}

#[test]
fn sonys_bss_size_is_the_negated_relocation_size() {
    // Not a bss size at all. Confirmed exactly on every fixture: the field
    // holds -(PT_PRXRELOC p_filesz), which means its conventional name is
    // wrong. The loader does not validate it — this crate writes the summed
    // PT_LOAD bss instead and those builds boot.
    for_each_sony(|f| {
        let module = decrypt_prx(&f.eboot).unwrap();
        let segs = segments(&module);
        let Some(reloc) = segs.iter().find(|s| s.kind == PT_PRXRELOC) else {
            return;
        };

        let sony_bss = f.header().bss_size as i32;
        assert_eq!(
            sony_bss,
            -(reloc.filesz as i32),
            "{}: bss_size {:#010x} is not -(PT_PRXRELOC filesz {})",
            f.name,
            f.header().bss_size,
            reloc.filesz
        );

        // And what this crate writes instead: the actual bss.
        let ours = encrypt_prx(
            &module,
            &EncryptOptions {
                compress: false,
                ..Default::default()
            },
        )
        .unwrap();
        let expected: u32 = segs
            .iter()
            .filter(|s| s.kind == PT_LOAD)
            .map(|s| s.memsz - s.filesz)
            .sum();
        assert_eq!(
            PspModuleHeader::parse(&ours.data).unwrap().bss_size,
            expected,
            "{}: our bss_size is not the summed PT_LOAD bss",
            f.name
        );
    });
}

#[test]
fn we_produce_a_far_smaller_container_than_sony_shipped() {
    for_each_sony(|f| {
        let module = decrypt_prx(&f.eboot).unwrap();
        // Sony shipped these uncompressed; compression is the whole saving.
        let ours = encrypt_prx(&module, &EncryptOptions::default()).unwrap();
        assert!(ours.compressed, "{}", f.name);
        assert!(
            ours.data.len() < f.eboot.len(),
            "{}: {} is not smaller than {}",
            f.name,
            ours.data.len(),
            f.eboot.len()
        );
        // And it still round-trips to exactly what Sony encrypted.
        assert_eq!(decrypt_prx(&ours.data).unwrap(), module, "{}", f.name);
    });
}
