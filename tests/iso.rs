//! Tests against a real PSP UMD image.
//!
//! A retail ISO cannot be checked into the repository, so these tests look for
//! one and skip when it is absent. They are the only place the reader meets a
//! genuine Sony-produced image rather than a synthetic one, so when an ISO is
//! available they are worth far more than the unit tests.
//!
//! Point `PSPBUILD_TEST_ISO` at an image, or drop one in `plans/`.

use std::path::PathBuf;

use pspbuild::iso::{EBOOT_BIN, Iso, PSP_GAME_ASSETS, SECTOR_SIZE, UMD_DATA_BIN};

/// Locate a UMD image to test against, if there is one.
fn find_iso() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PSPBUILD_TEST_ISO") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let plans = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("plans");
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(plans)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("iso"))
        })
        .collect();
    candidates.sort();
    candidates.into_iter().next()
}

/// Skip the test body when no image is available.
macro_rules! iso_or_skip {
    () => {
        match find_iso() {
            Some(path) => Iso::open(path).expect("image opens"),
            None => {
                eprintln!("no UMD image available; skipping");
                return;
            }
        }
    };
}

#[test]
fn reads_a_retail_volume_descriptor() {
    let iso = iso_or_skip!();
    let volume = iso.volume();

    // Every PSP UMD identifies itself this way.
    assert_eq!(volume.system_id, "PSP GAME");
    assert_eq!(volume.block_size, SECTOR_SIZE as u16);
    assert!(volume.volume_blocks > 0);
}

#[test]
fn the_declared_volume_size_matches_the_file() {
    let path = match find_iso() {
        Some(path) => path,
        None => {
            eprintln!("no UMD image available; skipping");
            return;
        }
    };
    let on_disk = std::fs::metadata(&path).unwrap().len();
    let iso = Iso::open(&path).unwrap();

    // A UMD's descriptor describes the whole image. If these disagree the
    // image was truncated or padded, and the EG pipeline would encrypt the
    // wrong number of sectors.
    assert_eq!(
        iso.volume_size(),
        on_disk,
        "declared volume size disagrees with the file"
    );
}

#[test]
fn finds_the_psp_game_layout() {
    let mut iso = iso_or_skip!();

    // A bootable UMD must have these two.
    assert!(iso.exists("/PSP_GAME/PARAM.SFO"));
    assert!(iso.exists(EBOOT_BIN), "no {EBOOT_BIN}");
    assert!(iso.file_size(EBOOT_BIN).unwrap() > 0);

    // Directories are entries too, and are not readable as files.
    assert!(iso.exists("/PSP_GAME"));
    assert!(iso.exists("/PSP_GAME/SYSDIR"));
    assert_eq!(iso.file_size("/PSP_GAME"), None);
    assert!(iso.read_file("/PSP_GAME").is_err());

    // Absent assets report absent rather than erroring.
    for (path, _) in PSP_GAME_ASSETS {
        match iso.read_optional(path).unwrap() {
            Some(data) => assert_eq!(data.len() as u64, iso.file_size(path).unwrap()),
            None => assert!(!iso.exists(path) || iso.file_size(path) == Some(0)),
        }
    }
}

#[test]
fn the_retail_param_sfo_round_trips_byte_for_byte() {
    let mut iso = iso_or_skip!();
    let raw = iso.read_file("/PSP_GAME/PARAM.SFO").unwrap();
    let sfo = pspbuild::Sfo::parse(&raw).expect("retail PARAM.SFO parses");

    // The strongest check the SFO code gets: a table Sony produced, re-emitted
    // byte for byte. Normalising the per-entry reserved sizes would break this.
    assert_eq!(
        sfo.to_bytes(),
        raw,
        "retail PARAM.SFO did not re-emit exactly"
    );

    // A UMD is category UG, which is neither of the two pipelines.
    assert_eq!(sfo.category().unwrap().as_str(), "UG");
    assert!(sfo.get_text("DISC_ID").is_some());
    assert_eq!(sfo.get_u32("BOOTABLE"), Some(1));
}

#[test]
fn reads_files_and_raw_sectors_consistently() {
    let mut iso = iso_or_skip!();
    let entry = iso.entry(EBOOT_BIN).unwrap().clone();

    let by_file = iso.read_file(EBOOT_BIN).unwrap();
    assert_eq!(by_file.len() as u32, entry.size);

    // The same bytes must be reachable as raw sectors, which is how the EG
    // pipeline will consume the image.
    let by_blocks = iso.read_blocks(entry.lba, entry.block_count()).unwrap();
    assert_eq!(&by_blocks[..by_file.len()], &by_file[..]);
    assert_eq!(by_blocks.len() as u64 % SECTOR_SIZE, 0);
}

#[test]
fn the_retail_eboot_is_an_encrypted_prx_with_an_unsupported_tag() {
    let mut iso = iso_or_skip!();
    let eboot = iso.read_file(EBOOT_BIN).unwrap();
    assert_eq!(&eboot[..4], b"~PSP", "retail EBOOT.BIN should be encrypted");

    let info = pspbuild::inspect_prx(&eboot).unwrap();
    assert!(info.encrypted);

    // Retail discs use tags this tool does not emit. Decryption must refuse
    // rather than attempt it under the one key it does have.
    let tag = info.tag.expect("encrypted module carries a tag");
    if tag != pspbuild::psp::tag::TAG_DEMO_280.tag {
        assert!(
            pspbuild::decrypt_prx(&eboot).is_err(),
            "decrypted a module with unsupported tag {tag:#010X}"
        );
    }
}

#[test]
fn disc_identification_is_readable() {
    let mut iso = iso_or_skip!();
    let Some(raw) = iso.read_optional(UMD_DATA_BIN).unwrap() else {
        return;
    };
    let text = String::from_utf8_lossy(&raw);

    // UMD_DATA.BIN is pipe-separated: disc id, a hex value, version, type.
    let fields: Vec<&str> = text.split('|').collect();
    assert!(fields.len() >= 4, "unexpected UMD_DATA.BIN: {text:?}");
    assert!(
        fields[0].len() >= 9 && fields[0].contains('-'),
        "first field is not a disc id: {:?}",
        fields[0]
    );
}

#[test]
fn every_entry_lies_inside_the_volume() {
    let iso = iso_or_skip!();
    let blocks = iso.volume().volume_blocks;

    for entry in iso.entries() {
        assert!(
            entry.lba < blocks,
            "{} starts at block {} but the volume is {blocks} blocks",
            entry.path,
            entry.lba
        );
        let end = u64::from(entry.lba) + u64::from(entry.block_count());
        assert!(
            end <= u64::from(blocks),
            "{} runs past the end of the volume",
            entry.path
        );
    }
}
