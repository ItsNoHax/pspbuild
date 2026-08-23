//! Building an MG `EBOOT.PBP`.

use crate::error::{Error, Result};
use crate::pbp::{Pbp, PbpBuilder, PbpSection};
use crate::prx::parser::parse_module;
use crate::psp::header::{METADATA_SIZE, PSP_HEADER_SIZE, PspModuleHeader};
use crate::sfo::{Category, Sfo, SfoEntry, mg_param_sfo};
use crate::{EncryptOptions, Encrypted, encrypt_prx};

/// What to put in an MG EBOOT.
#[derive(Debug, Default)]
pub struct MgEbootRequest<'a> {
    /// The module. Either a plain PRX/ELF, which is encrypted, or one that is
    /// already a `~PSP` container, which is used as-is.
    pub module: &'a [u8],
    /// XMB title. Defaults to the module's own name.
    pub title: Option<&'a str>,
    /// Minimum firmware, written to `PSP_SYSTEM_VER`. Defaults to `1.00`.
    pub system_version: Option<&'a str>,
    /// Compress the module before encrypting.
    pub compress: bool,
    /// An existing container to build on. Every section not replaced here is
    /// carried over untouched.
    pub base: Option<&'a Pbp>,
    /// Optional media sections.
    pub icon0: Option<Vec<u8>>,
    pub icon1: Option<Vec<u8>>,
    pub pic0: Option<Vec<u8>>,
    pub pic1: Option<Vec<u8>>,
    pub snd0: Option<Vec<u8>>,
}

/// A built MG EBOOT.
#[derive(Debug, Clone)]
pub struct MgEboot {
    /// The serialised `EBOOT.PBP`.
    pub data: Vec<u8>,
    /// The container, for callers that want to inspect it without reparsing.
    pub pbp: Pbp,
    /// Sizing detail from the PRX encryption step, when one happened.
    pub encrypted: Option<Encrypted>,
    /// The title written to `PARAM.SFO`.
    pub title: String,
    /// Whether the module arrived already encrypted.
    pub module_was_encrypted: bool,
}

/// Whether `data` is already a `~PSP` encrypted module.
fn is_encrypted_module(data: &[u8]) -> bool {
    data.len() >= METADATA_SIZE && data[..4] == crate::psp::header::PSP_MAGIC
}

/// The module's own name, used as the default title.
fn module_name(data: &[u8]) -> Result<String> {
    if is_encrypted_module(data) {
        Ok(PspModuleHeader::parse(data)?.modname)
    } else {
        Ok(parse_module(data)?.name)
    }
}

/// Build an MG `EBOOT.PBP` from a module.
///
/// The output is sized from what it actually contains: the encrypted module is
/// header plus aligned payload, and the container is header plus sections. No
/// section is padded to a template's capacity.
pub fn build_mg_eboot(request: &MgEbootRequest<'_>) -> Result<MgEboot> {
    if request.module.is_empty() {
        return Err(Error::InvalidPbp(
            "cannot build an EBOOT from an empty module".into(),
        ));
    }
    if Pbp::is_pbp(request.module) {
        // A PBP here means the caller passed a whole EBOOT where a module was
        // expected. Encrypting it wholesale would bury a container inside a
        // container, so say so instead.
        return Err(Error::InvalidPbp(
            "expected a PRX module but got a PBP container; \
             use `encrypt-prx` to re-encrypt an existing EBOOT"
                .into(),
        ));
    }

    let module_was_encrypted = is_encrypted_module(request.module);
    let title = match request.title {
        Some(title) => title.to_owned(),
        None => module_name(request.module)?,
    };

    // Encrypt, unless the module already went through that step.
    let (data_psp, encrypted) = if module_was_encrypted {
        if request.module.len() < PSP_HEADER_SIZE {
            return Err(Error::TooShort {
                expected: PSP_HEADER_SIZE,
                actual: request.module.len(),
            });
        }
        (request.module.to_vec(), None)
    } else {
        let out = encrypt_prx(
            request.module,
            &EncryptOptions {
                compress: request.compress,
                ..Default::default()
            },
        )?;
        (out.data.clone(), Some(out))
    };

    let param_sfo = build_param_sfo(request, &title)?;

    let mut builder = match request.base {
        Some(base) => PbpBuilder::from_pbp(base),
        None => PbpBuilder::new(),
    };
    builder = builder
        .section(PbpSection::ParamSfo, param_sfo.to_bytes())
        .section(PbpSection::DataPsp, data_psp)
        .optional_section(PbpSection::Icon0Png, request.icon0.clone())
        .optional_section(PbpSection::Icon1Pmf, request.icon1.clone())
        .optional_section(PbpSection::Pic0Png, request.pic0.clone())
        .optional_section(PbpSection::Pic1Png, request.pic1.clone())
        .optional_section(PbpSection::Snd0At3, request.snd0.clone());

    let pbp = builder.build();
    // The pipeline that just ran must be the one the container asks for.
    pbp.require_category(&Category::Mg)?;

    Ok(MgEboot {
        data: pbp.to_bytes(),
        pbp,
        encrypted,
        title,
        module_was_encrypted,
    })
}

/// Produce the `PARAM.SFO`, reusing the base container's where there is one.
///
/// Reusing it matters: a homebrew project's `PARAM.SFO` may carry keys this
/// crate has no opinion about, and dropping them would change how the firmware
/// treats the build. Only the fields this pipeline is responsible for are
/// overwritten — `CATEGORY`, because that is what selects the pipeline, plus
/// the title and firmware requirement when the caller asked for them.
fn build_param_sfo(request: &MgEbootRequest<'_>, title: &str) -> Result<Sfo> {
    let existing =
        request.base.map(Pbp::param_sfo).transpose().map_err(|e| {
            Error::InvalidSfo(format!("base container's PARAM.SFO is unusable: {e}"))
        })?;

    let mut sfo = match existing {
        Some(mut sfo) => {
            sfo.set(SfoEntry::text_padded("CATEGORY", Category::Mg.as_str(), 4)?);
            if request.title.is_some() {
                sfo.set(SfoEntry::text_padded("TITLE", title, 128)?);
            }
            sfo
        }
        None => mg_param_sfo(title)?,
    };

    if let Some(version) = request.system_version {
        sfo.set(SfoEntry::text_padded("PSP_SYSTEM_VER", version, 8)?);
    }
    Ok(sfo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prx::parser::tests::synthetic_prx;
    use crate::{decrypt_prx, verify_prx};

    fn request(module: &[u8]) -> MgEbootRequest<'_> {
        MgEbootRequest {
            module,
            compress: true,
            ..Default::default()
        }
    }

    #[test]
    fn builds_a_bootable_looking_eboot_from_a_module() {
        let module = synthetic_prx("homebrew", 40_000);
        let built = build_mg_eboot(&request(&module)).unwrap();

        // It is a PBP, it declares MG, and DATA.PSP is an encrypted PRX.
        let parsed = Pbp::parse(&built.data).unwrap();
        assert_eq!(parsed.category(), Some(Category::Mg));
        assert_eq!(&parsed.data_psp()[..4], b"~PSP");
        assert_eq!(parsed.section(PbpSection::ParamSfo)[..4], *b"\0PSF");

        // The executable round-trips and verifies through the container.
        assert_eq!(decrypt_prx(&built.data).unwrap(), module);
        assert!(verify_prx(&built.data).is_ok());

        // MG carries no archive.
        assert!(parsed.data_psar().is_empty());
    }

    #[test]
    fn the_title_defaults_to_the_module_name() {
        let module = synthetic_prx("MyModule", 2048);
        let built = build_mg_eboot(&request(&module)).unwrap();
        assert_eq!(built.title, "MyModule");
        assert_eq!(
            built.pbp.param_sfo().unwrap().get_text("TITLE").as_deref(),
            Some("MyModule")
        );

        let built = build_mg_eboot(&MgEbootRequest {
            title: Some("Explicit Title"),
            ..request(&module)
        })
        .unwrap();
        assert_eq!(built.title, "Explicit Title");
    }

    #[test]
    fn the_container_is_only_as_big_as_its_contents() {
        let module = synthetic_prx("sized", 200_000);
        let built = build_mg_eboot(&request(&module)).unwrap();

        let expected: usize =
            crate::pbp::HEADER_SIZE + built.pbp.sections.iter().map(Vec::len).sum::<usize>();
        assert_eq!(built.data.len(), expected);
        // A compressible module must not produce a multi-megabyte EBOOT.
        assert!(built.data.len() < 30_000, "got {}", built.data.len());
    }

    #[test]
    fn media_sections_are_carried_through() {
        let module = synthetic_prx("media", 1024);
        let built = build_mg_eboot(&MgEbootRequest {
            icon0: Some(vec![0x89; 300]),
            pic1: Some(vec![0x89; 500]),
            snd0: Some(vec![0x41; 700]),
            ..request(&module)
        })
        .unwrap();

        let parsed = Pbp::parse(&built.data).unwrap();
        assert_eq!(parsed.section(PbpSection::Icon0Png).len(), 300);
        assert_eq!(parsed.section(PbpSection::Pic1Png).len(), 500);
        assert_eq!(parsed.section(PbpSection::Snd0At3).len(), 700);
        // Ones that were not supplied stay empty rather than being invented.
        assert!(parsed.section(PbpSection::Icon1Pmf).is_empty());
        assert!(parsed.section(PbpSection::Pic0Png).is_empty());
    }

    #[test]
    fn rebuilding_on_a_base_preserves_its_sections_and_extra_sfo_keys() {
        let module = synthetic_prx("base", 4096);

        let mut sfo = mg_param_sfo("Original").unwrap();
        sfo.set(SfoEntry::int("APP_VER", 7));
        let base = PbpBuilder::new()
            .section(PbpSection::ParamSfo, sfo.to_bytes())
            .section(PbpSection::Icon0Png, vec![0x89; 120])
            .section(PbpSection::DataPsp, b"replaced".to_vec())
            .build();

        let built = build_mg_eboot(&MgEbootRequest {
            base: Some(&base),
            ..request(&module)
        })
        .unwrap();

        let parsed = Pbp::parse(&built.data).unwrap();
        assert_eq!(parsed.section(PbpSection::Icon0Png).len(), 120);

        // A key this crate has no opinion about must survive.
        let out_sfo = parsed.param_sfo().unwrap();
        assert_eq!(out_sfo.get_u32("APP_VER"), Some(7));
        // The base's title is kept when the caller did not ask for one.
        assert_eq!(out_sfo.get_text("TITLE").as_deref(), Some("Original"));
        assert_eq!(out_sfo.category(), Some(Category::Mg));
        assert_eq!(decrypt_prx(&built.data).unwrap(), module);
    }

    #[test]
    fn a_non_mg_base_is_forced_to_mg_rather_than_inherited() {
        // Rebuilding an EG container as MG must not leave CATEGORY=EG behind,
        // which would point the firmware at a pipeline this build did not run.
        let module = synthetic_prx("recat", 1024);
        let mut sfo = mg_param_sfo("Was EG").unwrap();
        sfo.set(SfoEntry::text_padded("CATEGORY", "EG", 4).unwrap());
        let base = PbpBuilder::new()
            .section(PbpSection::ParamSfo, sfo.to_bytes())
            .build();

        let built = build_mg_eboot(&MgEbootRequest {
            base: Some(&base),
            ..request(&module)
        })
        .unwrap();
        assert_eq!(built.pbp.category(), Some(Category::Mg));
    }

    #[test]
    fn an_already_encrypted_module_is_packaged_not_re_encrypted() {
        let module = synthetic_prx("preenc", 8192);
        let enc = encrypt_prx(&module, &EncryptOptions::default()).unwrap();

        let built = build_mg_eboot(&request(&enc.data)).unwrap();
        assert!(built.module_was_encrypted);
        assert!(built.encrypted.is_none());
        // Byte-identical: no second encryption pass happened.
        assert_eq!(built.pbp.data_psp(), enc.data.as_slice());
        assert_eq!(decrypt_prx(&built.data).unwrap(), module);
    }

    #[test]
    fn the_system_version_is_settable() {
        let module = synthetic_prx("fw", 1024);
        let built = build_mg_eboot(&MgEbootRequest {
            system_version: Some("6.60"),
            ..request(&module)
        })
        .unwrap();
        assert_eq!(
            built
                .pbp
                .param_sfo()
                .unwrap()
                .get_text("PSP_SYSTEM_VER")
                .as_deref(),
            Some("6.60")
        );
    }

    #[test]
    fn uncompressed_builds_round_trip_too() {
        let module = synthetic_prx("plain", 4096);
        let built = build_mg_eboot(&MgEbootRequest {
            compress: false,
            ..request(&module)
        })
        .unwrap();
        assert!(!built.encrypted.as_ref().unwrap().compressed);
        assert_eq!(decrypt_prx(&built.data).unwrap(), module);
    }

    #[test]
    fn bad_inputs_are_rejected_with_a_reason() {
        assert!(matches!(
            build_mg_eboot(&request(b"")).unwrap_err(),
            Error::InvalidPbp(_)
        ));

        // A whole EBOOT where a module was expected.
        let module = synthetic_prx("nested", 1024);
        let eboot = build_mg_eboot(&request(&module)).unwrap();
        let err = build_mg_eboot(&request(&eboot.data)).unwrap_err();
        assert!(
            err.to_string().contains("encrypt-prx"),
            "unhelpful error: {err}"
        );

        // Not a module at all.
        assert!(build_mg_eboot(&request(&[0xFFu8; 500])).is_err());

        // A title too long for its reservation.
        let long = "a".repeat(200);
        assert!(
            build_mg_eboot(&MgEbootRequest {
                title: Some(&long),
                ..request(&module)
            })
            .is_err()
        );
    }

    #[test]
    fn output_is_reproducible() {
        let module = synthetic_prx("repro", 16_384);
        let a = build_mg_eboot(&request(&module)).unwrap();
        let b = build_mg_eboot(&request(&module)).unwrap();
        assert_eq!(a.data, b.data);
    }
}
