//! `pspbuild` command-line entry point.

mod cli;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, Command, derive_output_path};
use pspbuild::inspect::{FileFormat, Inspection, IsoReport, inspect, inspect_iso, inspect_pbp};
use pspbuild::mg::{MgEbootRequest, build_mg_eboot};
use pspbuild::pbp::{Pbp, PbpSection};
use pspbuild::{Container, EncryptOptions, Error, decrypt_prx, encrypt_prx, verify_prx};

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(error) = run(&cli) {
        eprintln!("error: {error}");
        // Show the underlying cause when there is one.
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            eprintln!("  caused by: {cause}");
            source = cause.source();
        }
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run(cli: &Cli) -> Result<(), Error> {
    match &cli.command {
        Command::EncryptPrx {
            input,
            output,
            no_compress,
            format,
        } => {
            let data = read(input)?;
            let options = EncryptOptions {
                compress: !no_compress,
                format: (*format).into(),
            };

            let encrypted = encrypt_prx(&data, &options)?;
            let out_path = output
                .clone()
                .unwrap_or_else(|| derive_output_path(input, "enc"));

            if cli.verbose {
                let mut err = std::io::stderr().lock();
                if encrypted.container == Container::Pbp {
                    let _ = writeln!(err, "Container:        PBP (encrypting DATA.PSP)");
                }
                let _ = writeln!(err, "Input size:       {} bytes", encrypted.input_size);
                let _ = writeln!(
                    err,
                    "Compression:      {}",
                    if encrypted.compressed {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
                let _ = writeln!(err, "Payload size:     {} bytes", encrypted.payload_size);
                let _ = writeln!(
                    err,
                    "Encrypted size:   {} bytes",
                    encrypted.aligned_payload_size
                );
                let _ = writeln!(err, "Output size:      {} bytes", encrypted.data.len());
                let _ = writeln!(err, "Output:           {}", out_path.display());
            }

            write(&out_path, &encrypted.data)
        }

        Command::BuildMg {
            input,
            output,
            title,
            system_version,
            no_compress,
            base,
            icon0,
            icon1,
            pic0,
            pic1,
            snd0,
        } => {
            let module = read(input)?;
            let base_bytes = base.as_deref().map(read).transpose()?;
            let base_pbp = base_bytes.as_deref().map(Pbp::parse).transpose()?;

            let built = build_mg_eboot(&MgEbootRequest {
                module: &module,
                title: title.as_deref(),
                system_version: system_version.as_deref(),
                compress: !no_compress,
                base: base_pbp.as_ref(),
                icon0: icon0.as_deref().map(read).transpose()?,
                icon1: icon1.as_deref().map(read).transpose()?,
                pic0: pic0.as_deref().map(read).transpose()?,
                pic1: pic1.as_deref().map(read).transpose()?,
                snd0: snd0.as_deref().map(read).transpose()?,
            })?;

            let out_path = output
                .clone()
                .unwrap_or_else(|| sibling(input, "EBOOT.PBP"));

            if cli.verbose {
                let mut err = std::io::stderr().lock();
                let _ = writeln!(err, "Category:         MG");
                let _ = writeln!(err, "Title:            {}", built.title);
                if built.module_was_encrypted {
                    let _ = writeln!(err, "Module:           already encrypted, packaged as-is");
                } else if let Some(enc) = &built.encrypted {
                    let _ = writeln!(err, "Input size:       {} bytes", enc.input_size);
                    let _ = writeln!(
                        err,
                        "Compression:      {}",
                        if enc.compressed {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    );
                    let _ = writeln!(err, "DATA.PSP size:    {} bytes", enc.data.len());
                }
                for (section, _, size) in built.pbp.layout() {
                    if size > 0 {
                        let _ = writeln!(err, "  {section:<12} {size} bytes");
                    }
                }
                let _ = writeln!(err, "Output size:      {} bytes", built.data.len());
                let _ = writeln!(err, "Output:           {}", out_path.display());
            }

            write(&out_path, &built.data)
        }

        Command::BuildEg { input, .. } => Err(Error::Unimplemented {
            pipeline: "EG",
            detail: format!(
                "building an NPDRM EBOOT from {} needs the NPUMDIMG format, \
                 which is not implemented yet; see docs/EG.md",
                input.display()
            ),
        }),

        Command::Inspect { input } => {
            // A UMD runs to 1.8 GB and an EG EBOOT to over a gigabyte, so
            // classify from a prefix and stream rather than reading the whole
            // file just to find out what it is.
            let format = detect_file(input)?;
            if matches!(format, FileFormat::Iso9660 | FileFormat::Pbp) {
                let file = std::fs::File::open(input).map_err(|e| Error::io(input, e))?;
                let size = file.metadata().map(|m| m.len()).unwrap_or(0);
                if format == FileFormat::Iso9660 {
                    print_iso(&inspect_iso(file)?, size);
                } else {
                    print_inspection(&inspect_pbp(file, size)?);
                }
                return Ok(());
            }
            let data = read(input)?;
            let report = inspect(&data)?;
            print_inspection(&report);
            Ok(())
        }

        Command::Verify { input } => {
            let data = read(input)?;
            let result = verify_prx(&data)?;

            let mut out = std::io::stdout().lock();
            for check in &result.checks {
                let _ = writeln!(out, "VALID: {check}");
            }
            let _ = writeln!(out, "Recovered size:      {} bytes", result.recovered_size);
            if let Some(module) = &result.module {
                let _ = writeln!(out, "Module name:         {}", module.name);
            }
            let _ = writeln!(out, "VERIFIED");
            Ok(())
        }

        Command::Extract {
            input,
            output,
            decrypt,
        } => {
            let data = read(input)?;
            let pbp = Pbp::parse(&data)?;
            std::fs::create_dir_all(output).map_err(|e| Error::io(output, e))?;

            let mut out = std::io::stdout().lock();
            for section in PbpSection::ALL {
                let bytes = pbp.section(section);
                if bytes.is_empty() {
                    continue;
                }
                let path = output.join(section.name());
                write(&path, bytes)?;
                let _ = writeln!(out, "{} ({} bytes)", path.display(), bytes.len());
            }

            if *decrypt {
                // Only meaningful when DATA.PSP really is an encrypted PRX;
                // say so rather than writing a file that is not what it claims.
                let decrypted = decrypt_prx(pbp.data_psp())?;
                let path = output.join("DATA.PSP.dec");
                write(&path, &decrypted)?;
                let _ = writeln!(out, "{} ({} bytes)", path.display(), decrypted.len());
            }
            Ok(())
        }

        Command::Decrypt { input, output } => {
            let data = read(input)?;
            let decrypted = decrypt_prx(&data)?;
            let out_path = output
                .clone()
                .unwrap_or_else(|| derive_output_path(input, "dec"));

            if cli.verbose {
                let _ = writeln!(
                    std::io::stderr(),
                    "Recovered {} bytes to {}",
                    decrypted.len(),
                    out_path.display()
                );
            }
            write(&out_path, &decrypted)
        }
    }
}

fn print_inspection(report: &Inspection) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "Format:              {}", report.format);
    let _ = writeln!(out, "Total size:          {} bytes", report.total_size);

    if let Some(container) = &report.container {
        let _ = writeln!(out, "Container version:   {:#010X}", container.version);
        match &container.category {
            Some(category) => {
                let _ = writeln!(out, "Category:            {category}");
            }
            None => {
                let _ = writeln!(out, "Category:            unknown");
            }
        }
        if let Some(title) = &container.title {
            let _ = writeln!(out, "Title:               {title}");
        }
        if let Some(version) = &container.system_version {
            let _ = writeln!(out, "Firmware required:   {version}");
        }
        if let Some(error) = &container.param_sfo_error {
            let _ = writeln!(out, "PARAM.SFO:           unreadable ({error})");
        }

        let _ = writeln!(out, "\nSections:");
        for section in &container.sections {
            if section.size == 0 {
                let _ = writeln!(out, "  {:<12} empty", section.section.name());
            } else {
                let _ = writeln!(
                    out,
                    "  {:<12} offset {:#010X}  {:>10} bytes  {}",
                    section.section.name(),
                    section.offset,
                    section.size,
                    section.format
                );
            }
        }
        let _ = writeln!(out);
    }

    // A standalone PARAM.SFO has no container to list it under, so show the
    // table itself — it is the whole content of the file.
    if report.container.is_none()
        && let Some(sfo) = &report.param_sfo
    {
        let _ = writeln!(out, "\nEntries:");
        for entry in &sfo.entries {
            let value = entry
                .as_text()
                .or_else(|| entry.as_u32().map(|n| n.to_string()))
                .unwrap_or_else(|| format!("<{} bytes>", entry.data.len()));
            let _ = writeln!(out, "  {:<16} {value}", entry.key);
        }
    }

    match (&report.module, &report.module_error) {
        (Some(info), _) => {
            let _ = writeln!(out, "Executable:");
            let _ = writeln!(out, "  Format:            {}", info.format);
            let _ = writeln!(out, "  Encrypted:         {}", yes_no(info.encrypted));
            let _ = writeln!(out, "  Compression:       {}", yes_no(info.compressed));
            if let Some(size) = info.payload_size {
                let _ = writeln!(out, "  Payload size:      {size} bytes");
            }
            if let Some(size) = info.kirk_payload_size {
                let _ = writeln!(out, "  KIRK payload:      {size} bytes");
            }
            let _ = writeln!(out, "  Module name:       {}", info.module_name);
            let _ = writeln!(out, "  Entry point:       {:#010X}", info.entry_point);
            let _ = writeln!(out, "  Segments:          {}", info.segments.len());
            for (i, (address, size)) in info.segments.iter().enumerate() {
                let _ = writeln!(out, "    [{i}] address {address:#010X}  size {size}");
            }
            if let Some(tag) = info.tag {
                let _ = writeln!(out, "  Tag:               {tag:#010X}");
            }
        }
        (None, Some(error)) => {
            let _ = writeln!(out, "Executable:          {error}");
        }
        (None, None) => {}
    }
}

/// Classify a file by reading only as much of it as detection needs.
fn detect_file(path: &Path) -> Result<FileFormat, Error> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|e| Error::io(path, e))?;
    let mut prefix = vec![0u8; FileFormat::detect_prefix()];
    // A short file is not an error here — it just cannot be an ISO.
    let mut filled = 0;
    loop {
        match file.read(&mut prefix[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::io(path, e)),
        }
        if filled == prefix.len() {
            break;
        }
    }
    prefix.truncate(filled);
    Ok(FileFormat::detect(&prefix))
}

fn print_iso(report: &IsoReport, file_size: u64) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "Format:              ISO9660 image (UMD)");
    let _ = writeln!(out, "File size:           {file_size} bytes");
    let _ = writeln!(out, "System identifier:   {}", report.volume.system_id);
    if !report.volume.volume_id.is_empty() {
        let _ = writeln!(out, "Volume identifier:   {}", report.volume.volume_id);
    }
    let _ = writeln!(
        out,
        "Volume size:         {} blocks ({} bytes)",
        report.volume.volume_blocks,
        u64::from(report.volume.volume_blocks) * pspbuild::iso::SECTOR_SIZE
    );
    let _ = writeln!(out, "Entries:             {}", report.entry_count);
    if let Some(disc) = &report.disc_id {
        let _ = writeln!(out, "Disc identifier:     {disc}");
    }

    let _ = writeln!(out, "\nPSP_GAME assets:");
    for asset in &report.assets {
        match asset.size {
            Some(size) => {
                let _ = writeln!(out, "  {:<24} {:>10} bytes", asset.path, size);
            }
            None => {
                let _ = writeln!(out, "  {:<24} {:>10}", asset.path, "absent");
            }
        }
    }
    match report.eboot_size {
        Some(size) => {
            let _ = writeln!(out, "  {:<24} {size:>10} bytes", pspbuild::iso::EBOOT_BIN);
        }
        None => {
            let _ = writeln!(out, "  {:<24} {:>10}", pspbuild::iso::EBOOT_BIN, "absent");
        }
    }

    if let Some(sfo) = &report.param_sfo {
        let _ = writeln!(out, "\nPARAM.SFO:");
        for entry in &sfo.entries {
            let value = entry
                .as_text()
                .or_else(|| entry.as_u32().map(|n| n.to_string()))
                .unwrap_or_else(|| format!("<{} bytes>", entry.data.len()));
            let _ = writeln!(out, "  {:<16} {value}", entry.key);
        }
    }
}

/// A path beside `input` with the given file name.
fn sibling(input: &Path, name: &str) -> PathBuf {
    input.with_file_name(name)
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn read(path: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|e| Error::io(path, e))
}

fn write(path: &Path, data: &[u8]) -> Result<(), Error> {
    std::fs::write(path, data).map_err(|e| Error::io(path, e))
}
