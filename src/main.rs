//! `pspbuild` command-line entry point.

mod cli;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, Command, derive_output_path};
use pspbuild::inspect::{Inspection, inspect};
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
