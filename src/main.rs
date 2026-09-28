//! `pspbuild` command-line entry point.

mod cli;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use cli::{AudioCommand, Cli, Command, derive_output_path};
use pspbuild::audio::{At3Report, Snd0, Snd0Options, Snd0Source, make_snd0};
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
        Command::Encrypt {
            input,
            output,
            no_compress,
        } => {
            let data = read(input)?;
            let options = EncryptOptions {
                compress: !no_compress,
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
            snd0_start,
            snd0_duration,
        } => {
            let module = read(input)?;
            let snd0 = snd0
                .as_deref()
                .map(|path| {
                    let options = Snd0Options {
                        start: *snd0_start,
                        duration: *snd0_duration,
                    };
                    let converted = make_snd0(&read(path)?, &options)?;
                    report_snd0(cli.verbose, path, &converted);
                    Ok::<_, Error>(converted.data)
                })
                .transpose()?;
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
                snd0,
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

        Command::BuildEg {
            input,
            output,
            content_id,
            no_compress,
            startdat,
            opnssmp,
        } => {
            let output = output
                .clone()
                .unwrap_or_else(|| input.with_file_name("EBOOT.PBP"));

            let image = std::fs::File::open(input).map_err(|e| Error::io(input, e))?;
            let image_size = image.metadata().map_err(|e| Error::io(input, e))?.len();
            let mut out = std::fs::File::create(&output).map_err(|e| Error::io(&output, e))?;

            let mut options = pspbuild::npdrm::ArchiveOptions::fixed_key(content_id.clone());
            options.compress = !no_compress;
            options.startdat = read_optional(startdat.as_ref())?;
            options.opnssmp = read_optional(opnssmp.as_ref())?;
            let built = pspbuild::eg::build_eg_eboot(
                image,
                image_size,
                &mut out,
                &options,
                &mut pspbuild::npdrm::SystemEntropy,
            )?;

            if let Some(title) = &built.title {
                println!("Title:               {title}");
            }
            println!("Content ID:          {}", built.content_id);
            println!("Image size:          {image_size} bytes");
            let blocks = built.archive.layout.blocks;
            let packed = built.archive.compressed_blocks;
            println!(
                "Blocks:              {blocks} of {} bytes, {} compressed",
                built.archive.layout.block_size(),
                if packed == 0 {
                    "none".to_string()
                } else {
                    format!("{packed} ({}%)", packed * 100 / blocks)
                }
            );
            if built.startdat_size > 0 {
                println!("STARTDAT:            {} byte PNG", built.startdat_size);
            }
            if built.opnssmp_size > 0 {
                println!(
                    "OPNSSMP:             {} bytes encrypted",
                    built.opnssmp_size
                );
            }
            println!("DATA.PSAR:           {} bytes", built.archive.size);
            println!(
                "Wrote {} ({} bytes)",
                output.display(),
                built.container_size + built.archive.size
            );
            Ok(())
        }

        Command::Audio { command } => match command {
            AudioCommand::Snd0 {
                input,
                output,
                start,
                duration,
            } => {
                let options = Snd0Options {
                    start: *start,
                    duration: *duration,
                };
                let snd0 = make_snd0(&read(input)?, &options)?;
                let out_path = output.clone().unwrap_or_else(|| sibling(input, "SND0.AT3"));
                report_snd0(cli.verbose, input, &snd0);
                if cli.verbose {
                    let _ = writeln!(
                        std::io::stderr(),
                        "Output:           {}",
                        out_path.display()
                    );
                }
                write(&out_path, &snd0.data)
            }
            AudioCommand::Inspect { input, strict } => {
                let report = pspbuild::audio::inspect_at3(&read(input)?);
                print_at3(&mut std::io::stdout().lock(), &report, "");
                match report.failure_summary(*strict) {
                    Some(problems) => Err(Error::InvalidAudio(problems)),
                    None => Ok(()),
                }
            }
        },

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
            if let Some(report) = &result.snd0 {
                for warning in report.warnings() {
                    let _ = writeln!(out, "WARNING: SND0.AT3: {}", warning.message);
                }
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
        if let Some(snd0) = &container.snd0 {
            let _ = writeln!(out, "SND0.AT3:");
            print_at3(&mut out, snd0, "  ");
            let _ = writeln!(out);
        }
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

/// Tell the user what happened to an SND0 source: notices always, detail
/// only when asked.
fn report_snd0(verbose: bool, path: &Path, snd0: &Snd0) {
    let mut err = std::io::stderr().lock();
    for notice in &snd0.notices {
        let _ = writeln!(err, "warning: {}: {notice}", path.display());
    }
    if !verbose {
        return;
    }
    match &snd0.source {
        Snd0Source::PassedThrough => {
            let _ = writeln!(
                err,
                "SND0:             {} is already a playable SND0, used as-is",
                path.display()
            );
        }
        Snd0Source::Encoded {
            format,
            sample_rate,
            channels,
            input_seconds,
            ..
        } => {
            let _ = writeln!(
                err,
                "SND0 source:      {format}, {sample_rate} Hz, {channels} channel{}, {input_seconds:.2} s",
                if *channels == 1 { "" } else { "s" }
            );
            let _ = writeln!(
                err,
                "SND0:             ATRAC3 LP4, {} frames, {:.2} s, {} bytes",
                snd0.report.frames,
                snd0.report.duration_seconds(),
                snd0.data.len()
            );
        }
    }
}

/// Print an AT3 report, each line prefixed with `indent`.
fn print_at3(out: &mut impl Write, report: &At3Report, indent: &str) {
    let line = |out: &mut dyn Write, label: &str, value: String| {
        let _ = writeln!(out, "{indent}{:<21}{value}", format!("{label}:"));
    };
    line(out, "File size", format!("{} bytes", report.file_size));
    if !report.chunks.is_empty() {
        let _ = writeln!(out, "{indent}Chunks:");
        for chunk in &report.chunks {
            let _ = writeln!(
                out,
                "{indent}  {:<5} offset {:#010X}  {:>10} bytes",
                chunk.id, chunk.offset, chunk.size
            );
        }
    }
    if let Some(tag) = report.format_tag {
        let codec = if tag == pspbuild::audio::riff::FORMAT_ATRAC3 {
            "ATRAC3"
        } else {
            "not ATRAC3"
        };
        line(out, "Codec", format!("{codec} ({tag:#06X})"));
    }
    if let Some(rate) = report.sample_rate {
        line(out, "Sample rate", format!("{rate} Hz"));
    }
    if let Some(channels) = report.channels {
        line(out, "Channels", channels.to_string());
    }
    if let (Some(bps), Some(align)) = (report.bitrate_bps(), report.block_align) {
        let profile = match align {
            192 => " (LP4)",
            384 => " (LP2)",
            _ => "",
        };
        line(
            out,
            "Bitrate",
            format!("{bps} bps{profile}, {align}-byte frames"),
        );
    }
    if let Some(joint) = report.joint_stereo {
        line(
            out,
            "Stereo",
            if joint {
                "joint".into()
            } else {
                "independent channels".into()
            },
        );
    }
    if report.format_tag.is_some() {
        line(
            out,
            "fmt chunk",
            if report.fmt_matches_known_good {
                "identical to a known-good LP4 SND0".into()
            } else {
                "differs from the known-good LP4 SND0".into()
            },
        );
    }
    if report.frames > 0 {
        line(
            out,
            "Frames",
            format!("{} ({:.2} s)", report.frames, report.duration_seconds()),
        );
        let bands = |counts: &[usize; 4]| {
            counts
                .iter()
                .enumerate()
                .filter(|&(_, &n)| n > 0)
                .map(|(b, n)| {
                    let bands = b + 1;
                    format!("{bands} band{} in {n}", if bands == 1 { "" } else { "s" })
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        if report.frames_decoded > 0 {
            line(out, "Coded QMF bands", bands(&report.bands_first_unit));
            line(
                out,
                if report.joint_stereo == Some(false) {
                    "  right channel"
                } else {
                    "  side channel"
                },
                bands(&report.bands_second_unit),
            );
        }
    }
    if let (Some(fact), Some(looped)) = (report.fact, report.loop_points) {
        let seconds = f64::from(fact.samples) / 44_100.0;
        let times = if looped.play_count == 0 {
            "forever".to_string()
        } else {
            format!("{} times", looped.play_count)
        };
        line(
            out,
            "Loop",
            format!(
                "samples {} to {} ({seconds:.2} s), {times}",
                looped.start, looped.end
            ),
        );
    } else if report.format_tag.is_some() {
        line(out, "Loop", "none".into());
    }
    let verdict = if !report.is_playable() {
        "NOT PLAYABLE"
    } else if report.is_strictly_valid() {
        "playable; matches the profile pspbuild writes"
    } else {
        "playable, with warnings"
    };
    line(out, "Verdict", verdict.into());
    for finding in &report.findings {
        let label = match finding.severity {
            pspbuild::audio::Severity::Error => "ERROR",
            pspbuild::audio::Severity::Warning => "WARNING",
        };
        let _ = writeln!(out, "{indent}{label}: {}", finding.message);
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

/// Read a file that a flag may or may not have named.
fn read_optional(path: Option<&PathBuf>) -> Result<Option<Vec<u8>>, Error> {
    path.map(|p| read(p)).transpose()
}

fn write(path: &Path, data: &[u8]) -> Result<(), Error> {
    std::fs::write(path, data).map_err(|e| Error::io(path, e))
}
