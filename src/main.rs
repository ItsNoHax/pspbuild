//! `prx-encrypter` command-line entry point.

mod cli;

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, Command, derive_output_path};
use prx_encrypter::{EncryptOptions, Error, decrypt_prx, encrypt_prx, inspect_prx, verify_prx};

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

        Command::Inspect { input } => {
            let data = read(input)?;
            let info = inspect_prx(&data)?;

            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "Format:              {}", info.format);
            let _ = writeln!(out, "Encrypted:           {}", yes_no(info.encrypted));
            let _ = writeln!(out, "Compression:         {}", yes_no(info.compressed));
            let _ = writeln!(
                out,
                "Payload size:        {}",
                info.payload_size
                    .map_or_else(|| "unknown".to_string(), |s| format!("{s} bytes"))
            );
            let _ = writeln!(
                out,
                "KIRK payload size:   {}",
                info.kirk_payload_size
                    .map_or_else(|| "n/a".to_string(), |s| format!("{s} bytes"))
            );
            let _ = writeln!(out, "Total file size:     {} bytes", info.total_size);
            let _ = writeln!(out, "Module name:         {}", info.module_name);
            let _ = writeln!(out, "Segments:            {}", info.segments.len());
            for (i, (address, size)) in info.segments.iter().enumerate() {
                let _ = writeln!(out, "  [{i}] address {address:#010X}  size {size}");
            }
            let _ = writeln!(out, "Entry point:         {:#010X}", info.entry_point);
            if let Some(tag) = info.tag {
                let _ = writeln!(out, "Tag:                 {tag:#010X}");
            }
            Ok(())
        }

        Command::Verify { input } => {
            let data = read(input)?;
            let result = verify_prx(&data)?;

            let mut out = std::io::stdout().lock();
            for check in &result.checks {
                let _ = writeln!(out, "ok: {check}");
            }
            let _ = writeln!(out, "Recovered size:      {} bytes", result.recovered_size);
            if let Some(module) = &result.module {
                let _ = writeln!(out, "Module name:         {}", module.name);
            }
            let _ = writeln!(out, "VERIFIED");
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

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn read(path: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|e| Error::io(path, e))
}

fn write(path: &Path, data: &[u8]) -> Result<(), Error> {
    std::fs::write(path, data).map_err(|e| Error::io(path, e))
}
