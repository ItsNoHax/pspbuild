//! Command-line interface definition.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};

/// Encrypt PSP PRX modules into PSP-compatible encrypted PRX files.
#[derive(Debug, Parser)]
#[command(name = "prx-encrypter", version, about, long_about = None)]
pub struct Cli {
    /// Print details of each stage to stderr.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt a PRX.
    Encrypt {
        /// Input PRX or ELF.
        input: PathBuf,

        /// Output file. Defaults to the input with a `.enc.prx` suffix.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Do not gzip the payload before encrypting.
        #[arg(long)]
        no_compress: bool,

        /// Output format.
        #[arg(long, value_enum, default_value_t = FormatArg::Psp)]
        format: FormatArg,

        /// Derive the ambiguous header fields from the input module instead of
        /// using the values genuine Sony modules carry. Retail firmware
        /// rejects the derived values; this is for investigation only.
        #[arg(long)]
        derived_metadata: bool,
    },

    /// Print a summary of a PRX, encrypted or not.
    Inspect {
        /// File to inspect.
        input: PathBuf,
    },

    /// Check an encrypted PRX as thoroughly as the format allows.
    Verify {
        /// File to verify.
        input: PathBuf,
    },

    /// Decrypt an encrypted PRX back to the original module.
    Decrypt {
        /// Encrypted PRX.
        input: PathBuf,

        /// Output file. Defaults to the input with a `.dec.prx` suffix.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FormatArg {
    /// Standard encrypted PSP PRX.
    Psp,
    /// PSPemu/PBOOT variant (not implemented yet).
    Pspemu,
}

impl From<FormatArg> for prx_encrypter::Format {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Psp => prx_encrypter::Format::Psp,
            FormatArg::Pspemu => prx_encrypter::Format::PspEmu,
        }
    }
}

/// Derive an output path by replacing the extension, e.g. `foo.prx` becomes
/// `foo.enc.prx`.
pub fn derive_output_path(input: &Path, infix: &str) -> PathBuf {
    let extension = input
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("prx")
        .to_owned();
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output")
        .to_owned();
    input.with_file_name(format!("{stem}.{infix}.{extension}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn derives_output_paths() {
        assert_eq!(
            derive_output_path(Path::new("foo.prx"), "enc"),
            PathBuf::from("foo.enc.prx")
        );
        assert_eq!(
            derive_output_path(Path::new("/tmp/game.prx"), "enc"),
            PathBuf::from("/tmp/game.enc.prx")
        );
        // No extension: fall back to .prx.
        assert_eq!(
            derive_output_path(Path::new("game"), "enc"),
            PathBuf::from("game.enc.prx")
        );
        assert_eq!(
            derive_output_path(Path::new("a.b.prx"), "dec"),
            PathBuf::from("a.b.dec.prx")
        );
    }

    #[test]
    fn parses_the_documented_invocations() {
        let cli =
            Cli::try_parse_from(["prx-encrypter", "encrypt", "in.prx", "-o", "out.prx"]).unwrap();
        assert!(matches!(cli.command, Command::Encrypt { .. }));

        let cli = Cli::try_parse_from(["prx-encrypter", "-v", "encrypt", "game.prx"]).unwrap();
        assert!(cli.verbose);

        assert!(Cli::try_parse_from(["prx-encrypter", "inspect", "a.prx"]).is_ok());
        assert!(Cli::try_parse_from(["prx-encrypter", "verify", "a.prx"]).is_ok());
        assert!(
            Cli::try_parse_from(["prx-encrypter", "encrypt", "a.prx", "--no-compress"]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["prx-encrypter", "encrypt", "a.prx", "--format", "pspemu"])
                .is_ok()
        );

        // Missing operands must fail rather than default to something.
        assert!(Cli::try_parse_from(["prx-encrypter", "encrypt"]).is_err());
        assert!(Cli::try_parse_from(["prx-encrypter"]).is_err());
    }
}
