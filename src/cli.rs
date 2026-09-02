//! Command-line interface definition.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

/// Build, encrypt and inspect PSP EBOOTs.
#[derive(Debug, Parser)]
#[command(name = "pspbuild", version, about, long_about = None)]
pub struct Cli {
    /// Print details of each stage to stderr.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt a PRX, or the DATA.PSP of an existing EBOOT.
    Encrypt {
        /// Input PRX, ELF or EBOOT.PBP.
        input: PathBuf,

        /// Output file. Defaults to the input with a `.enc.prx` suffix.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Do not gzip the payload before encrypting.
        #[arg(long)]
        no_compress: bool,
    },

    /// Build an MG EBOOT.PBP (homebrew) from a module.
    BuildMg {
        /// Input PRX or ELF.
        input: PathBuf,

        /// Output EBOOT. Defaults to `EBOOT.PBP` beside the input.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// XMB title. Defaults to the module's own name.
        #[arg(short, long)]
        title: Option<String>,

        /// Minimum firmware written to PSP_SYSTEM_VER.
        #[arg(long, value_name = "VERSION")]
        system_version: Option<String>,

        /// Do not gzip the payload before encrypting.
        #[arg(long)]
        no_compress: bool,

        /// Existing EBOOT.PBP to build on; its other sections are preserved.
        #[arg(long, value_name = "FILE")]
        base: Option<PathBuf>,

        /// XMB icon.
        #[arg(long, value_name = "FILE")]
        icon0: Option<PathBuf>,
        /// Animated XMB icon.
        #[arg(long, value_name = "FILE")]
        icon1: Option<PathBuf>,
        /// Background image, upper layer.
        #[arg(long, value_name = "FILE")]
        pic0: Option<PathBuf>,
        /// Background image.
        #[arg(long, value_name = "FILE")]
        pic1: Option<PathBuf>,
        /// XMB background audio.
        #[arg(long, value_name = "FILE")]
        snd0: Option<PathBuf>,
    },

    /// Build an EG EBOOT.PBP from a PSP ISO.
    BuildEg {
        /// Input PSP ISO.
        input: PathBuf,

        /// Output EBOOT.PBP.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Content ID, e.g. UL0000-ABCD12345_00-0000000000000000.
        ///
        /// For a fixed-key title this also derives the encryption key, so it
        /// must match what the container will be distributed as.
        #[arg(long, value_name = "ID")]
        content_id: String,

        /// Store every block uncompressed.
        ///
        /// Roughly triples the output. Useful for comparing against a
        /// reference build that was made the same way.
        #[arg(long)]
        no_compress: bool,

        /// PNG to show while the game loads.
        #[arg(long, value_name = "FILE")]
        startdat: Option<PathBuf>,

        /// OPNSSMP.BIN module to carry, encrypted under the version key.
        #[arg(long, value_name = "FILE")]
        opnssmp: Option<PathBuf>,
    },

    /// Report what a file is and what it contains.
    Inspect {
        /// File to inspect.
        input: PathBuf,
    },

    /// Check a file as thoroughly as the format allows.
    Verify {
        /// File to verify.
        input: PathBuf,
    },

    /// Write each section of a PBP to a directory.
    Extract {
        /// EBOOT.PBP to extract.
        input: PathBuf,

        /// Destination directory. Created if it does not exist.
        #[arg(short, long, default_value = ".")]
        output: PathBuf,

        /// Also write DATA.PSP decrypted, as DATA.PSP.dec.
        #[arg(long)]
        decrypt: bool,
    },

    /// Decrypt an encrypted PRX back to the original module.
    Decrypt {
        /// Encrypted PRX or EBOOT.PBP.
        input: PathBuf,

        /// Output file. Defaults to the input with a `.dec.prx` suffix.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
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
        let cli = Cli::try_parse_from(["pspbuild", "encrypt", "in.prx", "-o", "out.prx"]).unwrap();
        assert!(matches!(cli.command, Command::Encrypt { .. }));

        let cli = Cli::try_parse_from(["pspbuild", "-v", "encrypt", "game.prx"]).unwrap();
        assert!(cli.verbose);

        assert!(Cli::try_parse_from(["pspbuild", "inspect", "a.prx"]).is_ok());
        assert!(Cli::try_parse_from(["pspbuild", "verify", "a.prx"]).is_ok());
        assert!(Cli::try_parse_from(["pspbuild", "extract", "EBOOT.PBP", "-o", "out"]).is_ok());
        assert!(Cli::try_parse_from(["pspbuild", "build-mg", "game.prx"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "pspbuild",
                "build-eg",
                "game.iso",
                "--content-id",
                "UL0000-ABCD12345_00-0000000000000000",
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["pspbuild", "encrypt", "a.prx", "--no-compress"]).is_ok());

        // Missing operands must fail rather than default to something.
        assert!(Cli::try_parse_from(["pspbuild", "encrypt"]).is_err());
        assert!(Cli::try_parse_from(["pspbuild", "build-mg"]).is_err());
        // A content ID is not optional: for a fixed-key title it derives the
        // encryption key, so there is no sensible default.
        assert!(Cli::try_parse_from(["pspbuild", "build-eg", "game.iso"]).is_err());
        assert!(Cli::try_parse_from(["pspbuild"]).is_err());
    }

    #[test]
    fn build_mg_takes_its_documented_options() {
        let cli = Cli::try_parse_from([
            "pspbuild",
            "build-mg",
            "game.prx",
            "-o",
            "EBOOT.PBP",
            "--title",
            "My Game",
            "--system-version",
            "6.60",
            "--icon0",
            "ICON0.PNG",
            "--base",
            "old.PBP",
        ])
        .unwrap();

        let Command::BuildMg {
            title,
            system_version,
            icon0,
            base,
            ..
        } = cli.command
        else {
            panic!("wrong subcommand");
        };
        assert_eq!(title.as_deref(), Some("My Game"));
        assert_eq!(system_version.as_deref(), Some("6.60"));
        assert_eq!(icon0, Some(PathBuf::from("ICON0.PNG")));
        assert_eq!(base, Some(PathBuf::from("old.PBP")));
    }
}
