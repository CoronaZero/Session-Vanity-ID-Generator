use clap::Parser;

use std::path::PathBuf;

/// Session Vanity ID Generator
#[derive(Parser, Debug)]
#[command(
    name = "session-vanity",
    version,
    about = "Generate vanity Session Account IDs"
)]
pub(crate) struct Args {
    /// Number of worker threads
    #[arg(short = 't', long, default_value_t = 1)]
    pub(crate) threads: usize,

    /// Pattern file, one pattern per line
    #[arg(short, long)]
    pub(crate) patterns: PathBuf,

    /// Output directory
    #[arg(short, long, default_value = "found")]
    pub(crate) output: PathBuf,

    /// Session mnemonic word list
    #[arg(long, default_value = "english.json")]
    pub(crate) wordlist: PathBuf,
}
