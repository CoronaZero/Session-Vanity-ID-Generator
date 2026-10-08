use clap::Parser;
use crc32fast::Hasher;
use serde::Deserialize;
use sodiumoxide::crypto::sign::ed25519;

use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

/// Session Vanity ID Generator
#[derive(Parser, Debug)]
#[command(
    name = "session-vanity",
    version,
    about = "Generate vanity Session Account IDs"
)]
struct Args {
    /// Number of worker threads
    #[arg(short = 't', long, default_value_t = 1)]
    threads: usize,

    /// Pattern file, one pattern per line
    #[arg(short, long)]
    patterns: PathBuf,

    /// Output directory
    #[arg(short, long, default_value = "found")]
    output: PathBuf,

    /// Session mnemonic word list
    #[arg(long, default_value = "english.json")]
    wordlist: PathBuf,
}

/// A parsed vanity pattern.
#[derive(Clone, Debug)]
enum Pattern {
    /// 05AB -> 05AB...
    Prefix(String),

    /// ..AB -> ...AB
    Suffix(String),

    /// ..AB.. -> ...AB...
    Contains(String),
}

impl Pattern {
    fn display(&self) -> String {
        match self {
            Pattern::Prefix(value) => value.clone(),
            Pattern::Suffix(value) => format!("..{}", value),
            Pattern::Contains(value) => format!("..{}..", value),
        }
    }

    /// Check whether this pattern matches a Session ID.
    fn matches(&self, session_id: &str) -> bool {
        match self {
            Pattern::Prefix(value) => {
                session_id.starts_with(value)
            }

            Pattern::Suffix(value) => {
                session_id.ends_with(value)
            }

            Pattern::Contains(value) => {
                session_id.contains(value)
            }
        }
    }
}

struct MatchResult {
    session_id: String,
    seed: [u8; 16],
}

#[derive(Deserialize)]
struct WordList(Vec<String>);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.threads == 0 {
        return Err("--threads must be greater than 0".into());
    }

    if !args.patterns.exists() {
        return Err(format!(
            "pattern file does not exist: {}",
            args.patterns.display()
        )
        .into());
    }

    if !args.wordlist.exists() {
        return Err(format!(
            "wordlist does not exist: {}",
            args.wordlist.display()
        )
        .into());
    }

    /*
     * Initialize libsodium.
     */
    sodiumoxide::init()
        .map_err(|_| "failed to initialize libsodium")?;

    /*
     * Load Session mnemonic word list.
     */
    let words = load_wordlist(&args.wordlist)?;

    /*
     * Load vanity patterns.
     */
    let patterns = load_patterns(&args.patterns)?;

    if patterns.is_empty() {
        return Err("no valid patterns found".into());
    }

    /*
     * Create output directory.
     */
    fs::create_dir_all(&args.output)?;

    let patterns = Arc::new(patterns);
    let words = Arc::new(words);
    let output = Arc::new(args.output);

    let stop = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));

    /*
     * Ctrl+C handler.
     */
    {
        let stop = Arc::clone(&stop);

        ctrlc::set_handler(move || {
            stop.store(true, Ordering::Relaxed);
        })?;
    }

    println!("Session Vanity ID Generator");
    println!("============================");
    println!("Threads : {}", args.threads);
    println!("Patterns: {}", patterns.len());
    println!("Wordlist: {} words", words.len());
    println!("Output  : {}", output.display());
    println!();

    println!("Patterns:");

    for pattern in patterns.iter() {
        println!("  {}", pattern.display());
    }

    println!();
    println!("Searching...");
    println!("Press Ctrl+C to stop.");
    println!();

    let start = Instant::now();

    let mut workers = Vec::with_capacity(args.threads);

    /*
     * Start workers.
     */
    for _ in 0..args.threads {
        let patterns = Arc::clone(&patterns);
        let words = Arc::clone(&words);
        let output = Arc::clone(&output);
        let stop = Arc::clone(&stop);
        let attempts = Arc::clone(&attempts);

        let worker = thread::spawn(move || {
            worker_loop(
                &words,
                &patterns,
                &output,
                &stop,
                &attempts,
            );
        });

        workers.push(worker);
    }

    /*
     * Statistics loop.
     */
    while !stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(1));

        let count = attempts.load(Ordering::Relaxed);
        let elapsed = start.elapsed().as_secs_f64();

        let speed = if elapsed > 0.0 {
            count as f64 / elapsed
        } else {
            0.0
        };

        print!(
            "\rAttempts: {:>15} | Speed: {:>12.0} attempts/s",
            count,
            speed
        );

        io::stdout().flush()?;
    }

    println!();
    println!();
    println!("Stopping workers...");

    /*
     * Wait for all workers.
     */
    for worker in workers {
        let _ = worker.join();
    }

    let count = attempts.load(Ordering::Relaxed);
    let elapsed = start.elapsed().as_secs_f64();

    let speed = if elapsed > 0.0 {
        count as f64 / elapsed
    } else {
        0.0
    };

    println!();
    println!("Stopped.");
    println!("Attempts : {}", count);
    println!("Average  : {:.0} attempts/s", speed);

    Ok(())
}

/// Worker thread.
fn worker_loop(
    words: &[String],
    patterns: &[Pattern],
    output: &Path,
    stop: &AtomicBool,
    attempts: &AtomicU64,
) {
    while !stop.load(Ordering::Relaxed) {
        /*
         * Generate only the Session ID.
         *
         * The mnemonic is generated only after a match,
         * which avoids a significant amount of unnecessary work.
         */
        let account = generate_account();

        attempts.fetch_add(1, Ordering::Relaxed);

        /*
         * Check every pattern.
         */
        for pattern in patterns {
            if pattern.matches(&account.session_id) {
                /*
                 * Generate the mnemonic only when we actually
                 * found a matching Session ID.
                 */
                let mnemonic =
                    encode_session_mnemonic(&account.seed, words);

                let account = MatchResultWithMnemonic {
                    session_id: account.session_id.clone(),
                    mnemonic,
                    seed: account.seed,
                };

                match save_match(output, &account) {
                    Ok(true) => {
                        println!(
                            "\n[MATCH] {} -> {}",
                            pattern.display(),
                            account.session_id
                        );
                    }

                    Ok(false) => {
                        /*
                         * The account was already saved.
                         */
                    }

                    Err(error) => {
                        eprintln!(
                            "\n[ERROR] Failed to save {}: {}",
                            account.session_id,
                            error
                        );
                    }
                }
            }
        }
    }
}

/// Account information used during the search.
struct MatchResultWithMnemonic {
    session_id: String,
    mnemonic: String,
    seed: [u8; 16],
}

/// Generate a Session account ID.
///
/// The mnemonic is intentionally NOT generated here.
fn generate_account() -> MatchResult {
    /*
     * Session uses a 16-byte random seed.
     */
    let random = sodiumoxide::randombytes::randombytes(16);

    let mut seed = [0u8; 16];
    seed.copy_from_slice(&random);

    /*
     * Session pads the 16-byte seed to 32 bytes
     * before passing it to crypto_sign_seed_keypair().
     */
    let mut sodium_seed_bytes = [0u8; 32];

    sodium_seed_bytes[..16].copy_from_slice(&seed);

    let sodium_seed =
        ed25519::Seed::from_slice(&sodium_seed_bytes)
            .expect("32-byte seed must always be valid");

    /*
     * Generate Ed25519 key pair.
     */
    let (ed_public, _ed_secret) =
        ed25519::keypair_from_seed(&sodium_seed);

    /*
     * Convert Ed25519 public key to X25519 public key.
     */
    let x_public =
        ed25519::to_curve25519_pk(&ed_public)
            .expect("valid Ed25519 public key must convert");

    /*
     * Session Account ID:
     *
     *     05 + X25519 public key
     *
     * 66 hexadecimal characters in total.
     */
    let mut session_id = String::with_capacity(66);

    session_id.push_str("05");

    for byte in x_public.as_ref() {
        session_id.push_str(&format!("{:02X}", byte));
    }

    MatchResult {
        session_id,
        seed,
    }
}

/// Encode Session's 16-byte seed into a 13-word mnemonic.
fn encode_session_mnemonic(
    seed: &[u8; 16],
    words: &[String],
) -> String {
    const WORD_COUNT: u32 = 1626;

    let mut result = Vec::with_capacity(13);

    /*
     * 16 bytes = four 32-bit integers.
     *
     * Each integer produces three words.
     */
    for chunk in seed.chunks_exact(4) {
        let value = u32::from_le_bytes([
            chunk[0],
            chunk[1],
            chunk[2],
            chunk[3],
        ]);

        let word1 = value % WORD_COUNT;

        let word2 =
            ((value / WORD_COUNT) + word1)
                % WORD_COUNT;

        let word3 =
            (((value / WORD_COUNT) / WORD_COUNT)
                + word2)
                % WORD_COUNT;

        result.push(words[word1 as usize].clone());
        result.push(words[word2 as usize].clone());
        result.push(words[word3 as usize].clone());
    }

    /*
     * Session checksum:
     *
     * Take the first three characters of each
     * generated word and calculate CRC32.
     */
    let mut checksum_input = String::with_capacity(36);

    for word in &result {
        if word.len() >= 3 {
            checksum_input.push_str(&word[..3]);
        }
    }

    let mut hasher = Hasher::new();
    hasher.update(checksum_input.as_bytes());

    let checksum = hasher.finalize();

    /*
     * Select one of the 12 data words as
     * the checksum word.
     */
    let checksum_index =
        (checksum % result.len() as u32) as usize;

    result.push(result[checksum_index].clone());

    result.join(" ")
}

/// Load Session mnemonic word list.
fn load_wordlist(
    path: &Path,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let data = fs::read_to_string(path)?;

    let words: Vec<String> =
        serde_json::from_str(&data)?;

    if words.len() != 1626 {
        return Err(format!(
            "invalid wordlist size: {}, expected 1626",
            words.len()
        )
        .into());
    }

    Ok(words)
}

/// Load and validate vanity patterns.
///
/// Supported syntax:
///
///     05AB       Prefix
///     05AB..     Prefix
///     ..AB       Suffix
///     ..AB..     Contains
fn load_patterns(
    path: &Path,
) -> io::Result<Vec<Pattern>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut patterns = Vec::new();

    for (line_number, line) in reader.lines().enumerate() {
        let line_number = line_number + 1;
        let original = line?;
        let line = original.trim();

        /*
         * Ignore empty lines.
         */
        if line.is_empty() {
            continue;
        }

        /*
         * Ignore comments.
         */
        if line.starts_with('#') {
            continue;
        }

        let mut pattern = line.to_ascii_uppercase();

        /*
         * Only these characters are allowed:
         *
         *   0-9
         *   A-F
         *   .
         */
        if !pattern
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.')
        {
            eprintln!(
                "[WARNING] line {} ignored: '{}' \
                 contains invalid characters. \
                 Only 0-9, A-F and '.' are allowed.",
                line_number,
                original
            );
            continue;
        }

        /*
         * Dots are only meaningful at the beginning/end.
         *
         * Examples:
         *
         *   05AB..   valid
         *   ..AB     valid
         *   ..AB..   valid
         *
         *   05..AB   invalid
         *   AB..CD   invalid
         */
        let leading_dots = pattern.starts_with("..");
        let trailing_dots = pattern.ends_with("..");

        let core = if leading_dots && trailing_dots {
            &pattern[2..pattern.len() - 2]
        } else if leading_dots {
            &pattern[2..]
        } else if trailing_dots {
            &pattern[..pattern.len() - 2]
        } else {
            &pattern[..]
        };

        /*
         * A pattern must contain actual hexadecimal characters.
         */
        if core.is_empty() {
            eprintln!(
                "[WARNING] line {} ignored: '{}' \
                 does not contain a hexadecimal pattern.",
                line_number,
                original
            );
            continue;
        }

        /*
         * No single '.' is allowed.
         *
         * We only support '..' as the wildcard marker.
         */
        if pattern.contains('.') {
            let dot_count = pattern.matches('.').count();

            if dot_count != 2
                && dot_count != 4
            {
                eprintln!(
                    "[WARNING] line {} ignored: '{}' \
                     uses an invalid '.' wildcard. \
                     Use '..AB', 'AB..', or '..AB..'.",
                    line_number,
                    original
                );
                continue;
            }
        }

        /*
         * Dots must only appear at the beginning or end.
         */
        let inner = if leading_dots {
            &pattern[2..]
        } else {
            &pattern[..]
        };

        let inner = if inner.ends_with("..") {
            &inner[..inner.len() - 2]
        } else {
            inner
        };

        if inner.contains('.') {
            eprintln!(
                "[WARNING] line {} ignored: '{}' \
                 has '..' in the middle. \
                 Wildcards are only allowed at the beginning/end.",
                line_number,
                original
            );
            continue;
        }

        /*
         * The core must be hexadecimal.
         */
        if !core
            .chars()
            .all(|c| c.is_ascii_hexdigit())
        {
            eprintln!(
                "[WARNING] line {} ignored: '{}' \
                 contains invalid hexadecimal characters.",
                line_number,
                original
            );
            continue;
        }

        /*
         * Session IDs are exactly 66 hexadecimal characters.
         */
        if core.len() > 66 {
            eprintln!(
                "[WARNING] line {} ignored: '{}' \
                 is longer than a Session ID.",
                line_number,
                original
            );
            continue;
        }

        /*
         * A prefix must describe an actual Session ID.
         *
         * Every Session Account ID starts with 05.
         */
        if !leading_dots && !core.starts_with("05") {
            eprintln!(
                "[WARNING] line {} ignored: '{}' \
                 is an invalid prefix. \
                 Session Account IDs must start with 05.",
                line_number,
                original
            );
            continue;
        }

        /*
         * A prefix/suffix/contains pattern with an odd number
         * of hexadecimal characters can never match a byte-aligned
         * representation if it is intended to describe complete
         * bytes.
         *
         * We do NOT reject it because hexadecimal prefixes such as
         * 05A are perfectly valid string prefixes.
         */

        /*
         * Construct the parsed pattern.
         */
        let parsed = if leading_dots && trailing_dots {
            Pattern::Contains(core.to_string())
        } else if leading_dots {
            Pattern::Suffix(core.to_string())
        } else {
            Pattern::Prefix(core.to_string())
        };

        patterns.push(parsed);
    }

    Ok(patterns)
}

/// Save a matched Session account.
fn save_match(
    output: &Path,
    account: &MatchResultWithMnemonic,
) -> io::Result<bool> {
    /*
     * Each account gets its own directory.
     */
    let directory =
        output.join(&account.session_id);

    /*
     * create_dir() allows us to determine whether
     * another worker already saved this account.
     */
    match fs::create_dir(&directory) {
        Ok(_) => {}

        Err(error)
            if error.kind()
                == io::ErrorKind::AlreadyExists =>
        {
            return Ok(false);
        }

        Err(error) => {
            return Err(error);
        }
    }

    /*
     * account.txt
     */
    let mut account_file =
        File::create(directory.join("account.txt"))?;

    writeln!(
        account_file,
        "Session Account ID:"
    )?;

    writeln!(
        account_file,
        "{}",
        account.session_id
    )?;

    writeln!(account_file)?;

    writeln!(
        account_file,
        "Recovery Phrase:"
    )?;

    writeln!(
        account_file,
        "{}",
        account.mnemonic
    )?;

    writeln!(account_file)?;

    writeln!(
        account_file,
        "Seed:"
    )?;

    writeln!(
        account_file,
        "{}",
        hex_encode(&account.seed)
    )?;

    /*
     * recovery_phrase.txt
     */
    let mut phrase_file =
        File::create(
            directory.join("recovery_phrase.txt")
        )?;

    writeln!(
        phrase_file,
        "{}",
        account.mnemonic
    )?;

    /*
     * seed.hex
     */
    let mut seed_file =
        File::create(
            directory.join("seed.hex")
        )?;

    writeln!(
        seed_file,
        "{}",
        hex_encode(&account.seed)
    )?;

    Ok(true)
}

/// Convert bytes to lowercase hexadecimal.
fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] =
        b"0123456789abcdef";

    let mut result =
        String::with_capacity(data.len() * 2);

    for &byte in data {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }

    result
}
