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

    /// Pattern file, one prefix per line
    #[arg(short, long)]
    patterns: PathBuf,

    /// Output directory
    #[arg(short, long, default_value = "found")]
    output: PathBuf,

    /// Session mnemonic word list
    #[arg(
        long,
        default_value = "english.json"
    )]
    wordlist: PathBuf,
}

#[derive(Clone)]
struct MatchResult {
    session_id: String,
    mnemonic: String,
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

    /*
     * Shared state.
     */
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
        println!("  {}", pattern);
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
    patterns: &[String],
    output: &Path,
    stop: &AtomicBool,
    attempts: &AtomicU64,
) {
    while !stop.load(Ordering::Relaxed) {
        /*
         * Generate one Session account.
         */
        if let Some(account) = generate_account(words) {
            attempts.fetch_add(1, Ordering::Relaxed);

            /*
             * Check every pattern.
             */
            for pattern in patterns {
                if account.session_id.starts_with(pattern) {
                    match save_match(output, &account) {
                        Ok(true) => {
                            println!(
                                "\n[MATCH] {} -> {}",
                                pattern,
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
        } else {
            attempts.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Generate a Session account.
fn generate_account(words: &[String]) -> Option<MatchResult> {
    /*
     * Session uses a 16-byte random seed.
     */
    let random = sodiumoxide::randombytes::randombytes(16);

    let mut seed = [0u8; 16];

    seed.copy_from_slice(&random);

    /*
     * Generate the Session recovery phrase.
     */
    let mnemonic = encode_session_mnemonic(&seed, words);

    /*
     * Session pads the 16-byte seed to 32 bytes
     * before passing it to crypto_sign_seed_keypair().
     */
    let mut sodium_seed_bytes = [0u8; 32];

    sodium_seed_bytes[..16].copy_from_slice(&seed);

    let sodium_seed =
        ed25519::Seed::from_slice(&sodium_seed_bytes)?;

    /*
     * Generate Ed25519 key pair.
     */
    let (ed_public, _ed_secret) =
        ed25519::keypair_from_seed(&sodium_seed);

    /*
     * Convert Ed25519 public key to X25519 public key.
     */
    let x_public =
        ed25519::to_curve25519_pk(&ed_public).ok()?;

    /*
     * Session Account ID:
     *
     *     05 + X25519 public key
     *
     * 32 bytes public key = 64 hex characters.
     * 05 = 2 characters.
     *
     * Total:
     *
     *     66 hexadecimal characters
     */
    let mut session_id = String::with_capacity(66);

    session_id.push_str("05");

    for byte in x_public.as_ref() {
        session_id.push_str(&format!("{:02X}", byte));
    }

    Some(MatchResult {
        session_id,
        mnemonic,
        seed,
    })
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
        if word.len() < 3 {
            continue;
        }

        checksum_input.push_str(&word[..3]);
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

    /*
     * Session's english.json is a JSON array:
     *
     * [
     *   "word1",
     *   "word2",
     *   ...
     * ]
     */
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

/// Load vanity prefixes.
fn load_patterns(
    path: &Path,
) -> io::Result<Vec<String>> {
    let file = File::open(path)?;

    let reader = BufReader::new(file);

    let mut patterns = Vec::new();

    for line in reader.lines() {
        let line = line?;

        let line = line.trim();

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

        /*
         * Session IDs use hexadecimal representation.
         */
        let pattern = line.to_ascii_uppercase();

        /*
         * Session Account IDs start with 05.
         */
        if !pattern.starts_with("05") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid Session ID prefix: {}",
                    line
                ),
            ));
        }

        /*
         * Make sure the pattern is hexadecimal.
         */
        if !pattern
            .chars()
            .all(|c| c.is_ascii_hexdigit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "pattern contains non-hexadecimal characters: {}",
                    line
                ),
            ));
        }

        /*
         * Maximum length of a Session ID is 66
         * hexadecimal characters.
         */
        if pattern.len() > 66 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "pattern is longer than a Session ID: {}",
                    line
                ),
            ));
        }

        patterns.push(pattern);
    }

    Ok(patterns)
}

/// Save a matched Session account.
fn save_match(
    output: &Path,
    account: &MatchResult,
) -> io::Result<bool> {
    /*
     * Each account gets its own directory:
     *
     * found/
     *   └── SessionID/
     */
    let directory =
        output.join(&account.session_id);

    /*
     * create_dir() instead of create_dir_all()
     * allows us to determine whether another worker
     * has already saved the same account.
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
    let mut result =
        String::with_capacity(data.len() * 2);

    for byte in data {
        result.push_str(
            &format!("{:02x}", byte)
        );
    }

    result
}