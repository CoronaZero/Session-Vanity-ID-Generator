mod account;
mod cli;
mod mnemonic;
mod output;
mod pattern;
mod worker;

use clap::Parser;

use std::{
    fs,
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use crate::cli::Args;
use crate::mnemonic::load_wordlist;
use crate::pattern::load_patterns;
use crate::worker::worker_loop;

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
