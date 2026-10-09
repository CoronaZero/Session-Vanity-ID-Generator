use std::{
    path::Path,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use crate::account::{generate_account, MatchResultWithMnemonic};
use crate::mnemonic::encode_session_mnemonic;
use crate::output::save_match;
use crate::pattern::Pattern;

/// Worker thread.
pub(crate) fn worker_loop(
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
