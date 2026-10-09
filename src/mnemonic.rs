use crc32fast::Hasher;

use std::{fs, path::Path};

/// Encode Session's 16-byte seed into a 13-word mnemonic.
pub(crate) fn encode_session_mnemonic(
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
pub(crate) fn load_wordlist(
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
