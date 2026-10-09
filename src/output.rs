use std::{
    fs::{self, File},
    io::{self, Write},
    path::Path,
};

use crate::account::MatchResultWithMnemonic;

/// Save a matched Session account.
pub(crate) fn save_match(
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
