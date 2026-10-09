use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
};

/// A parsed vanity pattern.
#[derive(Clone, Debug)]
pub(crate) enum Pattern {
    /// 05AB -> 05AB...
    Prefix(String),

    /// ..AB -> ...AB
    Suffix(String),

    /// ..AB.. -> ...AB...
    Contains(String),
}

impl Pattern {
    pub(crate) fn display(&self) -> String {
        match self {
            Pattern::Prefix(value) => value.clone(),
            Pattern::Suffix(value) => format!("..{}", value),
            Pattern::Contains(value) => format!("..{}..", value),
        }
    }

    /// Check whether this pattern matches a Session ID.
    pub(crate) fn matches(&self, session_id: &str) -> bool {
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

/// Load and validate vanity patterns.
///
/// Supported syntax:
///
///     05AB       Prefix
///     05AB..     Prefix
///     ..AB       Suffix
///     ..AB..     Contains
pub(crate) fn load_patterns(
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

        let pattern = line.to_ascii_uppercase();

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
