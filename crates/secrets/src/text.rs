//! Small readings of a text that several detectors share. Every function
//! takes byte offsets on `char` boundaries and returns without slicing
//! through a character.

/// The character that ends just before byte `at`.
pub(crate) fn before(text: &str, at: usize) -> Option<char> {
    text.get(..at)?.chars().next_back()
}

/// The character that starts at byte `at`.
pub(crate) fn after(text: &str, at: usize) -> Option<char> {
    text.get(at..)?.chars().next()
}

/// Whether `text[start..end]` stands alone: no ASCII letter or digit touches
/// it on either side. A letter or digit beside a token means the token is a
/// piece of something longer (a base64 blob, an identifier), which is not
/// what the token's shape is.
///
/// Only ASCII counts, on purpose: text written without spaces (Chinese,
/// Japanese) runs words together, and a key must still be found beside it.
pub(crate) fn alone(text: &str, start: usize, end: usize) -> bool {
    !before(text, start).is_some_and(|c| c.is_ascii_alphanumeric())
        && !after(text, end).is_some_and(|c| c.is_ascii_alphanumeric())
}

/// Whether the last 32 characters of `secret`, after the fixed prefix of the
/// provider (what ends at the last `_`, `-` or `.` of its first 16 characters:
/// `sk_live_`, `glpat-`, `sk-ant-api03-`), have six different ones at least. A
/// key is random; a placeholder (`xxxxxxxx`, `00000000`, `abababab`, after
/// however long a prefix) is not, and writing one in a README is not a leak. A
/// key that is random in its front and repeats at its end is still a key.
pub(crate) fn varied(secret: &str) -> bool {
    let prefix = secret
        .char_indices()
        .take(16)
        .filter(|(_, c)| matches!(c, '_' | '-' | '.'))
        .last()
        .map_or(0, |(at, c)| at + c.len_utf8());
    let mut body: Vec<char> = secret
        .get(prefix..)
        .unwrap_or_default()
        .chars()
        .rev()
        .take(32)
        .collect();
    body.sort_unstable();
    body.dedup();
    body.len() >= 6
}

/// Whether `value` is no value at all but a stand-in for one: a reference to
/// a variable (`$TOKEN`, `${TOKEN}`, `{{ token }}`), a template field
/// (`<password>`, `%s`), a redaction (`[REDACTED]`) or a mask (`****`,
/// `xxxxxxxx`). Such a text names where a secret comes from, and holds none.
pub(crate) fn is_reference(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return true;
    };
    if value.contains("${") || value.contains("{{") || value.contains("{%") {
        return true;
    }
    let last = value.chars().next_back().unwrap_or(first);
    match first {
        '$' => {
            let name = &value[1..];
            let name = name
                .strip_prefix('{')
                .and_then(|n| n.strip_suffix('}'))
                .unwrap_or(name);
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '-')
                && !name.starts_with(|c: char| c.is_ascii_digit())
        }
        '<' => last == '>',
        '{' => last == '}',
        '[' => last == ']',
        '%' => true,
        _ => is_mask(value),
    }
}

/// Whether `value` is three or more of one character, or only of the
/// characters people write a hidden value with: `xxxx`, `****`, `0000`.
fn is_mask(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return true;
    };
    value.chars().count() >= 3
        && (chars.all(|c| c == first)
            || value
                .chars()
                .all(|c| matches!(c, '*' | 'x' | 'X' | '.' | '#' | '\u{2022}')))
}

/// Whether `text[start..end]` is a piece of a longer dotted number
/// (`1.2.3.4.5`, `4111111111111111.5`): a dot and a digit touch it.
pub(crate) fn in_longer_number(text: &str, start: usize, end: usize) -> bool {
    let dotted_before = before(text, start) == Some('.')
        && text
            .get(..start - 1)
            .and_then(|head| head.chars().next_back())
            .is_some_and(|c| c.is_ascii_digit());
    let dotted_after = after(text, end) == Some('.')
        && text
            .get(end + 1..)
            .and_then(|tail| tail.chars().next())
            .is_some_and(|c| c.is_ascii_digit());
    dotted_before || dotted_after
}

/// Words a value is when it stands for a missing one, written as a whole
/// word: the literals of a language.
const LITERALS: [&str; 12] = [
    "string",
    "str",
    "null",
    "none",
    "nil",
    "undefined",
    "true",
    "false",
    "required",
    "optional",
    "hidden",
    "masked",
];

/// The words a stand-in is written with, with case, `_`, `-` and `.` left
/// out: a closed list. A stand-in is one of these, alone or with the word the
/// name ends in, and up to three digits (`example`, `changeme123`,
/// `dummy_password`, `your_api_key_here`); never one of them followed by
/// other characters, which is a value that begins with a word.
const STEMS: [&str; 10] = [
    "changeme",
    "replaceme",
    "replace",
    "dummy",
    "placeholder",
    "example",
    "sample",
    "todo",
    "fixme",
    "your",
];

/// `value` with letters lowercased and `_`, `-` and `.` left out: the form
/// in which two spellings of one name (`API_KEY`, `api-key`, `apiKey`) are
/// equal.
pub(crate) fn squeezed(value: &str) -> String {
    value
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | '.'))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Where a value was found, for judging whether it is a stand-in.
pub(crate) struct Standin<'a> {
    /// The word the name ends in (`password`, `apikey`), if there is a name.
    pub(crate) word: Option<&'a str>,
    /// Whether the value was in quotes.
    pub(crate) quoted: bool,
    /// Whether it is the password of an address.
    pub(crate) address: bool,
    /// Whether it is on a line that is only `NAME=value` or `export NAME=value`:
    /// an environment file, which has no constants to name.
    pub(crate) env_file: bool,
}

/// Whether `value` is a stand-in for a value. **A stand-in is recognised by
/// the shape of the whole value, never by a prefix or by what it contains**;
/// anything else is a value, since a password missed costs more than a mask
/// too many. The shapes:
///
/// - **its own name**, all of it: `api_key=api_key`, `password=PASSWORD`,
///   `token=Token` (case, `_`, `-` and `.` left out on both sides);
/// - **a literal**: `string`, `null`, `true`, …;
/// - **a stem** of a closed list, alone or with the name's word, and up to
///   three digits: `changeme123`, `dummy_password`, `your_api_key_here`;
/// - **a constant**, unquoted, not in an address and not on a line of an
///   environment file (`NAME=value`, which has no constants): upper snake case, letters
///   only (a trailing number of one or two digits is allowed): `DEFAULT_TOKEN`,
///   `REPLACE_ME`. `K7X_93QZ_M2PL` is a value;
/// - **a mask** (`****`, `xxxxxxxx`), **few characters** repeated
///   (`abababab`), or **an elision**: a short head that ends in `_` or `-`
///   (or is a key's capital letters, `AKIA`), and a run of `.`, `…`, `*`, `x`
///   or `0` to the end: `sk-...`, `ghp_xxxxxxxx`. A visible head and tail
///   around the dots (`ab...cd9X`) is a value;
/// - **documented** by AWS: twenty or forty characters that end in `EXAMPLE` or
///   `EXAMPLEKEY`.
pub(crate) fn is_placeholder(value: &str, context: &Standin<'_>) -> bool {
    let squeezed = squeezed(value);
    // The word the name ends in, and the word before `key` in it.
    let words = context.word.map(|word| {
        [
            Some(word),
            word.strip_suffix("key").filter(|w| w.len() >= 5),
        ]
    });
    let own = words
        .into_iter()
        .flatten()
        .flatten()
        .any(|word| squeezed == word);
    let digits = squeezed
        .bytes()
        .rev()
        .take_while(u8::is_ascii_digit)
        .count();
    let stem =
        digits <= 3
            && squeezed.get(..squeezed.len() - digits).is_some_and(|rest| {
                STEMS.iter().any(|stem| {
                    let after = rest.strip_prefix(stem);
                    after.is_some_and(|after| {
                        after.is_empty()
                            || words.into_iter().flatten().flatten().any(|word| {
                                after == word || after.strip_prefix(word) == Some("here")
                            })
                    })
                })
            });
    let documented = matches!(value.len(), 20 | 40)
        && (value.ends_with("EXAMPLE") || value.ends_with("EXAMPLEKEY"));
    let constant = !context.quoted && !context.address && !context.env_file && is_constant(value);
    own || LITERALS.contains(&squeezed.as_str())
        || stem
        || constant
        || documented
        || is_mask(value)
        || has_few_characters(value)
        || is_elided(value)
}

/// Upper snake case: two or more words of capital letters joined by `_`,
/// the last of them a number of one or two digits instead, if it is.
fn is_constant(value: &str) -> bool {
    let words: Vec<&str> = value.split('_').collect();
    let Some((last, head)) = words.split_last() else {
        return false;
    };
    words.len() >= 2
        && head
            .iter()
            .all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_uppercase()))
        && !last.is_empty()
        && (last.bytes().all(|b| b.is_ascii_uppercase())
            || (last.len() <= 2 && last.bytes().all(|b| b.is_ascii_digit())))
}

/// Eight or more characters of at most two kinds, letters or digits among
/// them: `abababab`.
fn has_few_characters(value: &str) -> bool {
    let mut kinds: Vec<char> = value.chars().collect();
    kinds.sort_unstable();
    kinds.dedup();
    value.chars().count() >= 8
        && kinds.len() <= 2
        && value.chars().any(|c| c.is_ascii_alphanumeric())
}

/// A short head and a run of dots, `…`, stars or `x`s to the end.
fn is_elided(value: &str) -> bool {
    let Some(last) = value.chars().next_back() else {
        return false;
    };
    let least = match last {
        '…' => 1,
        '.' | '*' => 3,
        'x' | 'X' | '0' | '#' => 8,
        _ => return false,
    };
    let run = value.chars().rev().take_while(|c| *c == last).count();
    let head = value
        .char_indices()
        .rev()
        .nth(run - 1)
        .and_then(|(at, _)| value.get(..at))
        .unwrap_or_default();
    run >= least
        && head.chars().count() <= 16
        && (head.is_empty()
            || head.ends_with(['_', '-'])
            || (head.len() <= 8 && head.bytes().all(|b| b.is_ascii_uppercase())))
}
