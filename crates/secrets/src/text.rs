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

/// Whether the last 16 characters of `secret` are varied enough to be
/// random. A key is random; a placeholder (`xxxxxxxx`, `00000000`,
/// `abababab`) is not, and writing one in a README is not a leak.
pub(crate) fn varied(secret: &str) -> bool {
    let mut tail: Vec<char> = secret.chars().rev().take(16).collect();
    tail.sort_unstable();
    tail.dedup();
    tail.len() >= 6
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
                .all(|c| matches!(c, '*' | 'x' | 'X' | '.' | '-' | '_' | '#' | '\u{2022}')))
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
/// word: the literals of a language and the label of a field.
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

/// What a stand-in value begins with, with case, `_`, `-` and `.` left out.
/// A closed list: a word is added with a row in the tests, never to catch a
/// secret that someone found, which is the other list's job (there is none).
const STEMS: [&str; 10] = [
    "changeme",
    "change-me",
    "change_me",
    "replace",
    "dummy",
    "placeholder",
    "example",
    "sample",
    "todo",
    "fixme",
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

/// Whether `value` has the shape of a stand-in for a value, by shape and not
/// by a list of words:
///
/// - **upper snake case**, the name of a constant (`DEFAULT_TOKEN`,
///   `REPLACE_ME`);
/// - **repeated characters**, or too few different ones to be random
///   (`xxxxxxxx`, `ghp_` and thirty-six `x`);
/// - **elided**, with `...` or `…` in it (`sk-...`);
/// - **its own name**, when `name_word` (the word the name ends in:
///   `password`, `apikey`) is in the value (`api_key=api_key`,
///   `dummy_password`, `my-secret-2`);
/// - **a stem** from a closed list that begins a value written to be
///   replaced (`changeme123`), or a literal (`string`, `null`).
pub(crate) fn is_placeholder(value: &str, name_word: Option<&str>) -> bool {
    let lower = value.to_ascii_lowercase();
    let squeezed = squeezed(value);
    // A stem begins the value and is a word of its own: `changeme123` and
    // `replace-with-your-token`, not `Replacement9`.
    let stem = STEMS.iter().any(|stem| {
        lower
            .strip_prefix(stem)
            .is_some_and(|rest| !rest.starts_with(|c: char| c.is_ascii_lowercase()))
    });
    // The word the name ends in, and the word before `key` in it.
    let own = name_word.is_some_and(|word| {
        let words = [
            Some(word),
            word.strip_suffix("key").filter(|w| w.len() >= 5),
        ];
        // A short word is in too many passwords: it must be all of it. And a
        // value with a run of digits is a value.
        let few_digits = squeezed.bytes().filter(u8::is_ascii_digit).count() <= 3;
        words.into_iter().flatten().any(|word| {
            if word.len() >= 5 {
                squeezed.contains(word) && few_digits
            } else {
                squeezed == word
            }
        })
    });
    is_placeholder_shape(value)
        || LITERALS.contains(&squeezed.as_str())
        || stem
        || own
        || lower.starts_with("your_")
        || lower.starts_with("your-")
}

/// The shapes of a stand-in that need no name: all but its own name, the
/// literals and the stems.
pub(crate) fn is_placeholder_shape(value: &str) -> bool {
    let upper_snake = value.contains('_')
        && value.starts_with(|c: char| c.is_ascii_uppercase())
        && value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    let few = value.chars().count() >= 16 && !varied(value);
    // The values AWS's documentation shows end in `EXAMPLE` or `EXAMPLEKEY`.
    let documented = value.ends_with("EXAMPLE") || value.ends_with("EXAMPLEKEY");
    upper_snake
        || few
        || documented
        || is_mask(value)
        || value.contains("...")
        || value.contains('…')
}
