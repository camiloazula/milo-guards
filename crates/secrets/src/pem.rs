//! A block of private key: the `-----BEGIN … PRIVATE KEY-----` line, the
//! base64 body and the `-----END` line.
//!
//! A header alone is not a key, so it is not a finding: the text that
//! explains the format names the header and holds no key. What follows the
//! header must look like a key's body: lines of base64 with no space in them
//! (the lines of an armour header, such as `Proc-Type: 4,ENCRYPTED`, are
//! allowed and do not count). A body that is cut short, with no `END` line,
//! is a key as far as it goes, and so is one written in a JSON string with
//! `\n` for its line ends.

use std::sync::OnceLock;

use regex::Regex;

use crate::mask::Mask;
use crate::scan::Hit;
use crate::Rule;

const HEADER: &str = r"-----BEGIN (?:[A-Z0-9]+ ){0,5}PRIVATE KEY(?: BLOCK)?-----";
const FOOTER: &str = r"^-----END (?:[A-Z0-9]+ ){0,5}PRIVATE KEY(?: BLOCK)?-----";

/// Base64 characters a body needs before it is called a key: the smallest
/// real key (an Ed25519 one) has 64.
const MIN_BODY: usize = 32;

fn header() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(HEADER).ok()).as_ref()
}

fn footer() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(FOOTER).ok()).as_ref()
}

/// Adds a hit for each block of private key in `text`.
pub(crate) fn scan(text: &str, lower: &str, out: &mut Vec<Hit>) {
    if !lower.contains("private key") {
        return;
    }
    let (Some(header), Some(footer)) = (header(), footer()) else {
        return;
    };
    let mut at = 0;
    while let Some(found) = header.find_at(text, at) {
        let body = read_body(text.as_bytes(), found.end());
        if body.base64 < MIN_BODY {
            at = found.end();
            continue;
        }
        let end = text
            .get(body.end..)
            .and_then(|rest| footer.find(rest))
            .map_or(body.last, |ending| body.end + ending.end());
        out.push(Hit {
            rule: Rule::PrivateKey,
            reason: "holds a private key",
            start: found.start(),
            end,
            mask: Mask::Head(found.end()),
        });
        at = end;
    }
}

/// What follows a header.
struct Body {
    /// How many base64 characters sit on lines with nothing else.
    base64: usize,
    /// Where the body stops: at the first character a body has none of, or
    /// at a run of five dashes (the `END` line).
    end: usize,
    /// The byte after the last base64 character, where a body with no `END`
    /// line stops.
    last: usize,
}

fn read_body(bytes: &[u8], from: usize) -> Body {
    let mut base64 = 0;
    let mut line_length = 0;
    let mut line_clean = true;
    // A space between two base64 characters makes the line prose; one before
    // the first (an indent) or after the last does not.
    let mut gap = false;
    let mut last = from;
    let mut dashes = 0;
    let mut at = from;
    let flush = |base64: &mut usize, length: &mut usize, clean: &mut bool, gap: &mut bool| {
        if *clean {
            *base64 += *length;
        }
        *length = 0;
        *clean = true;
        *gap = false;
    };
    while let Some(&byte) = bytes.get(at) {
        if byte == b'-' {
            dashes += 1;
            if dashes >= 5 {
                break;
            }
            line_clean = false;
            at += 1;
            continue;
        }
        dashes = 0;
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' => {
                if gap {
                    line_clean = false;
                }
                line_length += 1;
                at += 1;
                last = at;
            }
            b'\n' | b'\r' => {
                flush(&mut base64, &mut line_length, &mut line_clean, &mut gap);
                at += 1;
            }
            // A line end written as `\n`, `\r` or `\t` inside a string.
            b'\\' if matches!(bytes.get(at + 1), Some(b'n' | b'r' | b't')) => {
                flush(&mut base64, &mut line_length, &mut line_clean, &mut gap);
                at += 2;
            }
            b' ' | b'\t' => {
                gap = line_length > 0;
                at += 1;
            }
            // What a comment or a quotation puts before each line.
            b'#' | b'>' | b'*' | b'|' if line_length == 0 => at += 1,
            b':' | b',' | b'.' | b'_' => {
                line_clean = false;
                at += 1;
            }
            _ => break,
        }
    }
    flush(&mut base64, &mut line_length, &mut line_clean, &mut gap);
    // Four dashes were already passed when the fifth stopped the loop: they
    // began an `END` line, not the body.
    let end = if dashes >= 5 { at - 4 } else { at };
    Body { base64, end, last }
}
