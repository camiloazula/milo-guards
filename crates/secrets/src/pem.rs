//! A block of private key: the `-----BEGIN … PRIVATE KEY-----` line, the
//! base64 body and the `-----END` line; the same block of SSH.com
//! (`---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----`); and a PuTTY key file's
//! `Private-Lines`.
//!
//! A header alone is not a key, so it is not a finding: the text that
//! explains the format names the header and holds no key. What follows the
//! header must look like a key's body: lines of base64 with no space in them.
//! Before the body come the lines of an armour header (`Proc-Type: 4,…`,
//! `Version:`, `Comment:`), up to a blank line; they are part of the block
//! and count for nothing. A body that is cut short, with no `END` line, is a
//! key as far as it goes, and so is one written in a string with `\n` (or
//! `\\n`, in a string in a string) for its line ends, indented, or each line
//! quoted or commented.
//!
//! Every line is read once and a header's lines are few and short, so a text
//! of headers is read in time linear in its length.

use std::sync::OnceLock;

use regex::Regex;

use crate::mask::Mask;
use crate::scan::Hit;
use crate::Rule;

const HEADER: &str = r"-{4,5} ?BEGIN (?:[A-Z0-9]+ ){0,5}PRIVATE KEY(?: BLOCK)? ?-{4,5}";
const FOOTER: &str = r"^-{4,5} ?END (?:[A-Z0-9]+ ){0,5}PRIVATE KEY(?: BLOCK)? ?-{4,5}";
const PUTTY: &str = r"Private-Lines:[ \t]*([0-9]{1,3})";

/// Base64 characters a body needs before it is called a key: the smallest
/// real key (an Ed25519 one) has 64.
const MIN_BODY: usize = 32;

/// The longest line of armour header, and the most of them, read.
const HEADER_LINE: usize = 256;
const HEADER_LINES: usize = 24;

fn compiled(cell: &'static OnceLock<Option<Regex>>, pattern: &str) -> Option<&'static Regex> {
    cell.get_or_init(|| Regex::new(pattern).ok()).as_ref()
}

fn header() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    compiled(&REGEX, HEADER)
}

fn footer() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    compiled(&REGEX, FOOTER)
}

fn putty() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    compiled(&REGEX, PUTTY)
}

/// Adds a hit for each block of private key in `text`.
pub(crate) fn scan(text: &str, lower: &str, out: &mut Vec<Hit>) {
    if lower.contains("private key") {
        blocks(text, out);
    }
    if lower.contains("private-lines") {
        putty_lines(text, out);
    }
}

fn blocks(text: &str, out: &mut Vec<Hit>) {
    let (Some(header), Some(footer)) = (header(), footer()) else {
        return;
    };
    let mut at = 0;
    while let Some(found) = header.find_at(text, at) {
        let body = read_body(text.as_bytes(), found.end());
        if body.units < MIN_BODY {
            at = found.end();
            continue;
        }
        let end = text
            .get(body.stop..)
            .and_then(|rest| footer.find(rest))
            .map_or(body.last, |ending| body.stop + ending.end());
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

/// A PuTTY key file says how many lines of base64 its private part has.
fn putty_lines(text: &str, out: &mut Vec<Hit>) {
    let Some(regex) = putty() else {
        return;
    };
    let mut at = 0;
    while let Some(captures) = regex.captures_at(text, at) {
        let (Some(whole), Some(count)) = (captures.get(0), captures.get(1)) else {
            break;
        };
        at = whole.end();
        let Ok(count) = count.as_str().parse::<usize>() else {
            continue;
        };
        let mut lines = Lines::new(text.as_bytes(), whole.end());
        let mut first = None;
        let mut last = 0;
        let mut units = 0;
        let mut taken = 0;
        while taken < count.min(64) {
            let Some(line) = lines.next_line() else {
                break;
            };
            match line.content {
                // What is left of the `Private-Lines` line itself.
                Content::Blank if first.is_none() => {}
                Content::Base64(length) => {
                    taken += 1;
                    first.get_or_insert(line.begin);
                    last = line.begin + length;
                    units += length;
                }
                _ => break,
            }
        }
        if let (Some(start), true) = (first, units >= MIN_BODY) {
            out.push(Hit {
                rule: Rule::PrivateKey,
                reason: "holds a PuTTY private key",
                start,
                end: last,
                mask: Mask::Length,
            });
            at = at.max(last);
        }
    }
}

/// What a line holds, after the indent and the marks a comment or a quote
/// puts before it, and the marks it puts after.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Content {
    /// Nothing.
    Blank,
    /// Base64 and nothing else, this many bytes.
    Base64(usize),
    /// A run of dashes: the `END` line.
    Dashes,
    /// A line of the armour header: `Name: value`.
    Armour,
    /// Anything else.
    Other,
}

struct Line {
    /// Where the content begins.
    begin: usize,
    content: Content,
    /// The line's text, up to its end, for an armour line to be followed.
    continues: bool,
}

struct Lines<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Lines<'a> {
    fn new(bytes: &'a [u8], at: usize) -> Self {
        Self { bytes, at }
    }

    /// The length of the line end at `at`: a newline, or `\n`, `\r`, `\t`
    /// written with one or more backslashes.
    fn line_end(&self, at: usize) -> Option<usize> {
        match self.bytes.get(at)? {
            b'\n' | b'\r' => Some(1),
            b'\\' => {
                let mut length = 1;
                // Nine backslashes are as many as any string in a string in a
                // string writes; more is a run of backslashes, not a line end.
                while length < 9 && self.bytes.get(at + length) == Some(&b'\\') {
                    length += 1;
                }
                matches!(self.bytes.get(at + length), Some(b'n' | b'r' | b't'))
                    .then_some(length + 1)
            }
            _ => None,
        }
    }

    fn next_line(&mut self) -> Option<Line> {
        if self.at >= self.bytes.len() {
            return None;
        }
        // Where the line stops, and where it goes on.
        let mut stop = self.at;
        while stop < self.bytes.len() && self.line_end(stop).is_none() {
            // A run of dashes in the middle of a line begins another: the
            // `END` line, or the next block's header.
            if stop > self.at && self.bytes.get(stop..stop + 4) == Some(b"----") {
                break;
            }
            stop += 1;
            if stop - self.at > 4096 {
                break;
            }
        }
        let next = stop + self.line_end(stop).unwrap_or(0);
        let line = self.bytes.get(self.at..stop).unwrap_or_default();
        let marks = |b: &u8| matches!(b, b' ' | b'\t' | b'#' | b'>' | b'*' | b'|' | b'"' | b'\'');
        let lead = line.iter().take_while(|b| marks(b)).count();
        let trail = line
            .iter()
            .rev()
            .take_while(|b| marks(b) || **b == b',' || **b == b'\\')
            .count();
        let content = line
            .get(lead..line.len().saturating_sub(trail).max(lead))
            .unwrap_or_default();
        let kind = if content.is_empty() {
            Content::Blank
        } else if content.starts_with(b"----") {
            Content::Dashes
        } else if content
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            Content::Base64(content.len())
        } else if content.len() <= HEADER_LINE && is_armour(content) {
            Content::Armour
        } else {
            Content::Other
        };
        let begin = self.at + lead;
        let continues = line.last() == Some(&b'\\') && self.line_end(stop).is_some();
        self.at = next;
        Some(Line {
            begin,
            content: kind,
            continues,
        })
    }
}

/// `Name: value`: a name of letters, digits and dashes, and a colon.
fn is_armour(content: &[u8]) -> bool {
    let name = content
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'-')
        .count();
    name > 0 && content.get(name) == Some(&b':') && content[0].is_ascii_alphabetic()
}

/// What follows a header.
struct Body {
    /// How many base64 characters sit on lines with nothing else.
    units: usize,
    /// Where the line that is not the body begins: the `END` line, if any.
    stop: usize,
    /// The byte after the last base64 character, where a body with no `END`
    /// line stops.
    last: usize,
}

fn read_body(bytes: &[u8], from: usize) -> Body {
    let mut lines = Lines::new(bytes, from);
    let mut units = 0;
    let mut last = from;
    // Where the line that is not the body begins; the end of the text if
    // the body goes on to it.
    let mut stop = bytes.len();
    let mut armour = true;
    let mut armour_lines = 0;
    let mut continued = false;
    // The first line is what is left of the header's own.
    let mut rest_of_header = true;
    while let Some(line) = lines.next_line() {
        let first = std::mem::replace(&mut rest_of_header, false);
        match line.content {
            // The blank line that ends the armour header.
            Content::Blank if first => {}
            Content::Blank => {
                armour = false;
                continued = false;
            }
            Content::Armour if armour && armour_lines < HEADER_LINES => {
                armour_lines += 1;
                continued = line.continues;
            }
            // The line after one that ends in a backslash goes on with it.
            Content::Other | Content::Armour | Content::Base64(_) if continued && armour => {
                continued = line.continues;
            }
            Content::Base64(length) => {
                armour = false;
                units += length;
                last = line.begin + length;
            }
            _ => {
                stop = line.begin;
                break;
            }
        }
    }
    Body {
        units,
        stop,
        last: if units == 0 { from } else { last },
    }
}
