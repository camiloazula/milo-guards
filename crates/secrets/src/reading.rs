//! Reading a text as it means, not as it is spelled.
//!
//! A secret written `ghp_Abc…`, `AKIA%41…` or with a zero-width space in
//! the middle is the same secret to whatever reads it next, so it is judged as
//! the same one. Before the table is run, a text is read into a second one:
//! an escape that stands for a printable ASCII character is that character
//! (`%41`, `\x41`, `A`, `\u{41}`, `&#65;`, `&#x41;`), and a character
//! that shows nothing (a zero-width space or joiner, a byte order mark, a
//! soft hyphen) is dropped. The table runs over the second text, and each
//! range found is carried back to the first, covering the whole escape.
//!
//! Only escapes of printable ASCII are read, so no line end is made and no
//! character is made that the text did not already hold a spelling of.

use std::borrow::Cow;

/// A text and the same text read; and where each part of the one came from.
pub(crate) struct Reading<'a> {
    /// The text the table runs over: the original, or the read copy.
    text: Cow<'a, str>,
    /// What was changed, in order.
    edits: Vec<Edit>,
}

/// One change: `original_len` bytes at `original` became `decoded_len`
/// (zero or one) bytes at `decoded`.
struct Edit {
    decoded: usize,
    original: usize,
    original_len: usize,
    decoded_len: usize,
    /// How many bytes this change and every one before it took away.
    removed: usize,
}

/// Characters that show nothing.
const INVISIBLE: [char; 8] = [
    '\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}', '\u{00ad}', '\u{034f}', '\u{180e}',
];

impl<'a> Reading<'a> {
    pub(crate) fn new(text: &'a str) -> Self {
        let escapes = text.contains(['%', '\\', '&']) || text.contains(INVISIBLE);
        let borrowed = |edits| Self {
            text: Cow::Borrowed(text),
            edits,
        };
        if !escapes {
            return borrowed(Vec::new());
        }
        let mut out = String::with_capacity(text.len());
        let mut edits: Vec<Edit> = Vec::new();
        let mut at = 0;
        while let Some(rest) = text.get(at..) {
            let Some(next) = rest.chars().next() else {
                break;
            };
            let (length, replacement) = if INVISIBLE.contains(&next) {
                (next.len_utf8(), Some(None))
            } else if let Some((length, c)) = escape(rest) {
                (length, Some(Some(c)))
            } else {
                (next.len_utf8(), None)
            };
            match replacement {
                None => out.push(next),
                Some(replacement) => {
                    let decoded_len = usize::from(replacement.is_some());
                    let removed =
                        edits.last().map_or(0, |edit| edit.removed) + length - decoded_len;
                    edits.push(Edit {
                        decoded: out.len(),
                        original: at,
                        original_len: length,
                        decoded_len,
                        removed,
                    });
                    out.extend(replacement);
                }
            }
            at += length;
        }
        if edits.is_empty() {
            return borrowed(edits);
        }
        Self {
            text: Cow::Owned(out),
            edits,
        }
    }

    /// The text the table runs over.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// Where the byte `at` of the read text starts in the original.
    fn original_start(&self, at: usize) -> usize {
        let count = self.edits.partition_point(|edit| edit.decoded <= at);
        match count.checked_sub(1).and_then(|last| self.edits.get(last)) {
            Some(edit) if edit.decoded == at && edit.decoded_len == 1 => edit.original,
            Some(edit) => at + edit.removed,
            None => at,
        }
    }

    /// The range of the original that `start..end` of the read text was read
    /// from.
    pub(crate) fn original(&self, start: usize, end: usize) -> (usize, usize) {
        if self.edits.is_empty() {
            return (start, end);
        }
        let last = self
            .text
            .get(..end)
            .and_then(|head| head.char_indices().next_back());
        let end = match last {
            Some((place, c)) => {
                let escaped = self
                    .edits
                    .iter()
                    .find(|edit| edit.decoded == place && edit.decoded_len == 1);
                // An escape ends where its last character does.
                escaped.map_or(self.original_start(place) + c.len_utf8(), |edit| {
                    edit.original + edit.original_len
                })
            }
            None => self.original_start(end),
        };
        (self.original_start(start), end)
    }
}

/// The printable ASCII character an escape at the start of `rest` stands for,
/// and how many bytes the escape takes.
fn escape(rest: &str) -> Option<(usize, char)> {
    let bytes = rest.as_bytes();
    let (length, code) = match bytes.first()? {
        b'%' => (3, hex(bytes.get(1..3)?)?),
        b'\\' => match bytes.get(1)? {
            b'x' => (4, hex(bytes.get(2..4)?)?),
            b'u' if bytes.get(2) == Some(&b'{') => {
                let close = bytes.iter().take(10).position(|&b| b == b'}')?;
                let digits = rest.get(3..close)?;
                if digits.is_empty() || digits.len() > 6 {
                    return None;
                }
                (close + 1, hex(digits.as_bytes())?)
            }
            b'u' => (6, hex(bytes.get(2..6)?)?),
            _ => return None,
        },
        b'&' if bytes.get(1) == Some(&b'#') => {
            let close = bytes.iter().take(12).position(|&b| b == b';')?;
            let digits = rest.get(2..close)?;
            let code = match digits.strip_prefix(['x', 'X']) {
                Some(hexits) => hex(hexits.as_bytes())?,
                None => digits
                    .parse::<u32>()
                    .ok()
                    .filter(|_| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))?,
            };
            (close + 1, code)
        }
        _ => return None,
    };
    // Only what a person could type on a line: printable ASCII.
    let c = char::from_u32(code).filter(|c| (' '..='~').contains(c))?;
    Some((length, c))
}

/// The number `digits` spell in hex, if they are all hex digits.
fn hex(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u32, |number, &digit| {
        let value = char::from(digit).to_digit(16)?;
        number.checked_mul(16)?.checked_add(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> String {
        Reading::new(text).text().to_string()
    }

    #[test]
    fn printable_ascii_escapes_are_the_character() {
        assert_eq!(read("a%41b"), "aAb");
        assert_eq!(read("\\x41\\u0042\\u{43}&#68;&#x45;"), "ABCDE");
        assert_eq!(read("%7e%20"), "~ ");
        assert_eq!(read("x\u{200b}y\u{feff}z\u{ad}"), "xyz");
    }

    #[test]
    fn what_is_not_printable_ascii_or_not_an_escape_is_left() {
        for text in [
            "%0A",
            "%7f",
            "%80",
            "%4",
            "%zz",
            "\\x0a",
            "\\u00e9",
            "\\u{1F600}",
            "\\u{}",
            "\\u{41",
            "\\n",
            "&#10;",
            "&#233;",
            "&#;",
            "&#x;",
            "&#65",
            "&amp;",
            "100%",
            "&",
            "\\",
            "%%41",
        ] {
            let read = read(text);
            // A `%%41` is a percent and then `%41`, read once.
            assert!(read == text || text == "%%41", "{text:?} became {read:?}");
        }
        assert_eq!(read("%%41"), "%A");
    }

    #[test]
    fn a_range_goes_back_to_the_whole_escape() {
        let text = "é %41KI\\u0041 x\u{200b}y";
        let reading = Reading::new(text);
        assert_eq!(reading.text(), "é AKIA xy");
        let at = reading.text().find("AKIA").unwrap_or(0);
        let (start, end) = reading.original(at, at + 4);
        assert_eq!(&text[start..end], "%41KI\\u0041");
        let at = reading.text().find("xy").unwrap_or(0);
        let (start, end) = reading.original(at, at + 2);
        assert_eq!(&text[start..end], "x\u{200b}y");
        // A range that stops before a dropped character leaves it out.
        let (start, end) = reading.original(at, at + 1);
        assert_eq!(&text[start..end], "x");
    }

    #[test]
    fn a_text_with_no_escape_is_borrowed() {
        let reading = Reading::new("plain text, 100% é");
        assert!(matches!(reading.text, Cow::Borrowed(_)));
        assert_eq!(reading.original(2, 5), (2, 5));
    }

    /// A small deterministic generator.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> usize {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as usize
        }
    }

    #[test]
    fn any_range_maps_back_to_a_range_that_reads_as_it_does() {
        const PIECES: [&str; 14] = [
            "a", "Z", "9", "é", "日", "😀", "%41", "%2e", "\\u0042", "\\x43", "&#68;", "\u{200b}",
            "%", "\\",
        ];
        let mut random = Lcg(3);
        for _ in 0..2_000 {
            let text: String = (0..random.next() % 12)
                .map(|_| PIECES[random.next() % PIECES.len()])
                .collect();
            let reading = Reading::new(&text);
            let read = reading.text();
            let bounds: Vec<usize> = (0..=read.len())
                .filter(|&at| read.is_char_boundary(at))
                .collect();
            for &start in &bounds {
                for &end in bounds.iter().filter(|&&end| end > start) {
                    let (from, to) = reading.original(start, end);
                    assert!(from <= to && to <= text.len(), "{text:?} {start}..{end}");
                    assert!(text.is_char_boundary(from), "{text:?} {start}..{end}");
                    assert!(text.is_char_boundary(to), "{text:?} {start}..{end}");
                    assert_eq!(
                        Reading::new(&text[from..to]).text(),
                        &read[start..end],
                        "{text:?} {start}..{end} -> {from}..{to}"
                    );
                }
            }
        }
    }
}
