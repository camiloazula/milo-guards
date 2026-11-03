//! Numbers spelled as PowerShell reads them. PowerShell takes the letters of
//! a number in any case (`1MB`, `1KB`, `0X1F`, `1E3`, `10L`); the grammar
//! knows only the lower-case ones and fails on the rest, which would leave
//! a plain `Where-Object { $_.Length -gt 1MB }` unreadable. A line is
//! written with those letters in lower case before it is parsed.

use std::borrow::Cow;

/// The multipliers a number may end in.
const MULTIPLIERS: [&[u8]; 5] = [b"kb", b"mb", b"gb", b"tb", b"pb"];

/// `text` with the letters of each number in code written in lower case. A
/// number starts where a word can (after white space, an operator or a
/// bracket) and ends where a word does; text in quotes and comments is left
/// as written. A line the scan cannot follow with certainty (a here-string,
/// a subexpression in a double-quoted string, a quote or a block comment
/// that does not end) is left whole as written, for the grammar to fail on.
pub(super) fn lower(text: &str) -> Cow<'_, str> {
    let bytes = text.as_bytes();
    let any = bytes
        .windows(2)
        .any(|pair| pair[0].is_ascii_alphanumeric() && pair[1].is_ascii_uppercase());
    if !any {
        return Cow::Borrowed(text);
    }
    let mut out = bytes.to_vec();
    let mut changed = false;
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        let previous = at
            .checked_sub(1)
            .and_then(|before| bytes.get(before))
            .copied();
        match byte {
            b'@' if matches!(bytes.get(at + 1), Some(b'\'' | b'"')) => {
                return Cow::Borrowed(text);
            }
            b'\'' => {
                let Some(end) = bytes
                    .get(at + 1..)
                    .and_then(|rest| rest.iter().position(|&b| b == b'\''))
                else {
                    return Cow::Borrowed(text);
                };
                at += end + 2;
            }
            b'"' => {
                let mut end = at + 1;
                loop {
                    match bytes.get(end) {
                        None => return Cow::Borrowed(text),
                        Some(b'`') => end += 2,
                        Some(b'$') if bytes.get(end + 1) == Some(&b'(') => {
                            return Cow::Borrowed(text);
                        }
                        Some(b'"') => break,
                        Some(_) => end += 1,
                    }
                }
                at = end + 1;
            }
            b'`' => at += 2,
            b'<' if bytes.get(at + 1) == Some(&b'#') => {
                let Some(end) = bytes
                    .get(at + 2..)
                    .and_then(|rest| rest.windows(2).position(|pair| pair == b"#>"))
                else {
                    return Cow::Borrowed(text);
                };
                at += end + 4;
            }
            b'#' if previous.is_none_or(|previous| {
                previous.is_ascii_whitespace() || matches!(previous, b';' | b'(' | b'{')
            }) =>
            {
                at = bytes
                    .get(at..)
                    .and_then(|rest| rest.iter().position(|&b| b == b'\n'))
                    .map_or(bytes.len(), |end| at + end);
            }
            _ if starts(bytes, at) => {
                let end = number(bytes, at);
                if end > at {
                    if let Some(span) = out.get_mut(at..end) {
                        if span.iter().any(u8::is_ascii_uppercase) {
                            span.make_ascii_lowercase();
                            changed = true;
                        }
                    }
                    at = end;
                } else {
                    at += 1;
                }
            }
            _ => at += 1,
        }
    }
    if !changed {
        return Cow::Borrowed(text);
    }
    String::from_utf8(out).map_or(Cow::Borrowed(text), Cow::Owned)
}

/// Whether a number may start at `at`: a digit, or a `.` before one, where
/// a word can begin.
fn starts(bytes: &[u8], at: usize) -> bool {
    let first = bytes.get(at).copied();
    let digit = first.is_some_and(|byte| byte.is_ascii_digit())
        || (first == Some(b'.') && bytes.get(at + 1).is_some_and(u8::is_ascii_digit));
    if !digit {
        return false;
    }
    at.checked_sub(1)
        .and_then(|before| bytes.get(before))
        .copied()
        .is_none_or(opens)
}

/// Whether a number can begin after `byte`: white space, a bracket, a
/// separator or an operator. After a `-` or `+` it may also be the end of a
/// word (`a-1MB`), which the grammar reads either way.
fn opens(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'(' | b')'
                | b','
                | b';'
                | b'='
                | b'{'
                | b'}'
                | b'['
                | b'|'
                | b'+'
                | b'-'
                | b'*'
                | b'/'
                | b'%'
                | b'!'
                | b'<'
                | b'>'
                | b'&'
        )
}

/// Where the number that starts at `at` ends, as PowerShell reads one: hex
/// digits after `0x`, or digits with a fraction and an exponent, then a type
/// letter and a multiplier. `at` when the word goes on past it (`1MBx`): it
/// is no number.
fn number(bytes: &[u8], at: usize) -> usize {
    let digits = |from: usize, hex: bool| {
        bytes.get(from..).map_or(0, |rest| {
            rest.iter()
                .take_while(|b| {
                    if hex {
                        b.is_ascii_hexdigit()
                    } else {
                        b.is_ascii_digit()
                    }
                })
                .count()
        })
    };
    let mut end = at;
    let hex = bytes.get(at) == Some(&b'0')
        && bytes
            .get(at + 1)
            .is_some_and(|b| b.eq_ignore_ascii_case(&b'x'))
        && bytes.get(at + 2).is_some_and(u8::is_ascii_hexdigit);
    let mut real = false;
    if hex {
        end += 2;
        end += digits(end, true);
    } else {
        end += digits(end, false);
        if bytes.get(end) == Some(&b'.') && bytes.get(end + 1).is_some_and(u8::is_ascii_digit) {
            real = true;
            end += 1;
            end += digits(end, false);
        }
        if bytes
            .get(end)
            .is_some_and(|b| b.eq_ignore_ascii_case(&b'e'))
        {
            let sign = usize::from(matches!(bytes.get(end + 1), Some(b'+' | b'-')));
            let count = digits(end + 1 + sign, false);
            if count > 0 {
                real = true;
                end += 1 + sign + count;
            }
        }
    }
    // A type letter: `l` for a long, `d` for a decimal (not after a fraction).
    if bytes.get(end).is_some_and(|b| {
        b.eq_ignore_ascii_case(&b'l') || (!hex && !real && b.eq_ignore_ascii_case(&b'd'))
    }) {
        end += 1;
    }
    if let Some(pair) = bytes.get(end..end + 2) {
        if MULTIPLIERS
            .iter()
            .any(|multiplier| pair.eq_ignore_ascii_case(multiplier))
        {
            end += 2;
        }
    }
    let goes_on = bytes
        .get(end)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b >= 0x80);
    if goes_on {
        at
    } else {
        end
    }
}

#[cfg(test)]
mod tests {
    use super::lower;

    #[test]
    fn writes_the_letters_of_a_number_in_lower_case() {
        let cases = [
            ("$_.Length -gt 1MB", "$_.Length -gt 1mb"),
            ("1KB + 2Gb + 3tB + 4PB", "1kb + 2gb + 3tb + 4pb"),
            (
                "0X1F; 0x1FMB; 10L; 10LKB; 5D",
                "0x1f; 0x1fmb; 10l; 10lkb; 5d",
            ),
            ("1.5E3; .5MB; -1MB", "1.5e3; .5mb; -1mb"),
            ("@(1MB,2MB)", "@(1mb,2mb)"),
            // Words, paths and text are left as written.
            ("Get-Item .\\1MB", "Get-Item .\\1MB"),
            ("echo a1MB 1MBx", "echo a1MB 1MBx"),
            ("1MB+1MB-1MB*2KB", "1mb+1mb-1mb*2kb"),
            ("echo '1MB' \"1MB\" # 1MB", "echo '1MB' \"1MB\" # 1MB"),
            ("echo <# 1MB #> 1MB", "echo <# 1MB #> 1mb"),
            // A line the scan cannot follow is left whole.
            ("echo \"$(1MB)\" 1MB", "echo \"$(1MB)\" 1MB"),
            ("echo @'\n1MB\n'@ 1MB", "echo @'\n1MB\n'@ 1MB"),
            ("echo '1MB", "echo '1MB"),
            ("Get-ChildItem", "Get-ChildItem"),
        ];
        for (text, expected) in cases {
            assert_eq!(lower(text), expected, "{text:?}");
        }
    }
}
