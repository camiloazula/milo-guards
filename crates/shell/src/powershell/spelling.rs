//! The characters PowerShell reads as others: a space that is not an ASCII
//! one splits words, a typographic quote opens and closes a string, and an
//! en dash, em dash or horizontal bar at the start of a word is a `-`. The
//! grammar knows none of them, so a line is written with the ASCII ones
//! before it is parsed.

use std::borrow::Cow;

/// `text` with each character PowerShell reads as another written as that
/// one, where PowerShell reads it so: outside a string a space that is not an
/// ASCII one (U+0085, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029,
/// U+202F, U+205F, U+3000) is a space, a dash at the start of a word is `-`,
/// and a typographic quote opens a string; inside a string a quote of its
/// kind closes it, and everything else is the text it holds. A backtick
/// keeps the character after it as it is, and a comment is left as written.
pub(super) fn ascii(text: &str) -> Cow<'_, str> {
    if text.is_ascii() {
        return Cow::Borrowed(text);
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    // The strings and subexpressions the scan is in: a `$( … )` in a
    // double-quoted string is code again, up to its closing parenthesis.
    let mut nest: Vec<Within> = Vec::new();
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        match nest.last_mut() {
            Some(Within::Double) => match c {
                '`' => {
                    out.push(c);
                    out.extend(chars.get(at + 1));
                    at += 2;
                }
                c if is_double(c) && chars.get(at + 1).copied().is_some_and(is_double) => {
                    out.push_str("\"\"");
                    at += 2;
                }
                c if is_double(c) => {
                    out.push('"');
                    nest.pop();
                    at += 1;
                }
                '$' if chars.get(at + 1) == Some(&'(') => {
                    out.push_str("$(");
                    nest.push(Within::Code(1));
                    at += 2;
                }
                _ => {
                    out.push(c);
                    at += 1;
                }
            },
            code => {
                let previous = out.chars().next_back();
                match c {
                    '`' => {
                        out.push(c);
                        out.extend(chars.get(at + 1));
                        at += 2;
                    }
                    '(' => {
                        if let Some(Within::Code(open)) = code {
                            *open += 1;
                        }
                        out.push(c);
                        at += 1;
                    }
                    ')' => {
                        if let Some(Within::Code(open)) = code {
                            *open -= 1;
                            if *open == 0 {
                                nest.pop();
                            }
                        }
                        out.push(c);
                        at += 1;
                    }
                    '@' if chars.get(at + 1).copied().is_some_and(is_quote) => {
                        let end = here_string(&chars, at).unwrap_or(chars.len());
                        let body = &chars[at..end];
                        let quote = if body.get(1).copied().is_some_and(is_double) {
                            '"'
                        } else {
                            '\''
                        };
                        out.push('@');
                        out.push(quote);
                        if end == chars.len() {
                            out.extend(body.iter().skip(2));
                        } else {
                            // `…\n'@`: the closing quote is the one before the `@`.
                            out.extend(body.iter().skip(2).take(body.len().saturating_sub(4)));
                            out.push(quote);
                            out.push('@');
                        }
                        at = end;
                    }
                    c if is_single(c) => {
                        out.push('\'');
                        at += 1;
                        // A single-quoted string: a quote of its kind twice
                        // is one, once it closes the string.
                        while let Some(&inner) = chars.get(at) {
                            if is_single(inner) {
                                if chars.get(at + 1).copied().is_some_and(is_single) {
                                    out.push_str("''");
                                    at += 2;
                                    continue;
                                }
                                out.push('\'');
                                at += 1;
                                break;
                            }
                            out.push(inner);
                            at += 1;
                        }
                    }
                    c if is_double(c) => {
                        out.push('"');
                        nest.push(Within::Double);
                        at += 1;
                    }
                    '<' if chars.get(at + 1) == Some(&'#') => {
                        // A block comment runs to `#>`.
                        let end = (at + 2..chars.len().saturating_sub(1))
                            .find(|&i| chars[i] == '#' && chars[i + 1] == '>')
                            .map_or(chars.len(), |end| end + 2);
                        out.extend(&chars[at..end]);
                        at = end;
                    }
                    '#' if previous.is_none_or(starts_word) => {
                        // A line comment runs to the end of the line.
                        let end = (at..chars.len())
                            .find(|&i| chars[i] == '\n')
                            .unwrap_or(chars.len());
                        out.extend(&chars[at..end]);
                        at = end;
                    }
                    c if !c.is_ascii() && c.is_whitespace() => {
                        out.push(' ');
                        at += 1;
                    }
                    c if is_dash(c) && previous.is_none_or(starts_word) => {
                        out.push('-');
                        at += 1;
                    }
                    _ => {
                        out.push(c);
                        at += 1;
                    }
                }
            }
        }
    }
    if out == text {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(out)
    }
}

/// What the scan is inside of, besides the line's own code.
enum Within {
    /// A double-quoted string.
    Double,
    /// A `$( … )` in a double-quoted string, with how many parentheses are
    /// open.
    Code(usize),
}

/// Where the here-string that opens at `at` (`@'` or `@"`, then the end of
/// the line) ends: after the `'@` or `"@` at the start of a line. `None` when
/// it is not one, or is not closed.
fn here_string(chars: &[char], at: usize) -> Option<usize> {
    let double = is_double(*chars.get(at + 1)?);
    let quote = |c: char| if double { is_double(c) } else { is_single(c) };
    // Only white space may follow the opening marker on its line.
    let mut line = at + 2;
    while let Some(&c) = chars.get(line) {
        if c == '\n' {
            break;
        }
        if !c.is_whitespace() {
            return None;
        }
        line += 1;
    }
    let mut end = line;
    loop {
        if chars.get(end) == Some(&'\n')
            && chars.get(end + 1).copied().is_some_and(quote)
            && chars.get(end + 2) == Some(&'@')
        {
            return Some(end + 3);
        }
        end += 1;
        if end >= chars.len() {
            return None;
        }
    }
}

/// Whether a word can start after `c`.
fn starts_word(c: char) -> bool {
    c.is_ascii_whitespace() || matches!(c, '(' | '{' | ';' | '|' | '&' | ',')
}

/// A dash PowerShell reads as `-`: an en dash, an em dash, a horizontal bar.
fn is_dash(c: char) -> bool {
    matches!(c, '\u{2013}'..='\u{2015}')
}

/// A single quote, ASCII or typographic.
fn is_single(c: char) -> bool {
    matches!(c, '\'' | '\u{2018}'..='\u{201b}')
}

/// A double quote, ASCII or typographic.
fn is_double(c: char) -> bool {
    matches!(c, '"' | '\u{201c}'..='\u{201e}')
}

fn is_quote(c: char) -> bool {
    is_single(c) || is_double(c)
}

#[cfg(test)]
mod tests {
    use super::ascii;

    #[test]
    fn writes_what_powershell_reads_with_ascii() {
        let rows = [
            ("Remove-Item\u{a0}C:\\x", "Remove-Item C:\\x"),
            ("a\u{3000}b\u{2028}c\u{85}d", "a b c d"),
            (
                "redis-cli \u{201c}FLUSHALL\u{201d}",
                "redis-cli \"FLUSHALL\"",
            ),
            ("echo \u{2018}it\u{2019}\u{2019}s\u{2019}", "echo 'it''s'"),
            ("iex \u{2013}Command $x", "iex -Command $x"),
            ("rm \u{2014}r \u{2015}f", "rm -r -f"),
            // Text in a string is what it says.
            (
                "echo 'a\u{a0}b\u{2013}c\u{201c}'",
                "echo 'a\u{a0}b\u{2013}c\u{201c}'",
            ),
            ("echo \"a\u{a0}\u{2018}\"", "echo \"a\u{a0}\u{2018}\""),
            (
                "echo \"a$(x\u{a0}\u{2013}y)\u{a0}\"",
                "echo \"a$(x -y)\u{a0}\"",
            ),
            ("echo \"a$((1)\u{a0}\u{a0})\"", "echo \"a$((1)  )\""),
            ("echo \"\u{201c}\u{201d}\u{a0}\"", "echo \"\"\"\u{a0}\""),
            // A dash in a word is part of it.
            ("git push a\u{2013}b", "git push a\u{2013}b"),
            // An escape, a comment.
            ("echo a`\u{a0}b", "echo a`\u{a0}b"),
            ("echo x # a\u{a0}b\nrm\u{a0}y", "echo x # a\u{a0}b\nrm y"),
            ("echo <# a\u{a0}b #>\u{a0}y", "echo <# a\u{a0}b #> y"),
            // A here-string holds its text.
            (
                "@\u{201c}\na\u{a0}b\n\u{201d}@ | x\u{a0}y",
                "@\"\na\u{a0}b\n\"@ | x y",
            ),
            ("@'\na\u{a0}b", "@'\na\u{a0}b"),
            // Unclosed strings hold the rest.
            ("echo 'a\u{a0}", "echo 'a\u{a0}"),
            ("echo \"a\u{a0}", "echo \"a\u{a0}"),
        ];
        for (text, expected) in rows {
            assert_eq!(ascii(text), expected, "{text:?}");
        }
    }
}
