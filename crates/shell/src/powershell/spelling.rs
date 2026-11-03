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
/// kind closes it, and everything else is the text it holds, but for a
/// `$( … )`, which is code again (in a `@" … "@` here-string too). A here-
/// string opens only at the start of a word, with nothing after its marker
/// on its line. A backtick keeps the character after it as it is, a comment
/// is left as written, and so is the text after `--%` up to a pipe or the
/// end of the line, which PowerShell hands on as it is.
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
            Some(within @ (Within::Double | Within::Here)) => {
                let here = matches!(within, Within::Here);
                match c {
                    '`' => {
                        out.push(c);
                        out.extend(chars.get(at + 1));
                        at += 2;
                    }
                    // A here-string ends at a quote and `@` at the start of
                    // a line; any other quote in it is text.
                    '\n' if here
                        && chars.get(at + 1).copied().is_some_and(is_double)
                        && chars.get(at + 2) == Some(&'@') =>
                    {
                        out.push_str("\n\"@");
                        nest.pop();
                        at += 3;
                    }
                    c if !here
                        && is_double(c)
                        && chars.get(at + 1).copied().is_some_and(is_double) =>
                    {
                        out.push_str("\"\"");
                        at += 2;
                    }
                    c if !here && is_double(c) => {
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
                }
            }
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
                    // `--%` hands the rest of the line, up to a pipe, to the
                    // program as it is written: a typographic quote there is
                    // no quote to it, nor to `cmd`.
                    c if (c == '-' || is_dash(c))
                        && previous.is_none_or(starts_word)
                        && chars
                            .get(at + 1)
                            .copied()
                            .is_some_and(|c| c == '-' || is_dash(c))
                        && chars.get(at + 2) == Some(&'%') =>
                    {
                        out.push_str("--%");
                        let end = (at + 3..chars.len())
                            .find(|&i| matches!(chars[i], '|' | '\n'))
                            .unwrap_or(chars.len());
                        out.extend(&chars[at + 3..end]);
                        at = end;
                    }
                    // A here-string opens at the start of a word, with
                    // nothing but white space after it on its line;
                    // anywhere else the `@` is text and the quote opens a
                    // string (`me@"host"`).
                    '@' if chars.get(at + 1).copied().is_some_and(is_quote)
                        && previous
                            .is_none_or(|previous| starts_word(previous) || previous == '=') =>
                    {
                        let Some(body) = header(&chars, at + 2) else {
                            out.push('@');
                            at += 1;
                            continue;
                        };
                        let double = is_double(chars[at + 1]);
                        out.push('@');
                        out.push(if double { '"' } else { '\'' });
                        out.extend(chars[at + 2..body].iter().map(|&c| {
                            if c.is_ascii() {
                                c
                            } else {
                                ' '
                            }
                        }));
                        at = body;
                        if double {
                            // Its body is read as a double-quoted string's:
                            // a `$( … )` in it is code.
                            nest.push(Within::Here);
                            continue;
                        }
                        // `…\n'@`: the closing quote is the one before the
                        // `@`; the body is the text it holds.
                        let end = (at..chars.len()).find(|&i| {
                            chars[i] == '\n'
                                && chars.get(i + 1).copied().is_some_and(is_single)
                                && chars.get(i + 2) == Some(&'@')
                        });
                        if let Some(end) = end {
                            out.extend(&chars[at..=end]);
                            out.push_str("'@");
                            at = end + 3;
                        } else {
                            out.extend(&chars[at..]);
                            at = chars.len();
                        }
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
    /// A double-quoted here-string (`@"` … `"@`).
    Here,
    /// A `$( … )` in a double-quoted string, with how many parentheses are
    /// open.
    Code(usize),
}

/// Where the body of a here-string whose marker (`@'` or `@"`) ends before
/// `at` starts: after the end of the marker's line, which holds nothing but
/// white space. `None` when something else follows the marker on its line,
/// and it is not one.
fn header(chars: &[char], at: usize) -> Option<usize> {
    let mut line = at;
    while let Some(&c) = chars.get(line) {
        if c == '\n' {
            return Some(line);
        }
        if !c.is_whitespace() {
            return None;
        }
        line += 1;
    }
    Some(line)
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
            (
                "@\u{201c}\n\u{201c}$(rm\u{a0}x)\n\u{201d}@\u{a0}y",
                "@\"\n\u{201c}$(rm x)\n\"@ y",
            ),
            (
                "@'\n$(rm\u{a0}x)\n\u{2019}@\u{a0}y",
                "@'\n$(rm\u{a0}x)\n'@ y",
            ),
            // An `@` and a quote in a word, or with more on the line, open
            // no here-string.
            ("ssh me@\"h\"; rm\u{a0}x", "ssh me@\"h\"; rm x"),
            (
                "echo a@\u{201d}b\u{201d}; rm \u{201c}x\u{201d}",
                "echo a@\"b\"; rm \"x\"",
            ),
            ("@'b'; rm\u{a0}x", "@'b'; rm x"),
            // The text after `--%` is handed on as it is.
            (
                "cmd /c \u{2013}-% a \u{201c} & b | x\u{a0}y",
                "cmd /c --% a \u{201c} & b | x y",
            ),
            ("git a--%\u{a0}b", "git a--% b"),
            // Unclosed strings hold the rest.
            ("echo 'a\u{a0}", "echo 'a\u{a0}"),
            ("echo \"a\u{a0}", "echo \"a\u{a0}"),
        ];
        for (text, expected) in rows {
            assert_eq!(ascii(text), expected, "{text:?}");
        }
    }
}
