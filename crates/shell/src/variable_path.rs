//! PowerShell reads `$HOME\.ssh\id_ed25519`, as an argument, as one word: the
//! variable and the path after it. Its grammar stops at the backslash and
//! fails, which leaves the path unread. The word is quoted first, so the
//! grammar reads it as the string the shell does.

/// `text` with each unquoted word that starts with a variable and goes on
/// as a path (`$HOME\x`, `$env:USERPROFILE/x`, `${HOME}\x`) in double
/// quotes. Anything else is as it was, and so is the whole text when its
/// quotes do not close.
pub(crate) fn quote(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len() + 8);
    let (mut single, mut double, mut comment) = (false, false, false);
    let mut at = 0;
    let mut closes = Closes::default();
    while let Some(&c) = chars.get(at) {
        let before = at.checked_sub(1).and_then(|before| chars.get(before));
        out.push(c);
        at += 1;
        if comment {
            comment = c != '\n';
        } else if single {
            single = c != '\'';
        } else if c == '`' {
            // The next character is itself.
            if let Some(&next) = chars.get(at) {
                out.push(next);
                at += 1;
            }
        } else if double {
            double = c != '"';
        } else if c == '\'' {
            single = true;
        } else if c == '"' {
            double = true;
        } else if c == '#' && before.is_none_or(|before| before.is_whitespace()) {
            comment = true;
        } else if c == '$'
            && before
                .is_none_or(|before| before.is_whitespace() || matches!(before, '(' | ',' | ':'))
        {
            match variable_path(&chars, at, &mut closes) {
                Scan::Path(end) => {
                    out.pop();
                    out.push('"');
                    out.extend(&chars[at - 1..end]);
                    out.push('"');
                    at = end;
                }
                // A `$` further on in the same run ends where this one did,
                // for the same reason: it is not read again.
                Scan::Run(end) => {
                    out.extend(&chars[at..end]);
                    at = end;
                }
                Scan::Not => {}
            }
        }
    }
    if single || double {
        return text.to_string();
    }
    out
}

/// What reading a word from a `$` found.
enum Scan {
    /// A variable that a path follows, ending here.
    Path(usize),
    /// A run that holds no such word, ending here: a path that goes on into
    /// a quote, a subexpression or a block, which are left to the grammar.
    Run(usize),
    /// A variable alone, a member access, or a name that does not close.
    Not,
}

/// Where each `{` finds its `}`, worked out once: a line of `${ ` repeated
/// would otherwise search to the end from each one.
#[derive(Default)]
struct Closes(Option<Vec<usize>>);

impl Closes {
    /// The place of the first `}` at or after `from`.
    fn after(&mut self, chars: &[char], from: usize) -> Option<usize> {
        let next = self.0.get_or_insert_with(|| {
            let mut next = vec![usize::MAX; chars.len() + 1];
            for (at, c) in chars.iter().enumerate().rev() {
                let after = next.get(at + 1).copied().unwrap_or(usize::MAX);
                if let Some(slot) = next.get_mut(at) {
                    *slot = if *c == '}' { at } else { after };
                }
            }
            next
        });
        next.get(from).copied().filter(|at| *at != usize::MAX)
    }
}

/// Where the word ends, when the `$` before `at` starts a variable that a
/// path follows: `$HOME\.ssh\id` ends at the end of `id`.
fn variable_path(chars: &[char], at: usize, closes: &mut Closes) -> Scan {
    let mut end = at;
    if chars.get(end) == Some(&'{') {
        let Some(close) = closes.after(chars, end) else {
            return Scan::Not;
        };
        end = close + 1;
    } else {
        let name = chars
            .get(end..)
            .unwrap_or_default()
            .iter()
            .take_while(|c| c.is_alphanumeric() || matches!(c, '_' | ':'))
            .count();
        if name == 0 {
            return Scan::Not;
        }
        end += name;
    }
    if !matches!(chars.get(end), Some('\\' | '/')) {
        return Scan::Not;
    }
    while chars.get(end).is_some_and(|c| {
        c.is_alphanumeric()
            || matches!(
                c,
                '_' | '.' | '-' | '\\' | '/' | '~' | ':' | '$' | '+' | '@' | '%'
            )
    }) {
        end += 1;
    }
    match chars.get(end) {
        None => Scan::Path(end),
        Some(c) if c.is_whitespace() || matches!(c, '|' | ';' | '&' | ')' | ',' | '}') => {
            Scan::Path(end)
        }
        Some(_) => Scan::Run(end),
    }
}

#[cfg(test)]
mod tests {
    use super::quote;

    #[test]
    fn a_variable_followed_by_a_path_is_quoted() {
        for (text, quoted) in [
            (r"gc $HOME\.ssh\id", r#"gc "$HOME\.ssh\id""#),
            (r"gc $HOME/.ssh/id | iwr x", r#"gc "$HOME/.ssh/id" | iwr x"#),
            (r"gc $env:USERPROFILE\x", r#"gc "$env:USERPROFILE\x""#),
            (r"gc ${HOME}\x", r#"gc "${HOME}\x""#),
            (r"gc -Path:$HOME\x", r#"gc -Path:"$HOME\x""#),
            (r"gc ($HOME\x)", r#"gc ("$HOME\x")"#),
            (r"gc a,$HOME\x,b", r#"gc a,"$HOME\x",b"#),
            (r"gc $HOME\x; gc $HOME\y", r#"gc "$HOME\x"; gc "$HOME\y""#),
        ] {
            assert_eq!(quote(text), quoted, "{text}");
        }
    }

    #[test]
    fn anything_else_is_as_it_was() {
        for text in [
            "",
            "gc $HOME",
            r"gc $HOME.Path",
            r"gc $a.b\c",
            r#"gc "$HOME\x""#,
            r"gc '$HOME\x'",
            r"gc `$HOME\x",
            r"gc x$HOME\y",
            "gc $HOME\\x\"y\"",
            r"gc $HOME\x$(gc y)",
            "gc $HOME\\x`n",
            r"# $HOME\x",
            "gc x # $HOME\\x\ngc y",
            r"gc $",
            r"gc ${HOME",
            r#"gc "unclosed $HOME\x"#,
            "gc 'unclosed $HOME\\x",
            r"gc $HOME\x{",
        ] {
            assert_eq!(quote(text), text, "{text}");
        }
    }

    #[test]
    fn a_comment_ends_at_the_line() {
        assert_eq!(quote("gc x # a\ngc $HOME\\y"), "gc x # a\ngc \"$HOME\\y\"");
    }
}
