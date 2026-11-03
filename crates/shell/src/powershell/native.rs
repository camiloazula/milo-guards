//! How a native program splits the command line PowerShell hands it as
//! written: the text after `--%`, and an `-ArgumentList` string of
//! `Start-Process`.

use crate::unit::Arg;

/// The words a native program named by `key` (see [`crate::unit::key`])
/// reads from `text`, which follows the arguments `before` on its command
/// line. A program splits its own command line: most by the rules of the C
/// runtime (white space between words, double quotes around one, `""` in
/// quotes and `\"` a quote, backslashes before a quote halved); `cmd` runs
/// the text as it is, so its words keep their quotes and joining them gives
/// the command back, once cmd's own rule for the quotes around the command
/// after `/c` is applied (see [`cmd_quotes`]). `%NAME%` is left as written.
pub(crate) fn words(key: &str, before: &[Arg], text: &str) -> Vec<String> {
    if key == "cmd" {
        cmd(before, text)
    } else {
        argv(text)
    }
}

/// Where cmd is on its command line, as it reads its switches.
#[derive(Clone, Copy, PartialEq)]
enum Cmd {
    /// Reading switches; whether `/s` was one.
    Switches(bool),
    /// Right after `/c`, `/k` or `/r` (whether `/s` came before it): the
    /// command starts here.
    Command(bool),
    /// Inside the command.
    Within,
}

impl Cmd {
    /// Where cmd is after the word `word`.
    fn after(self, word: &str) -> Self {
        let lower = word.to_ascii_lowercase();
        match self {
            Self::Switches(strip) if matches!(lower.as_str(), "/c" | "/k" | "/r") => {
                Self::Command(strip)
            }
            // `/c"rd …"`: the command starts in the switch's word.
            Self::Switches(_)
                if ["/c", "/k", "/r"]
                    .iter()
                    .any(|switch| lower.starts_with(switch) && !lower[2..].starts_with(':')) =>
            {
                Self::Within
            }
            Self::Switches(strip) => Self::Switches(strip || lower == "/s"),
            Self::Command(_) | Self::Within => Self::Within,
        }
    }
}

/// `cmd`'s words of `text` after the arguments `before`.
fn cmd(before: &[Arg], text: &str) -> Vec<String> {
    let mut at = before
        .iter()
        .fold(Cmd::Switches(false), |at, arg| at.after(arg.text()));
    let mut words = Vec::new();
    let mut rest = text;
    while let Cmd::Switches(_) = at {
        let start = rest.len() - rest.trim_start().len();
        let end = rest[start..]
            .find(char::is_whitespace)
            .map_or(rest.len(), |end| start + end);
        if start == end {
            return words;
        }
        let word = &rest[start..end];
        let strip = at == Cmd::Switches(true);
        at = at.after(word);
        if at == Cmd::Within {
            // `/c"rd …"`: the rest of the word is the command, which
            // starts with what follows the switch.
            words.push(word[..2].to_string());
            rest = &rest[start + 2..];
            at = Cmd::Command(strip);
            break;
        }
        words.push(word.to_string());
        rest = &rest[end..];
    }
    let line = match at {
        Cmd::Command(strip) => cmd_quotes(rest, strip),
        _ => rest.to_string(),
    };
    words.extend(cmd_words(&line));
    words
}

/// The command after cmd's `/c`, `/k` or `/r` as cmd runs it. When it starts
/// with a quote, cmd keeps the quotes only when no `/s` came before, there
/// are just two of them, none of `&<>()@^|` and some white space is between
/// them, and what is between them is an executable file; otherwise it drops
/// the first and the last quote. Whether a file exists is not known here, so
/// when everything else holds, both readings are given, joined by `&`, and
/// each is judged.
fn cmd_quotes(rest: &str, strip: bool) -> String {
    let start = rest.len() - rest.trim_start().len();
    if !rest[start..].starts_with('"') {
        return rest.to_string();
    }
    let last = rest.rfind('"').unwrap_or(start);
    let mut dropped = String::with_capacity(rest.len());
    dropped.push_str(&rest[..start]);
    if last > start {
        dropped.push_str(&rest[start + 1..last]);
        dropped.push_str(&rest[last + 1..]);
    } else {
        dropped.push_str(&rest[start + 1..]);
    }
    let between = rest.get(start + 1..last).unwrap_or_default();
    let keeps = !strip
        && rest.matches('"').count() == 2
        && !between.contains(['&', '<', '>', '(', ')', '@', '^', '|'])
        && between.contains(char::is_whitespace);
    if keeps {
        format!("{dropped} & {rest}")
    } else {
        dropped
    }
}

/// The C runtime's split of a command line.
fn argv(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quoted = false;
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        match c {
            '\\' => {
                let run = chars[at..].iter().take_while(|&&c| c == '\\').count();
                at += run;
                in_word = true;
                if chars.get(at) == Some(&'"') {
                    word.extend(std::iter::repeat_n('\\', run / 2));
                    if run % 2 == 1 {
                        word.push('"');
                        at += 1;
                    }
                } else {
                    word.extend(std::iter::repeat_n('\\', run));
                }
            }
            '"' => {
                in_word = true;
                if quoted && chars.get(at + 1) == Some(&'"') {
                    word.push('"');
                    at += 2;
                } else {
                    quoted = !quoted;
                    at += 1;
                }
            }
            ' ' | '\t' | '\n' | '\r' if !quoted => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
                at += 1;
            }
            _ => {
                word.push(c);
                in_word = true;
                at += 1;
            }
        }
    }
    if in_word {
        words.push(word);
    }
    words
}

/// `cmd`'s words: white space outside double quotes splits them, and each
/// keeps its quotes.
fn cmd_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    for c in text.chars() {
        if c == '"' {
            quoted = !quoted;
        }
        if c.is_ascii_whitespace() && !quoted {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c);
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::words;
    use crate::unit::Arg;

    #[test]
    fn splits_as_the_program_does() {
        let rows: [(&str, &str, &[&str]); 9] = [
            ("git", " clean  -fdx ", &["clean", "-fdx"]),
            ("psql", "-c \"DROP TABLE t\"", &["-c", "DROP TABLE t"]),
            ("x", "a\"b c\"d", &["ab cd"]),
            ("x", "\"a\"\"b\"", &["a\"b"]),
            ("x", "a\\\"b", &["a\"b"]),
            ("x", "a\\\\\"b c\"", &["a\\b c"]),
            ("x", "C:\\a\\b \"\"", &["C:\\a\\b", ""]),
            ("x", "%USERPROFILE%\\x", &["%USERPROFILE%\\x"]),
            (
                "cmd",
                "/c rd /s \"C:\\a b\"",
                &["/c", "rd", "/s", "\"C:\\a b\""],
            ),
        ];
        for (key, text, expected) in rows {
            assert_eq!(words(key, &[], text), expected, "{text:?}");
        }
    }

    #[test]
    fn drops_the_quotes_around_cmds_command() {
        let c = [Arg::Known("/C".to_string())];
        let rows: [(&[Arg], &str, &[&str]); 10] = [
            // Both readings, when what is between may be a program.
            (
                &[],
                "/c \"rd /s C:\\x\"",
                &["/c", "rd", "/s", "C:\\x", "&", "\"rd /s C:\\x\""],
            ),
            (&c, " \"rd /s x\"", &["rd", "/s", "x", "&", "\"rd /s x\""]),
            // Only the dropped one, when `/s` came first, there are more
            // quotes, or a special character is between them.
            (&[], "/s /c \"rd x\"", &["/s", "/c", "rd", "x"]),
            (&[], "/c \"rd \"a b\"\"", &["/c", "rd", "\"a b\""]),
            (&[], "/c \"a&b\"", &["/c", "a&b"]),
            (
                &[],
                "/c\"rd x\" y",
                &["/c", "rd", "x", "y", "&", "\"rd x\"", "y"],
            ),
            (&[], "/s /c\"rd x\" y", &["/s", "/c", "rd", "x", "y"]),
            // No quote first, or the command is under way.
            (&[], "/c rd \"a b\"", &["/c", "rd", "\"a b\""]),
            (
                &[Arg::Known("/c".to_string()), Arg::Known("rd".to_string())],
                "\"a b\"",
                &["\"a b\""],
            ),
            (&[], "/d /k \"x\"", &["/d", "/k", "x"]),
        ];
        for (before, text, expected) in rows {
            assert_eq!(words("cmd", before, text), expected, "{text:?}");
        }
    }
}
