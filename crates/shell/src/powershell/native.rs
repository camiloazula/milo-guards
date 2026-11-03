//! How a native program splits the command line PowerShell hands it as
//! written: the text after `--%`, and an `-ArgumentList` string of
//! `Start-Process`.

/// The words a native program named by `key` (see [`crate::unit::key`])
/// reads from `text`. A program splits its own command line: most by the
/// rules of the C runtime (white space between words, double quotes around
/// one, `""` in quotes and `\"` a quote, backslashes before a quote halved);
/// `cmd` runs the text as it is, so its words keep their quotes and joining
/// them gives the command back. `%NAME%` is left as written.
pub(crate) fn words(key: &str, text: &str) -> Vec<String> {
    if key == "cmd" {
        cmd_words(text)
    } else {
        argv(text)
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
            assert_eq!(words(key, text), expected, "{text:?}");
        }
    }
}
