//! Shells and interpreters given a script, inline code, or their input:
//! which is which, and the perl in-place edits read like `sed -i`.

use super::{is_stdin, Launch};
use crate::unit::{Arg, Reads};
use crate::Shell;

/// The POSIX shells, which run a script with `-c` or read one from their
/// input.
pub(crate) const SHELLS: [&str; 11] = [
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "fish", "csh", "tcsh",
];

/// Language interpreters that read code from their input when given no
/// script.
pub(crate) const INTERPRETERS: [&str; 9] = [
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "lua",
];

/// A POSIX shell: `-c` runs its first operand; a script file is its own
/// business; with neither, it reads commands from its input.
pub(super) fn shell(args: &[Arg]) -> Launch {
    let mut command = false;
    let mut stdin = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            return Launch::Script(Shell::Posix, arg.clone());
        };
        match text {
            "--" => break,
            "-o" | "+o" | "-O" | "+O" | "--rcfile" | "--init-file" => {
                iter.next();
            }
            "-" => {
                stdin = true;
                break;
            }
            text if text.starts_with("--") => {}
            text if (text.starts_with('-') || text.starts_with('+')) && text.len() > 1 => {
                if text[1..].contains('c') {
                    command = true;
                }
                if text[1..].contains('s') {
                    stdin = true;
                }
            }
            _ => {
                return if command {
                    Launch::Script(Shell::Posix, arg.clone())
                } else if stdin || is_stdin(text) {
                    Launch::Reads(Reads::Shell)
                } else {
                    Launch::Itself
                };
            }
        }
    }
    match (command, iter.next()) {
        (true, Some(script)) => Launch::Script(Shell::Posix, script.clone()),
        (true, None) => Launch::Itself,
        (false, Some(Arg::Known(script))) if !stdin && !is_stdin(script) => Launch::Itself,
        (false, Some(script @ (Arg::Unknown(_) | Arg::Input))) if !stdin => {
            Launch::Script(Shell::Posix, script.clone())
        }
        _ => Launch::Reads(Reads::Shell),
    }
}

/// An interpreter runs code the guard does not read when it is given code inline
/// or reads it from its input; a script file or a module is its own
/// business. The flags that carry inline code differ per interpreter, so a
/// bundle (`-le`, `-Sc`) is read letter by letter: `-E` is code for perl
/// but an encoding for ruby.
pub(super) fn interpreter(key: &str, args: &[Arg]) -> Launch {
    let (short, long): (&[char], &[&str]) = if key.starts_with("python") {
        (&['c'], &[])
    } else {
        match key {
            "perl" => (&['e', 'E'], &[]),
            "ruby" => (&['e'], &["--eval"]),
            "node" | "nodejs" => (&['e', 'p'], &["--eval", "--print"]),
            "php" => (&['r', 'R', 'F'], &[]),
            "lua" => (&['e'], &[]),
            _ => (&['c', 'e'], &["--eval", "--print"]),
        }
    };
    let code = args.iter().any(|arg| {
        arg.known()
            .is_some_and(|text| match text.strip_prefix('-') {
                Some(bundle) if !bundle.is_empty() && !bundle.starts_with('-') => {
                    bundle.chars().any(|letter| short.contains(&letter))
                }
                _ => long.contains(&text),
            })
    });
    let file = args
        .iter()
        .any(|arg| !arg.known().is_some_and(|text| text.starts_with('-')));
    let stdin = args.iter().any(|arg| arg.known().is_some_and(is_stdin));
    // `perl -pi -e 's/a/b/' FILE` is an in-place edit like `sed -i`: its
    // files are judged as writes instead.
    if key == "perl" && perl_edits(args).is_some() {
        return Launch::Itself;
    }
    if code || stdin || !file {
        Launch::Reads(Reads::Interpreter)
    } else {
        Launch::Itself
    }
}

/// The files `perl -pi -e CODE FILE…` edits in place, when every piece of
/// `CODE` is a plain substitution or transliteration (`s/a/b/g`, `tr/a-z/A-Z/`)
/// that runs nothing; `None` for any other perl line.
pub(crate) fn perl_edits(args: &[Arg]) -> Option<Vec<&Arg>> {
    let mut in_place = false;
    let mut each_line = false;
    let mut codes = Vec::new();
    let mut files = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            files.push(arg);
            continue;
        };
        if text == "-e" || text == "-E" {
            codes.push(iter.next()?.known()?);
        } else if text == "-I" || text == "-M" {
            iter.next();
        } else if let Some(bundle) = text.strip_prefix('-').filter(|b| !b.starts_with('-')) {
            if let Some(at) = bundle.find('i') {
                in_place = true;
                // `-i` takes the rest of the bundle as a backup suffix, so a
                // later `e` there is not `-e`.
                each_line |= bundle[..at].contains(['p', 'n']);
                continue;
            }
            each_line |= bundle.contains(['p', 'n']);
            if bundle.ends_with(['e', 'E']) {
                codes.push(iter.next()?.known()?);
            } else if bundle.contains(['e', 'E']) {
                return None;
            }
        } else {
            files.push(arg);
        }
    }
    let edits = in_place
        && each_line
        && !codes.is_empty()
        && codes.iter().all(|code| perl_code_edits(code));
    edits.then_some(files)
}

/// Whether perl code is only substitutions and transliterations whose
/// replacement runs nothing: no `/e` flag, no `@{[…]}` or `${…}`
/// interpolation, no backticks, no `system`/`exec`/`qx`.
fn perl_code_edits(code: &str) -> bool {
    if code.contains(['`'])
        || code.contains("@{")
        || code.contains("${")
        || ["system", "exec", "qx", "open", "unlink", "eval", "require"]
            .iter()
            .any(|word| code.contains(word))
    {
        return false;
    }
    code.split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
        .all(perl_substitution)
}

/// One `s/…/…/flags`, `tr/…/…/flags` or `y/…/…/flags` with a plain
/// delimiter and no `e` (evaluate) flag.
fn perl_substitution(statement: &str) -> bool {
    let rest = statement
        .strip_prefix("tr")
        .or_else(|| statement.strip_prefix('y'))
        .or_else(|| statement.strip_prefix('s'));
    let Some(rest) = rest else {
        return false;
    };
    let Some(delimiter) = rest.chars().next() else {
        return false;
    };
    if delimiter.is_alphanumeric() || delimiter.is_whitespace() || "{[(<\\".contains(delimiter) {
        return false;
    }
    let mut fields = 0;
    let mut escaped = false;
    let mut flags = None;
    for (at, c) in rest.char_indices().skip(1) {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == delimiter {
            fields += 1;
            if fields == 2 {
                flags = rest.get(at + c.len_utf8()..);
                break;
            }
        }
    }
    flags.is_some_and(|flags| flags.chars().all(|flag| "gimsxrdcaulnpo".contains(flag)))
}
