//! git's own options, read before its subcommand, and the command
//! `git submodule foreach` runs in each submodule.

use super::{Launch, Word};
use crate::unit::Arg;
use crate::Shell;

/// What git's own options say, before its subcommand.
pub(crate) struct Global<'a> {
    /// Where the subcommand is in the arguments.
    pub(crate) at: usize,
    /// The folder `-C` moves git to.
    pub(crate) repository: Option<&'a Arg>,
    /// The `-c key=value` settings it is given.
    pub(crate) configs: Vec<&'a str>,
    /// The settings whose value is only known when it runs: a `-c` value
    /// not known in full, and every `--config-env`, whose value git takes
    /// from the environment.
    pub(crate) unread: Vec<Unread<'a>>,
}

/// A setting of git's own options whose value is only known when it runs.
pub(crate) struct Unread<'a> {
    /// The word that holds `key=value` (`-c`'s) or `key=VARIABLE`
    /// (`--config-env`'s).
    pub(crate) arg: &'a Arg,
    /// What is written before the setting in that word: `--config-env=`
    /// when it is joined to its option, or nothing.
    pub(crate) prefix: &'static str,
}

/// Read git's own options, up to its subcommand. They take no abbreviation.
/// A long option written with its value joined to it, where the value is
/// only known when it runs (`--git-dir="$D"`, `--work-tree=$W`), is one of
/// them all the same: the subcommand comes after it.
pub(crate) fn global(args: &[Arg]) -> Global<'_> {
    let mut at = 0;
    let mut repository = None;
    let mut configs = Vec::new();
    let mut unread = Vec::new();
    while let Some(arg) = args.get(at) {
        let Some(text) = arg.known() else {
            if joined_option(arg.text()) {
                if arg.text().starts_with(CONFIG_ENV) {
                    unread.push(Unread {
                        arg,
                        prefix: CONFIG_ENV,
                    });
                }
                at += 1;
                continue;
            }
            break;
        };
        match text {
            "-C" => {
                repository = args.get(at + 1);
                at += 2;
            }
            "-c" => {
                if let Some(value) = args.get(at + 1) {
                    match value.known() {
                        Some(config) => configs.push(config),
                        None => unread.push(Unread {
                            arg: value,
                            prefix: "",
                        }),
                    }
                }
                at += 2;
            }
            "--config-env" => {
                unread.extend(args.get(at + 1).map(|arg| Unread { arg, prefix: "" }));
                at += 2;
            }
            text if text.starts_with(CONFIG_ENV) => {
                unread.push(Unread {
                    arg,
                    prefix: CONFIG_ENV,
                });
                at += 1;
            }
            "--git-dir" | "--work-tree" | "--namespace" | "--super-prefix" | "--attr-source" => {
                at += 2;
            }
            text if text.starts_with('-') => at += 1,
            _ => break,
        }
    }
    Global {
        at,
        repository,
        configs,
        unread,
    }
}

/// git's `--config-env` joined to its value.
const CONFIG_ENV: &str = "--config-env=";

/// Whether `text`, a word as written, is a long option whose name is
/// written out and whose value is joined to it with `=`: `--git-dir="$D"`.
/// A name that is itself only known when it runs (`--$o`) may be one that
/// takes the next word as its value, so it is not one.
fn joined_option(text: &str) -> bool {
    text.strip_prefix("--")
        .and_then(|rest| rest.split_once('='))
        .is_some_and(|(name, _)| {
            name.starts_with(|c: char| c.is_ascii_alphabetic())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Whether a git long option `--name` or `--name=value`, as written, is
/// `long`: git takes any prefix of a long option that names only one, and
/// refuses a prefix that names several, so a prefix of `long` is `long`
/// whenever the line runs at all.
pub(crate) fn is_long(text: &str, long: &str) -> bool {
    text.strip_prefix("--")
        .map(|name| name.split_once('=').map_or(name, |(name, _)| name))
        .is_some_and(|name| !name.is_empty() && long.starts_with(name))
}

/// Whether a git subcommand is `submodule`, or `submodule--helper`, the
/// helper it calls, which runs the same commands (`foreach`, `update`,
/// `deinit`) when called directly.
pub(crate) fn is_submodule(sub: &str) -> bool {
    matches!(sub, "submodule" | "submodule--helper")
}

/// `git submodule foreach`: git runs its command in each submodule, with a
/// shell. One argument is a shell line (`git submodule foreach 'rm -rf ~'`);
/// with several, the first is put in a shell line as written and the others
/// are handed to it as words (`sh -c 'FIRST "$@"' FIRST REST…`), so the
/// line read is the first as it is and each other quoted. Its options
/// (`--recursive`, `--quiet`) come before the command; any other word that
/// starts with a dash is taken as one too, so what follows is still read.
pub(super) fn launch(args: &[Arg]) -> Launch {
    let global = global(args);
    if !args
        .get(global.at)
        .and_then(Arg::known)
        .is_some_and(is_submodule)
    {
        return Launch::Itself;
    }
    let rest = args.get(global.at + 1..).unwrap_or_default();
    // `git submodule --quiet foreach`: the options of `submodule` itself.
    let Some(foreach) = rest
        .iter()
        .position(|arg| arg.known().is_none_or(|text| !text.starts_with('-')))
    else {
        return Launch::Itself;
    };
    if rest.get(foreach).and_then(Arg::known) != Some("foreach") {
        return Launch::Itself;
    }
    let after = rest.get(foreach + 1..).unwrap_or_default();
    let Some(start) = super::after_options_by(after, |_, _| Word::Flag) else {
        return Launch::Itself;
    };
    let command = after.get(start..).unwrap_or_default();
    match command {
        [] => Launch::Itself,
        [line] => Launch::Elsewhere(Shell::Posix, line.clone()),
        [first, words @ ..] => {
            let mut line = first.text().to_string();
            for word in words {
                line.push(' ');
                match word {
                    Arg::Known(text) => line.push_str(&quoted(text)),
                    other => line.push_str(other.text()),
                }
            }
            let line = if first.known().is_some() {
                Arg::Known(line)
            } else {
                Arg::Unknown(line)
            };
            Launch::Elsewhere(Shell::Posix, line)
        }
    }
}

/// `text` in single quotes, as one word of a POSIX shell line.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prefix_of_a_long_option_is_that_option() {
        assert!(is_long("--f", "force"));
        assert!(is_long("--force", "force"));
        assert!(is_long("--pr=now", "prune"));
        assert!(!is_long("--", "force"));
        assert!(!is_long("--=x", "force"));
        assert!(!is_long("--forced", "force"));
        assert!(!is_long("-f", "force"));
        assert!(!is_long("--no-force", "force"));
    }

    #[test]
    fn a_long_option_with_a_joined_value_is_one_of_gits_own() {
        assert!(joined_option("--git-dir=\"$D\""));
        assert!(joined_option("--work-tree=$W"));
        assert!(!joined_option("--$o"));
        assert!(!joined_option("--$o=x"));
        assert!(!joined_option("$CMD"));
        assert!(!joined_option("-c$x"));
        let args = [
            Arg::Unknown("--git-dir=\"$D\"".to_string()),
            Arg::Known("clean".to_string()),
        ];
        assert_eq!(global(&args).at, 1);
    }

    #[test]
    fn the_submodule_helper_is_a_submodule() {
        assert!(is_submodule("submodule"));
        assert!(is_submodule("submodule--helper"));
        assert!(!is_submodule("submodules"));
    }

    #[test]
    fn a_word_is_quoted_whatever_it_holds() {
        assert_eq!(quoted("a b"), "'a b'");
        assert_eq!(quoted("it's"), r"'it'\''s'");
    }
}
