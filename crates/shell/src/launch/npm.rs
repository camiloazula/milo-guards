//! How npm and npx read the options in front of the program that `npm exec`
//! and `npx` run. A value option that is missed turns its value into the
//! program, so the tables below are npm's own: every setting of npm's config
//! definitions (`@npmcli/config`, npm 11) with its shorthands, and the
//! option parsers' rules for them.
//!
//! `npm exec` reads its options with nopt: a setting that is not a boolean
//! takes the next word (unless that looks like an option), a boolean takes
//! a following `true` or `false`, an option that is not known takes nothing,
//! and any option may be spelt as an unambiguous start of its name
//! (`--ed vim` is `--editor vim`). `npx` first runs a pass of its own that
//! only decides where to put a `--` (every option takes the next word unless
//! it is a switch or the word looks like an option, whatever its name), then
//! hands `npm exec` the words before the `--` to read with nopt, so a word
//! that pass took for a value but nopt did not is the program
//! (`npx --foo prog` runs `prog`).

use super::{after_options_by, Word};
use crate::unit::Arg;
use std::collections::VecDeque;

/// The settings of npm's config that are not booleans: each takes a value.
pub(super) const NPM_VALUES: &[&str] = &[
    "_auth",
    "access",
    "allow-directory",
    "allow-file",
    "allow-git",
    "allow-remote",
    "allow-scripts",
    "also",
    "audit-level",
    "auth-type",
    "before",
    "ca",
    "cache",
    "cache-max",
    "cache-min",
    "cafile",
    "call",
    "cert",
    "cidr",
    "cpu",
    "depth",
    "diff",
    "diff-dst-prefix",
    "diff-src-prefix",
    "diff-unified",
    "editor",
    "expect-result-count",
    "expires",
    "fetch-retries",
    "fetch-retry-factor",
    "fetch-retry-maxtimeout",
    "fetch-retry-mintimeout",
    "fetch-timeout",
    "git",
    "globalconfig",
    "heading",
    "https-proxy",
    "include",
    "init-author-email",
    "init-author-name",
    "init-author-url",
    "init-license",
    "init-module",
    "init-type",
    "init-version",
    "init.author.email",
    "init.author.name",
    "init.author.url",
    "init.license",
    "init.module",
    "init.version",
    "install-strategy",
    "key",
    "libc",
    "local-address",
    "location",
    "lockfile-version",
    "loglevel",
    "logs-dir",
    "logs-max",
    "name",
    "maxsockets",
    "message",
    "min-release-age",
    "min-release-age-exclude",
    "node-gyp",
    "node-options",
    "noproxy",
    "omit",
    "only",
    "orgs",
    "os",
    "otp",
    "package",
    "pack-destination",
    "packages",
    "prefix",
    "preid",
    "provenance-file",
    "proxy",
    "registry",
    "replace-registry-host",
    "save-prefix",
    "sbom-format",
    "sbom-type",
    "scope",
    "scopes",
    "packages-and-scopes-permission",
    "orgs-permission",
    "password",
    "token-description",
    "script-shell",
    "searchexclude",
    "searchlimit",
    "searchopts",
    "searchstaleness",
    "shell",
    "tag",
    "tag-version-prefix",
    "umask",
    "user-agent",
    "userconfig",
    "viewer",
    "which",
    "workspace",
];

/// The settings of npm's config that are booleans (`browser` and `color`
/// also take a word, see [`takes_word`]).
const NPM_FLAGS: &[&str] = &[
    "all",
    "allow-same-version",
    "audit",
    "bin-links",
    "browser",
    "bypass-2fa",
    "color",
    "commit-hooks",
    "dangerously-allow-all-scripts",
    "description",
    "dev",
    "diff-ignore-all-space",
    "diff-name-only",
    "diff-no-prefix",
    "diff-text",
    "dry-run",
    "engine-strict",
    "expect-results",
    "force",
    "foreground-scripts",
    "format-package-lock",
    "fund",
    "git-tag-version",
    "global",
    "global-style",
    "if-present",
    "ignore-scripts",
    "include-staged",
    "include-workspace-root",
    "include-attestations",
    "init-private",
    "install-links",
    "json",
    "legacy-bundling",
    "legacy-peer-deps",
    "link",
    "long",
    "offline",
    "omit-lockfile-registry-resolved",
    "optional",
    "package-lock",
    "package-lock-only",
    "parseable",
    "allow-scripts-pending",
    "allow-scripts-pin",
    "prefer-dedupe",
    "prefer-offline",
    "prefer-online",
    "production",
    "progress",
    "provenance",
    "read-only",
    "rebuild-bundle",
    "save",
    "save-bundle",
    "save-dev",
    "save-exact",
    "save-optional",
    "save-peer",
    "save-prod",
    "packages-all",
    "shrinkwrap",
    "sign-git-commit",
    "sign-git-tag",
    "strict-peer-deps",
    "strict-allow-scripts",
    "strict-ssl",
    "timing",
    "unicode",
    "update-notifier",
    "usage",
    "version",
    "versions",
    "workspaces",
    "workspaces-update",
    "yes",
];

/// The shorthands of npm's config: the words each one stands for.
const NPM_SHORTHANDS: &[(&str, &[&str])] = &[
    ("enjoy-by", &["--before"]),
    ("d", &["--loglevel", "info"]),
    ("dd", &["--loglevel", "verbose"]),
    ("ddd", &["--loglevel", "silly"]),
    ("quiet", &["--loglevel", "warn"]),
    ("q", &["--loglevel", "warn"]),
    ("s", &["--loglevel", "silent"]),
    ("silent", &["--loglevel", "silent"]),
    ("verbose", &["--loglevel", "verbose"]),
    ("desc", &["--description"]),
    ("help", &["--usage"]),
    ("local", &["--no-global"]),
    ("n", &["--no-yes"]),
    ("no", &["--no-yes"]),
    ("porcelain", &["--parseable"]),
    ("readonly", &["--read-only"]),
    ("reg", &["--registry"]),
    ("iwr", &["--include-workspace-root"]),
    ("ws", &["--workspaces"]),
    ("a", &["--all"]),
    ("c", &["--call"]),
    ("f", &["--force"]),
    ("g", &["--global"]),
    ("L", &["--location"]),
    ("l", &["--long"]),
    ("m", &["--message"]),
    ("p", &["--parseable"]),
    ("C", &["--prefix"]),
    ("S", &["--save"]),
    ("B", &["--save-bundle"]),
    ("D", &["--save-dev"]),
    ("E", &["--save-exact"]),
    ("O", &["--save-optional"]),
    ("P", &["--save-prod"]),
    ("?", &["--usage"]),
    ("H", &["--usage"]),
    ("h", &["--usage"]),
    ("v", &["--version"]),
    ("w", &["--workspace"]),
    ("y", &["--yes"]),
];

/// The options `npx` takes the next word for, whatever it looks like.
const NPX_VALUES: [&str; 10] = [
    "package",
    "p",
    "cache",
    "userconfig",
    "call",
    "c",
    "shell",
    "npm",
    "node-arg",
    "n",
];

/// The options `npx` has taken out, with their value if they take one.
const NPX_REMOVED: [&str; 6] = [
    "always-spawn",
    "ignore-existing",
    "shell-auto-fallback",
    "npm",
    "node-arg",
    "n",
];

/// What `npx` reads as a switch besides npm's booleans.
const NPX_SWITCHES: [&str; 10] = [
    "always-spawn",
    "ignore-existing",
    "shell-auto-fallback",
    "no-install",
    "quiet",
    "q",
    "version",
    "v",
    "help",
    "h",
];

/// The most steps one word is read for. A shorthand stands for words that
/// are not shorthands, so a word of `n` letters (`-yyyy`) is read as at most
/// two words per letter, one more for a value after `=`, and one to start
/// with: the bound grows with the word, so no word npm can read runs out of
/// steps.
fn max_steps(word: &str) -> usize {
    4 * word.len() + 8
}

/// The settings of npm's config (a start of a name that no other name starts
/// with stands for it).
fn setting(name: &str) -> Option<&'static str> {
    let all = || NPM_VALUES.iter().chain(NPM_FLAGS.iter());
    if let Some(key) = all().find(|key| **key == name) {
        return Some(key);
    }
    let mut starts = all().filter(|key| key.starts_with(name));
    let first = starts.next()?;
    starts.next().is_none().then_some(*first)
}

fn shorthand(name: &str) -> Option<&'static [&'static str]> {
    NPM_SHORTHANDS
        .iter()
        .find(|(short, _)| *short == name)
        .map(|(_, words)| *words)
}

/// The words a name stands for when it is not a setting of its own, as
/// nopt resolves one: a shorthand, single-letter shorthands run together
/// (`-yg`), or an unambiguous start of a shorthand's name.
fn expand(name: &str) -> Option<Vec<&'static str>> {
    if NPM_VALUES
        .iter()
        .chain(NPM_FLAGS.iter())
        .any(|key| *key == name)
    {
        return None;
    }
    if let Some(words) = shorthand(name) {
        return Some(words.to_vec());
    }
    let letters: Option<Vec<&[&str]>> = name
        .chars()
        .map(|letter| {
            let mut buffer = [0; 4];
            let letter: &str = letter.encode_utf8(&mut buffer);
            shorthand(letter).filter(|_| letter.len() == 1)
        })
        .collect();
    if let Some(letters) = letters {
        return Some(letters.concat());
    }
    if setting(name).is_some() {
        return None;
    }
    let mut starts = NPM_SHORTHANDS
        .iter()
        .filter(|(short, _)| short.starts_with(name));
    let (_, words) = starts.next()?;
    starts.next().is_none().then(|| words.to_vec())
}

/// Whether nopt leaves `word` out of the value of an option before it: it
/// looks like another option (`-x`, `--x`) or ends the options (`--`).
fn looks_like_option(word: &str) -> bool {
    let rest = word.trim_start_matches('-');
    let dashes = word.len() - rest.len();
    (dashes == 1 || dashes == 2) && !rest.is_empty() || dashes >= 2 && rest.is_empty()
}

/// Whether the boolean `key` also takes the word after it: `browser` takes
/// any word, `color` only `always`.
fn takes_word(key: &str, word: &str) -> bool {
    match key {
        "browser" => !looks_like_option(word),
        "color" => word == "always",
        _ => false,
    }
}

/// How `npm` (and `npm exec`) read one word that starts with a dash, given
/// the word after it.
pub(super) fn npm_word(text: &str, next: Option<&Arg>) -> Word {
    read_npm(text, next, false, "call").word
}

/// How `npm exec` reads one word `npx` hands it: the same, after the words
/// `npx` has rewritten (`-p` is `--package`, `--shell` is `--script-shell`,
/// `--no-install` is `--yes=false`) or taken out (`--npm x`, `-n x`,
/// `--node-arg x`, `--always-spawn`, `--ignore-existing` and
/// `--shell-auto-fallback`).
fn npx_lead_word(text: &str, next: Option<&Arg>) -> Word {
    read_npm(text, next, true, "call").word
}

/// What reading one word that starts with a dash came to.
struct Read {
    word: Word,
    /// The value of the setting asked for, when the word is (or stands for)
    /// it: for `--call`, `-c`, `-yc`, `--c`, `--call=x`, `-c=x`.
    call: Option<Arg>,
}

/// The script `npm exec` and `npx` run for `--call` (`-c`) among `words`, the
/// options before the program, read as [`read_npm`] reads each one. The
/// option may be anywhere in them, also before `exec` (`npm -c 'x' exec`),
/// at the end of a bundle (`-yc`), spelt `--c`, or given its value after `=`.
pub(super) fn call_script(words: &[Arg], npx: bool) -> Option<Arg> {
    setting_values(words, npx, "call").into_iter().next()
}

/// The folder `npm exec` and `npx` run the program in when `--prefix` (`-C`)
/// is among `words`, the options before the program, read as
/// [`call_script`] reads `--call`: the last one given.
pub(super) fn prefix_folder(words: &[Arg], npx: bool) -> Option<Arg> {
    setting_values(words, npx, "prefix").pop()
}

/// The values the setting `wanted` is given among `words`, in order, each
/// word read as [`read_npm`] reads it.
fn setting_values(words: &[Arg], npx: bool, wanted: &str) -> Vec<Arg> {
    let mut values = Vec::new();
    let mut at = 0;
    while let Some(arg) = words.get(at) {
        let text = arg.known().unwrap_or_default();
        if text == "--" {
            break;
        }
        if text.len() < 2 || !text.starts_with('-') {
            at += 1;
            continue;
        }
        let read = read_npm(text, words.get(at + 1), npx, wanted);
        values.extend(read.call);
        at += if matches!(read.word, Word::Value) {
            2
        } else {
            1
        };
    }
    values
}

/// Read one word `text` that starts with a dash, given the word `next`
/// after it, as npm does (as `npx` hands it when `npx`), keeping the value
/// of the setting `wanted` when the word gives it one.
fn read_npm(text: &str, next: Option<&Arg>, npx: bool, wanted: &str) -> Read {
    let mut queue: VecDeque<String> = VecDeque::from([text.to_string()]);
    let mut used = false;
    let mut call = None;
    let done = |used: bool, call| Read {
        word: if used { Word::Value } else { Word::Flag },
        call,
    };
    let operand = |call| Read {
        word: Word::Operand,
        call,
    };
    for _ in 0..max_steps(text) {
        let Some(word) = queue.pop_front() else {
            return done(used, call);
        };
        let (option, attached) = match word.split_once('=') {
            Some((option, value)) => (option.to_string(), Some(value.to_string())),
            None => (word, None),
        };
        // A word that is no option: a value nothing took.
        if option.len() < 2 || !option.starts_with('-') {
            return operand(call);
        }
        let mut name = option.trim_start_matches('-');
        if npx {
            match name {
                "always-spawn" | "ignore-existing" | "shell-auto-fallback" | "no-install" => {
                    continue;
                }
                // Taken out together with the word after it.
                "npm" | "node-arg" | "n" => {
                    if attached.is_none() && queue.pop_front().is_none() && next.is_some() {
                        used = true;
                    }
                    continue;
                }
                "p" => name = "package",
                "shell" => name = "script-shell",
                _ => {}
            }
        }
        // A value written after `=` stands where the next word would.
        if let Some(value) = &attached {
            queue.push_front(value.clone());
        }
        if let Some(words) = expand(name) {
            for word in words.iter().rev() {
                queue.push_front((*word).to_string());
            }
            continue;
        }
        let mut negated = false;
        while name
            .get(..3)
            .is_some_and(|start| start.eq_ignore_ascii_case("no-"))
        {
            negated = !negated;
            name = &name[3..];
        }
        let key = setting(name);
        let value_kind = key.is_some_and(|key| NPM_VALUES.contains(&key));
        let boolean =
            negated || (key.is_some() && !value_kind) || (key.is_none() && attached.is_none());
        let after = match queue.front() {
            Some(front) => Some(front.clone()),
            None if used => None,
            None => next.map(|arg| arg.text().to_string()),
        };
        let Some(after) = after else { continue };
        let calls = key == Some("call") && !boolean;
        let takes = if boolean {
            after == "true"
                || after == "false"
                || key.is_some_and(|key| !negated && takes_word(key, &after))
        } else {
            // A value written after `=` is the value, whatever it looks like.
            calls && attached.is_some() || !looks_like_option(&after)
        };
        if takes {
            let value = queue.pop_front();
            if key == Some(wanted) && !boolean {
                call = Some(value.as_ref().map_or_else(
                    || next.cloned().unwrap_or(Arg::Known(String::new())),
                    |value| Arg::Known(value.clone()),
                ));
            }
            if value.is_none() {
                used = true;
            }
        }
    }
    operand(call)
}

/// Where the program of `npx` starts in `args`: the first word `npm exec`
/// leaves unread when `npx` has put its `--` before the word its own pass
/// takes for the program.
pub(super) fn npx_start(args: &[Arg]) -> Option<usize> {
    let end = after_options_by(args, npx_word)?;
    Some(after_options_by(&args[..end], npx_lead_word).unwrap_or(end))
}

/// How `npx`'s own pass reads one word that starts with a dash, given the
/// word after it.
fn npx_word(text: &str, next: Option<&Arg>) -> Word {
    let mut queue: VecDeque<String> = VecDeque::from([text.to_string()]);
    let mut used = false;
    for _ in 0..max_steps(text) {
        let Some(word) = queue.pop_front() else {
            return if used { Word::Value } else { Word::Flag };
        };
        if !word.starts_with('-') {
            return Word::Operand;
        }
        let body = word.trim_start_matches('-');
        let (key, value) = match body.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (body, None),
        };
        if !matches!(key, "p" | "shell" | "no-install") && !NPX_REMOVED.contains(&key) {
            if let Some(words) = shorthand(key) {
                if let Some(value) = value {
                    queue.push_front(value.to_string());
                }
                for word in words.iter().rev() {
                    queue.push_front((*word).to_string());
                }
                continue;
            }
        }
        let switch = NPM_FLAGS.contains(&key) || NPX_SWITCHES.contains(&key);
        if value.is_some() || switch {
            continue;
        }
        let after = match queue.front() {
            Some(front) => Some(front.clone()),
            None if used => None,
            None => next.map(|arg| arg.text().to_string()),
        };
        let Some(after) = after else { continue };
        if (NPX_VALUES.contains(&key) || !after.starts_with('-')) && queue.pop_front().is_none() {
            used = true;
        }
    }
    Word::Operand
}
