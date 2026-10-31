//! The rule about secrets leaving the machine: a key, a credential, an
//! `.env` file or the environment sent to another machine, by an upload, a
//! copy to a remote destination, or a pipeline that ends in a program that
//! sends its input.
//!
//! A secret is a file the path model calls sensitive (`~/.ssh`, `~/.aws`),
//! an `.env` file anywhere, or the whole environment. Reading one on this
//! machine is nothing; only sending it is.

use std::collections::{HashMap, HashSet};

use milo_guards_core::spelling::glob;
use milo_guards_core::Flavour;

use super::files::remote;
use super::Checker;
use crate::path::Place;
use crate::unit::{has_flag, operands, Arg, Stage, Unit};
use crate::{Rule, Shell};

const ENVIRONMENT: &str = "your environment variables";
const DOTENV: &str = "an .env file";
const HOME: &str = "your home directory";
/// What core calls the repository's own history: sensitive to lose, not a
/// secret to send.
const HISTORY: &str = "the repository's history";

/// The ends of an `.env` file's name that make it a template, committed
/// with the code: `.env.example`.
const TEMPLATES: [&str; 4] = ["example", "sample", "template", "dist"];

/// Programs that send what they are given to another machine, so a secret
/// in their arguments, in a substitution they run or in a variable they
/// read has left.
const NETWORK: &[&str] = &[
    "curl",
    "wget",
    "fetch",
    "http",
    "https",
    "xh",
    "aria2c",
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "telnet",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "rclone",
    "sshpass",
    "mosh",
    "mail",
    "mailx",
    "sendmail",
    "msmtp",
    "mutt",
];

/// Programs that send their input as they get it.
const SINKS: &[&str] = &[
    "nc",
    "ncat",
    "netcat",
    "socat",
    "telnet",
    "ssh",
    "sshpass",
    "mosh",
    "mail",
    "mailx",
    "sendmail",
    "msmtp",
    "mutt",
    "invoke-webrequest",
    "invoke-restmethod",
];

/// Programs that name a key or a certificate they use to log in, which they
/// do not send: `ssh -i ~/.ssh/id_ed25519 host`.
const KEY_USERS: &[&str] = &[
    "ssh", "scp", "sftp", "rsync", "curl", "wget", "http", "https", "xh", "git", "sshpass", "mosh",
    "rclone",
];

/// The options of those programs whose value is such a file.
const LOGIN_OPTIONS: &[&str] = &[
    "-i",
    "-F",
    "-o",
    "-E",
    "-K",
    "--key",
    "--cert",
    "--cacert",
    "--identity-file",
    "--netrc-file",
    "--config",
];

/// `curl`'s short options that take a value and send none of it from a file.
const CURL_VALUES: &str = "AbcCDeEKmoPQrtuUwxXyYz";

/// The options that take a value, for each program that copies to another
/// machine, so a value is not read as a file to send.
const SCP_VALUES: [&str; 9] = ["-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-S"];
const SFTP_VALUES: [&str; 13] = [
    "-B", "-b", "-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-R", "-S", "-s",
];
const RSYNC_VALUES: [&str; 25] = [
    "-e",
    "--rsh",
    "--exclude",
    "--include",
    "--filter",
    "-f",
    "--files-from",
    "--exclude-from",
    "--include-from",
    "--log-file",
    "--password-file",
    "--port",
    "--backup-dir",
    "--suffix",
    "-T",
    "--temp-dir",
    "--chmod",
    "--chown",
    "--compare-dest",
    "--copy-dest",
    "--link-dest",
    "--partial-dir",
    "--timeout",
    "--bwlimit",
    "-M",
];
const CLOUD_VALUES: [&str; 31] = [
    "--exclude",
    "--include",
    "--filter",
    "--exclude-from",
    "--include-from",
    "--filter-from",
    "--files-from",
    "--config",
    "--profile",
    "--region",
    "--endpoint-url",
    "--acl",
    "--storage-class",
    "--sse",
    "--sse-kms-key-id",
    "--cache-control",
    "--content-type",
    "--content-encoding",
    "--metadata",
    "--bwlimit",
    "--transfers",
    "--checkers",
    "--retries",
    "--log-file",
    "--log-level",
    "--backup-dir",
    "--suffix",
    "--max-age",
    "--min-age",
    "--max-size",
    "--min-size",
];
const GSUTIL_VALUES: [&str; 3] = ["-h", "-o", "-x"];

/// A secret found, as a reason says it and as the line wrote it.
#[derive(Debug, Clone)]
struct Hit {
    words: &'static str,
    target: String,
}

/// Where the line reads secrets, and where what it reads goes, by unit
/// (an index in the split).
#[derive(Debug, Default)]
pub(super) struct Flow {
    /// A secret the unit itself reads: an argument that names one, the
    /// environment, a variable that holds one, a file redirected onto it.
    own: Vec<Option<Hit>>,
    /// A secret read for the unit: in a substitution, a here-document or a
    /// variable among its arguments.
    fed: Vec<Option<Hit>>,
    /// A secret redirected onto its input (`nc host 1 < ~/.ssh/id`).
    stdin: Vec<Option<Hit>>,
    /// Units whose output a redirect sends to the network
    /// (`> /dev/tcp/host/1`).
    to_network: HashSet<usize>,
    /// Where each unit stands in a pipeline: its own stage, or the one of the
    /// command whose script, substitution or `-exec` it runs for.
    stage_of: Vec<Option<Stage>>,
    /// For each pipeline, the first stage that reads a secret.
    stage: HashMap<usize, (usize, Hit)>,
}

impl Flow {
    fn own(&self, at: usize) -> Option<&Hit> {
        self.own.get(at).and_then(Option::as_ref)
    }

    fn fed(&self, at: usize) -> Option<&Hit> {
        self.fed.get(at).and_then(Option::as_ref)
    }

    fn stdin(&self, at: usize) -> Option<&Hit> {
        self.stdin.get(at).and_then(Option::as_ref)
    }

    fn stage_of(&self, at: usize) -> Option<Stage> {
        self.stage_of.get(at).copied().flatten()
    }
}

impl Checker<'_> {
    /// Follow every secret the line reads: which units read one, and which
    /// are handed one.
    pub(super) fn trace(&self) -> Flow {
        let units = &self.split.units;
        let mut flow = Flow {
            own: vec![None; units.len()],
            fed: vec![None; units.len()],
            stdin: vec![None; units.len()],
            stage_of: units.iter().map(|unit| unit.stage).collect(),
            ..Flow::default()
        };
        // Outer commands were noted last, and hand their place down first.
        for nested in self.split.nested.iter().rev() {
            let outer = nested
                .command
                .clone()
                .find_map(|at| flow.stage_of.get(at).copied().flatten());
            if let Some(outer) = outer {
                for at in nested.inside.clone() {
                    if let Some(slot) = flow.stage_of.get_mut(at).filter(|slot| slot.is_none()) {
                        *slot = Some(outer);
                    }
                }
            }
        }
        for redirect in &self.split.redirects {
            for at in redirect.units.clone() {
                let Some(unit) = units.get(at) else { continue };
                if redirect.input {
                    let hit = self.secret(unit, &redirect.target, false);
                    if let Some(slot) = flow.stdin.get_mut(at).filter(|_| hit.is_some()) {
                        *slot = hit;
                    }
                } else if redirect.target.known().is_some_and(network_device) {
                    flow.to_network.insert(at);
                }
            }
        }
        for (at, unit) in units.iter().enumerate() {
            let own = self.secret_read(unit, flow.stdin(at));
            if let Some(slot) = flow.own.get_mut(at) {
                *slot = own;
            }
        }
        // A variable set from what a secret-reading command prints holds
        // the secret, and so does one set from that.
        let mut held: Vec<(String, Hit)> = Vec::new();
        loop {
            let before = held.len();
            for assigned in &self.split.assigned {
                if held.iter().any(|(name, _)| *name == assigned.name) {
                    continue;
                }
                let hit = assigned.inside.clone().find_map(|at| {
                    flow.own(at)
                        .cloned()
                        .or_else(|| units.get(at).and_then(|unit| mentions(unit, &held)))
                });
                if let Some(hit) = hit {
                    held.push((assigned.name.clone(), hit));
                }
            }
            if held.len() == before {
                break;
            }
        }
        for (at, unit) in units.iter().enumerate() {
            if let Some(hit) = mentions(unit, &held) {
                if let Some(slot) = flow.fed.get_mut(at) {
                    *slot = Some(hit.clone());
                }
                if let Some(slot) = flow.own.get_mut(at).filter(|slot| slot.is_none()) {
                    *slot = Some(hit);
                }
            }
        }
        for nested in &self.split.nested {
            let hit = nested.inside.clone().find_map(|at| flow.own(at).cloned());
            if let Some(hit) = hit {
                for at in nested.command.clone() {
                    if let Some(slot) = flow.fed.get_mut(at).filter(|slot| slot.is_none()) {
                        *slot = Some(hit.clone());
                    }
                }
            }
        }
        for at in 0..units.len() {
            let (Some(stage), Some(hit)) = (flow.stage_of(at), flow.own(at).or(flow.fed(at)))
            else {
                continue;
            };
            let first = flow
                .stage
                .get(&stage.pipeline)
                .is_none_or(|(first, _)| stage.index < *first);
            if first {
                let hit = hit.clone();
                flow.stage.insert(stage.pipeline, (stage.index, hit));
            }
        }
        flow
    }

    /// A secret the unit itself reads: the environment, a file it is given
    /// or has on its input.
    fn secret_read(&self, unit: &Unit, stdin: Option<&Hit>) -> Option<Hit> {
        let key = unit.key()?;
        // They print or list keys the machine holds, which are public.
        if matches!(key.as_str(), "ssh-keygen" | "ssh-add") {
            return None;
        }
        if dumps_environment(unit, &key) {
            return Some(Hit {
                words: ENVIRONMENT,
                target: key,
            });
        }
        candidates(unit, &key)
            .iter()
            .find_map(|arg| self.secret(unit, arg, false))
            .or_else(|| stdin.cloned())
    }

    /// The secret `arg` names, when it names one: `home` also counts the
    /// home directory itself, which holds them, for what copies a folder.
    fn secret(&self, unit: &Unit, arg: &Arg, home: bool) -> Option<Hit> {
        let text = arg.known().filter(|text| *text != "-")?;
        let words = if is_environ(text) {
            ENVIRONMENT
        } else if dotenv(text, unit.shell, unit.hidden) {
            DOTENV
        } else if public_key(text) {
            return None;
        } else {
            match self.place(unit.shell, unit.scope(), arg) {
                Place::Sensitive(words) if words != HISTORY => words,
                Place::Home { .. } if home => HOME,
                _ => return None,
            }
        };
        Some(Hit {
            words,
            target: text.to_string(),
        })
    }

    fn sent(&mut self, hit: &Hit) {
        self.add(
            Rule::SendSecret,
            format!("sends {} off the machine", hit.words),
            Some(&Arg::Known(hit.target.clone())),
        );
    }

    /// Sending a secret: an upload that names a file, a copy to another
    /// machine, a program that sends what it is piped or redirected, and a
    /// sender handed one by a substitution.
    pub(super) fn send(&mut self, at: usize, unit: &Unit, key: &str) {
        for file in uploads(unit, key) {
            if let Some(hit) = self.secret(unit, &file, false) {
                self.sent(&hit);
            }
        }
        self.copy(unit, key);
        let network = NETWORK.contains(&key);
        let to_network = self.flow.to_network.contains(&at);
        let sink =
            takes_input(unit, key) || to_network || (network && unit.args.contains(&Arg::Input));
        if sink {
            let piped = self
                .flow
                .stage_of(at)
                .and_then(|stage| {
                    self.flow
                        .stage
                        .get(&stage.pipeline)
                        .filter(|(first, _)| *first < stage.index)
                })
                .map(|(_, hit)| hit);
            let own = if to_network {
                self.flow.own(at).or(self.flow.fed(at))
            } else {
                None
            };
            let hit = piped.or(self.flow.stdin(at)).or(own).cloned();
            if let Some(hit) = hit {
                self.sent(&hit);
            }
        }
        if network {
            if let Some(hit) = self.flow.fed(at).cloned() {
                self.sent(&hit);
            }
        }
    }

    /// `scp`, `rsync`, `sftp`, `rclone` and the cloud copiers given a
    /// destination on another machine: what they take from here goes.
    fn copy(&mut self, unit: &Unit, key: &str) {
        let values: &[&str] = match key {
            "scp" => &SCP_VALUES,
            "sftp" => &SFTP_VALUES,
            "rsync" => &RSYNC_VALUES,
            "rclone" | "aws" => &CLOUD_VALUES,
            "gsutil" => &GSUTIL_VALUES,
            _ => return,
        };
        let all = operands(&unit.args, values);
        let verb = |at: usize, verbs: &[&str]| {
            all.get(at)
                .and_then(|arg| arg.known())
                .is_some_and(|word| verbs.contains(&word))
        };
        let skip = match key {
            "rclone" if verb(0, &["copy", "sync", "move", "copyto", "moveto", "bisync"]) => 1,
            "aws" if verb(0, &["s3"]) && verb(1, &["cp", "mv", "sync"]) => 2,
            "gsutil" if verb(0, &["cp", "mv", "rsync"]) => 1,
            "scp" | "sftp" | "rsync" => 0,
            _ => return,
        };
        let Some((destination, sources)) = all.get(skip..).and_then(<[&Arg]>::split_last) else {
            return;
        };
        if !to_other_machine(destination, matches!(key, "scp" | "sftp")) {
            return;
        }
        for source in sources {
            if to_other_machine(source, false) {
                continue;
            }
            if let Some(hit) = self.secret(unit, source, true) {
                self.sent(&hit);
            }
        }
    }
}

/// A secret a variable the unit's arguments mention holds.
fn mentions(unit: &Unit, held: &[(String, Hit)]) -> Option<Hit> {
    unit.args.iter().find_map(|arg| {
        if !arg.is_unknown() {
            return None;
        }
        held.iter()
            .find(|(name, _)| names(arg.text(), name))
            .map(|(_, hit)| hit.clone())
    })
}

/// Whether `text`, an expansion the guard cannot resolve, names the
/// variable: `$k`, `"$k"`, `${k}`, but not `$key`.
fn names(text: &str, name: &str) -> bool {
    ["$", "${"].iter().any(|prefix| {
        let word = format!("{prefix}{name}");
        text.match_indices(&word).any(|(at, _)| {
            !text[at + word.len()..]
                .chars()
                .next()
                .is_some_and(|next| next.is_alphanumeric() || next == '_')
        })
    })
}

/// Whether the path is a network connection bash opens as a file.
fn network_device(text: &str) -> bool {
    text.starts_with("/dev/tcp/") || text.starts_with("/dev/udp/")
}

/// Whether `arg` is on another machine: `host:path`, a URL, a destination
/// only known when it runs that holds a colon, or (`unknown`) any
/// destination only known when it runs.
fn to_other_machine(arg: &Arg, unknown: bool) -> bool {
    match arg {
        Arg::Known(text) => {
            remote(arg)
                || text.contains("://")
                || text.starts_with(':')
                || (text.starts_with('[') && text.contains("]:"))
        }
        Arg::Unknown(_) | Arg::Template { .. } => unknown || arg.text().contains(':'),
        Arg::Input => false,
    }
}

/// The arguments of `unit` that may name a file it reads, without the ones
/// that name a key it logs in with, and the value of each `name=value`.
fn candidates(unit: &Unit, key: &str) -> Vec<Arg> {
    let logs_in = KEY_USERS.contains(&key);
    let mut found = Vec::new();
    let mut iter = unit.args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if logs_in {
            if LOGIN_OPTIONS.contains(&text) {
                iter.next();
                continue;
            }
            if text
                .split_once('=')
                .is_some_and(|(option, _)| LOGIN_OPTIONS.contains(&option))
            {
                continue;
            }
        }
        found.push(arg.clone());
        if let Some((_, value)) = text.split_once('=').filter(|(_, value)| !value.is_empty()) {
            found.push(Arg::Known(value.to_string()));
        }
    }
    found
}

/// Whether `unit` prints the whole environment: `env`, `printenv`, `set`,
/// `export -p`, `declare -x`, PowerShell's `Get-ChildItem env:`.
fn dumps_environment(unit: &Unit, key: &str) -> bool {
    let args = unit.args.as_slice();
    let none = operands(args, &[]).is_empty();
    match (unit.shell, key) {
        (Shell::Posix, "env") => true,
        (Shell::Posix, "printenv") => none,
        (Shell::Posix, "set") => args.is_empty(),
        (Shell::Posix, "export") => none,
        (Shell::Posix, "declare" | "typeset") => {
            none && (has_flag(args, Some('p'), None) || has_flag(args, Some('x'), None))
        }
        (Shell::PowerShell, "get-childitem" | "get-item") => args.iter().any(|arg| {
            arg.known().is_some_and(|text| {
                text.to_ascii_lowercase()
                    .strip_prefix("env:")
                    .is_some_and(|rest| rest.trim_matches(['\\', '/', '*']).is_empty())
            })
        }),
        _ => false,
    }
}

/// `/proc/self/environ` and the like: the environment, as a file.
fn is_environ(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.starts_with("/proc/") && lower.ends_with("/environ")
}

/// A public key is meant to be shared.
fn public_key(text: &str) -> bool {
    text.to_ascii_lowercase().ends_with(".pub")
}

/// Whether `text` names an `.env` file (`.env`, `.env.local`,
/// `config/.env.production`) or a pattern that can: not a folder, and not
/// a template such as `.env.example`.
fn dotenv(text: &str, shell: Shell, hidden: bool) -> bool {
    let windows = shell != Shell::Posix;
    let separators: &[char] = if windows { &['/', '\\'] } else { &['/'] };
    if text.ends_with(separators) {
        return false;
    }
    let name = text.rsplit(separators).next().unwrap_or(text);
    // Windows reads `.env.`, `.env ` and `.env:stream` as `.env`.
    let name = if windows {
        name.split(':')
            .next()
            .unwrap_or(name)
            .trim_end_matches(['.', ' '])
    } else {
        name
    };
    if glob::has_wildcard(name) {
        let flavour = if windows {
            Flavour::Windows
        } else {
            Flavour::Posix
        };
        return [".env", ".env.local"]
            .iter()
            .any(|file| glob::matches(name, file, flavour, hidden));
    }
    let lower = name.to_ascii_lowercase();
    match lower.strip_prefix(".env") {
        Some("") => true,
        Some(rest) => rest
            .strip_prefix('.')
            .is_some_and(|suffix| !TEMPLATES.contains(&suffix)),
        None => false,
    }
}

/// The files a unit uploads, named in its own arguments (`-` stands for
/// its input).
fn uploads(unit: &Unit, key: &str) -> Vec<Arg> {
    match key {
        "curl" => curl_files(&unit.args),
        "wget" => wget_files(&unit.args),
        "http" | "https" | "xh" => unit
            .args
            .iter()
            .filter_map(Arg::known)
            .filter(|text| !text.starts_with('-'))
            .filter_map(item_file)
            .map(named)
            .collect(),
        "invoke-webrequest" | "invoke-restmethod" => parameter(&unit.args, "infile"),
        _ => Vec::new(),
    }
}

/// A file argument; a device that is the input is `-`.
fn named(text: &str) -> Arg {
    let stdin = matches!(text, "/dev/stdin" | "/dev/fd/0");
    Arg::Known(if stdin { "-" } else { text }.to_string())
}

/// What `curl` takes from a file: `-d @f` (also `--data`, `--data-binary`,
/// `--data-ascii`, `--json`), `--data-urlencode name@f`, `-F name=@f` or
/// `name=<f`, `-T f` and `-H @f`.
fn curl_files(args: &[Arg]) -> Vec<Arg> {
    let mut files = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        let mut take = |kind: char, value: Option<Arg>| {
            if let Some(Arg::Known(value)) = value {
                files.extend(curl_file(kind, &value));
            }
        };
        if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            let kind = match name {
                "data" | "data-binary" | "data-ascii" | "json" => 'd',
                "data-urlencode" => 'u',
                "form" => 'F',
                "upload-file" => 'T',
                "header" => 'H',
                _ => continue,
            };
            let value = match attached {
                Some(value) => Some(Arg::Known(value.to_string())),
                None => iter.next().cloned(),
            };
            take(kind, value);
        } else if let Some(bundle) = text.strip_prefix('-') {
            for (at, letter) in bundle.char_indices() {
                let value = |rest: &str, iter: &mut std::slice::Iter<'_, Arg>| {
                    if rest.is_empty() {
                        iter.next().cloned()
                    } else {
                        Some(Arg::Known(rest.to_string()))
                    }
                };
                let rest = bundle.get(at + letter.len_utf8()..).unwrap_or_default();
                if matches!(letter, 'd' | 'F' | 'T' | 'H') {
                    take(letter, value(rest, &mut iter));
                    break;
                }
                if CURL_VALUES.contains(letter) {
                    value(rest, &mut iter);
                    break;
                }
            }
        }
    }
    files
}

/// The files one `curl` option's value names, by the option's kind: `d`
/// data, `u` `--data-urlencode`, `F` a form field, `T` an upload, `H` a
/// header.
fn curl_file(kind: char, value: &str) -> Vec<Arg> {
    match kind {
        'd' | 'H' => value.strip_prefix('@').map(named).into_iter().collect(),
        'u' => value
            .split_once('@')
            .filter(|(name, _)| !name.contains('='))
            .map(|(_, path)| named(path))
            .into_iter()
            .collect(),
        'F' => value
            .split_once('=')
            .and_then(|(_, field)| field.strip_prefix('@').or_else(|| field.strip_prefix('<')))
            .map(|field| {
                field
                    .split(';')
                    .next()
                    .unwrap_or(field)
                    .split(',')
                    .map(named)
                    .collect()
            })
            .unwrap_or_default(),
        // `-T .` uploads what is on the input.
        _ => vec![named(if value == "." { "-" } else { value })],
    }
}

/// What `wget` posts from a file: `--post-file f`, `--body-file f`.
fn wget_files(args: &[Arg]) -> Vec<Arg> {
    let mut files = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        let Some(long) = text.strip_prefix("--") else {
            continue;
        };
        let (name, attached) = long
            .split_once('=')
            .map_or((long, None), |(name, value)| (name, Some(value)));
        if !matches!(name, "post-file" | "body-file") {
            continue;
        }
        let value = match attached {
            Some(value) => Some(value),
            None => iter.next().and_then(Arg::known),
        };
        files.extend(value.map(named));
    }
    files
}

/// The file a request item names for `http` and `xh`: `field@f` uploads it,
/// `field=@f` and `field:=@f` read it as a value, `@f` is the body.
fn item_file(text: &str) -> Option<&str> {
    if text.contains("://") {
        return None;
    }
    let (name, path) = text.split_once('@')?;
    let field = name
        .strip_suffix(":=")
        .or_else(|| name.strip_suffix('='))
        .unwrap_or(name);
    (!field.contains(['=', ':', '@', '/'])).then_some(path)
}

/// The values of a PowerShell parameter, by its name or an abbreviation
/// of it.
fn parameter(args: &[Arg], name: &str) -> Vec<Arg> {
    let mut values = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(param) = arg.known().and_then(|text| text.strip_prefix('-')) else {
            continue;
        };
        let param = param.trim_end_matches(':').to_ascii_lowercase();
        if param.len() >= 2 && name.starts_with(&param) {
            values.extend(iter.next().cloned());
        }
    }
    values
}

/// Whether `unit` sends its input on: a program that does whatever it is
/// given, or one given an option that reads its body from the input.
fn takes_input(unit: &Unit, key: &str) -> bool {
    let args = unit.args.as_slice();
    let stdin = |files: Vec<Arg>| files.iter().any(|file| file.known() == Some("-"));
    match key {
        "curl" => stdin(curl_files(args)),
        "wget" => stdin(wget_files(args)),
        // They read a body from their input unless told not to.
        "http" | "https" | "xh" => {
            !has_flag(args, Some('I'), Some("ignore-stdin"))
                && !has_flag(args, None, Some("offline"))
        }
        "openssl" => args.iter().any(|arg| arg.known() == Some("s_client")),
        "rclone" => operands(args, &[]).first().and_then(|arg| arg.known()) == Some("rcat"),
        "aws" | "gsutil" => {
            args.iter().any(|arg| arg.known() == Some("-"))
                && operands(args, &[])
                    .iter()
                    .any(|arg| to_other_machine(arg, false))
        }
        "tee" => operands(args, &[])
            .iter()
            .any(|arg| arg.known().is_some_and(network_device)),
        "dd" => args
            .iter()
            .filter_map(Arg::known)
            .any(|text| text.strip_prefix("of=").is_some_and(network_device)),
        _ => SINKS.contains(&key),
    }
}
