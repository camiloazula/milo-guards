//! The service managers beyond `systemctl`, `service`, `launchctl` and the
//! init scripts: OpenBSD's `rcctl`, FreeBSD's `sysrc`, s6's `s6-svc` and
//! `s6-rc`, `dinitctl`, `insserv` and Homebrew's `brew services`. Each reads
//! as the `systemctl` verb it matches: a stop is a stop of each service it
//! names, judged by the same names ([`Checker::stop_service`]), and taking a
//! service out of what starts at boot is a disable of it, whatever the
//! service ([`Checker::disable_service`]).

use super::{first_word, getopt_walk, has_long, literal_start, short_options, Given, Word};
use crate::detect::Checker;
use crate::path::Access;
use crate::unit::{has_flag, operands, Arg, Unit};
use crate::Rule;

/// What a command word only known when it runs may change.
pub(super) const UNKNOWN_VERB: &str = "changes a system service only known when it runs";

/// The short options of `sysrc` that take a value: the file (`-f`), the
/// jail (`-j`), the root folder (`-R`) and the service (`-s`).
const SYSRC_VALUED: &str = "fjRs";

/// The short options of `s6-svc` that take a value: the timeout (`-T`),
/// what to wait for (`-w`) and the signal (`-s`).
const S6_SVC_VALUED: &str = "Tws";

/// The short options of `s6-rc` that take a value: the verbosity (`-v`),
/// the dry run's throttle (`-n`), the timeout (`-t`) and the live folder
/// (`-l`).
const S6_RC_VALUED: &str = "vntl";

/// The options of `dinitctl` that take the next word as their value.
const DINITCTL_VALUED: [&str; 5] = ["-p", "--socket-path", "-d", "--services-dir", "--from"];

/// Whether an `rc.conf` value turns a service on: `rc.subr` reads `YES`,
/// `TRUE`, `ON` and `1`, without case, as on, and anything else as off.
fn is_yes(value: &str) -> bool {
    ["yes", "true", "on", "1"]
        .iter()
        .any(|yes| yes.eq_ignore_ascii_case(value))
}

/// Whether an `rc.conf` variable is the one that starts a service at boot
/// (`sshd_enable`).
fn is_enable(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with("_enable")
}

/// Whether a word of `sysrc` takes a service out of what starts at boot:
/// a `NAME_enable` set to a value that is not on ([`is_yes`]), or changed
/// with `+=` or `-=`, which leaves a value `rc.subr` does not read as on,
/// or removed (`removes`, under `-x` or `-X`). A word only known when it runs is
/// such a variable unless what is known of it names another one
/// (`sshd_flags=$f`).
fn sysrc_disables(word: &Arg, removes: bool) -> bool {
    let (text, whole) = match word.known() {
        Some(text) => (text, true),
        None => (literal_start(word), false),
    };
    let Some((name, value)) = text.split_once('=') else {
        return !whole || removes && is_enable(text);
    };
    let changed = name.ends_with(['+', '-']);
    let name = name.trim_end_matches(['+', '-']);
    is_enable(name) && (changed || !whole || !is_yes(value))
}

/// The options of `s6-svc` that send a signal that ends the process
/// (`-t` `SIGTERM`, `-k` `SIGKILL`, `-K` `SIGKILL` to its process group, and
/// `-a`, `-b`, `-q`, `-h`, `-i`, `-1`, `-2`), restart it (`-r`) or reload
/// it (`-l`, a `-r` to a service that cannot reload), each of which s6
/// follows with a start unless `-O`, `-o` or `-Q` says not to.
const S6_SVC_ENDS: &str = "tkKabqhi12rl";

/// Whether a signal `s6-svc -s` sends may end the process: any it accepts
/// but `CONT` and `WINCH`, by name, with or without `SIG`, or by number
/// (18 and 28; 19, `CONT` on the BSDs, is [`pauses`]).
fn ends(signal: &str) -> bool {
    let upper = signal.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    !matches!(name, "CONT" | "WINCH" | "18" | "28")
}

/// Whether a signal `s6-svc -s` sends pauses the service: `STOP`, with or
/// without `SIG`, or its number on Linux (19) and the BSDs and macOS (17).
fn pauses(signal: &str) -> bool {
    let upper = signal.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    matches!(name, "STOP" | "19" | "17")
}

/// Whether the legacy arguments of `update-rc.d name start|stop NN
/// runlevel... .` stop the service in a runlevel the system runs in: `2` to
/// `5`, or `S`, the one it boots through. A group that names no runlevel
/// (`update-rc.d ssh stop`), a runlevel or a keyword only known when it runs
/// may be one of them. `words` start at the first keyword.
pub(super) fn legacy_stops(words: &[&Arg]) -> bool {
    let mut iter = words.iter();
    while let Some(keyword) = iter.next() {
        let stop = match keyword.known() {
            None => return true,
            Some(text) => text.eq_ignore_ascii_case("stop"),
        };
        // The sequence number, then the runlevels up to the `.`.
        iter.next();
        let mut levels = 0;
        for level in iter.by_ref() {
            match level.known() {
                Some(".") => break,
                Some(text) => {
                    levels += 1;
                    if stop
                        && matches!(
                            text.to_ascii_lowercase().as_str(),
                            "2" | "3" | "4" | "5" | "s"
                        )
                    {
                        return true;
                    }
                }
                None => {
                    levels += 1;
                    if stop {
                        return true;
                    }
                }
            }
        }
        if stop && levels == 0 {
            return true;
        }
    }
    false
}

impl Checker<'_> {
    /// `rcctl [-df] command daemon...`, OpenBSD's: `stop` stops each daemon,
    /// and `disable` and `set daemon status off` take it out of what starts
    /// at boot. A command, a variable or a value of `set status` only known
    /// when it runs may be any of them. `rcctl` refuses `set daemon flags
    /// NO`, so no value of `flags` disables the daemon.
    pub(super) fn rcctl(&mut self, args: &[Arg]) {
        let words = operands(args, &[]);
        let rest = words.get(1..).unwrap_or_default();
        let command = match first_word(&words) {
            Word::Missing => return,
            Word::Unknown => {
                self.add(Rule::SystemSettings, UNKNOWN_VERB, None);
                return;
            }
            Word::Is(command) => command,
        };
        match command.as_str() {
            "stop" => {
                for daemon in rest {
                    self.stop_service("stops", daemon);
                }
            }
            "disable" => {
                if let Some(daemon) = rest.first() {
                    self.disable_service(Some(daemon));
                }
            }
            "set" => {
                let (Some(daemon), Some(variable)) = (rest.first(), rest.get(1)) else {
                    return;
                };
                let value = rest.get(2).map(|value| value.known());
                let off = match variable.known().map(str::to_ascii_lowercase) {
                    None => true,
                    Some(variable) if variable == "status" => value.is_some_and(|value| {
                        value.is_none_or(|text| !text.eq_ignore_ascii_case("on"))
                    }),
                    Some(_) => false,
                };
                if off {
                    self.disable_service(Some(daemon));
                }
            }
            _ => {}
        }
    }

    /// `sysrc [options] name[[+|-]=value]...`, FreeBSD's, sets the variables
    /// of `rc.conf`: a word that takes a service out of what starts at boot
    /// ([`sysrc_disables`]) is a disable of it. `-c` only checks whether a
    /// value would change, and a file of the workspace's own (`-f
    /// ./rc.conf`) is not the system's, unless `-R` or `-j` has `sysrc` run
    /// again in another root or a jail, which reads the file there. An
    /// option only known when it runs may be `-x`.
    pub(super) fn sysrc(&mut self, unit: &Unit) {
        let args = unit.args.as_slice();
        let options = short_options(args, SYSRC_VALUED);
        let given = |letters: &[char]| options.iter().any(|(letter, _)| letters.contains(letter));
        if given(&['c']) {
            return;
        }
        let files: Vec<Arg> = options
            .iter()
            .filter(|(letter, _)| *letter == 'f')
            .filter_map(|(_, given)| match given {
                Given::Attached(text) => Some(Arg::Known((*text).to_string())),
                Given::Next(arg) => Some((*arg).clone()),
                Given::Nothing => None,
            })
            .collect();
        if !files.is_empty()
            && !given(&['R', 'j'])
            && files.iter().all(|file| {
                self.place(unit.shell, unit.scope(), file, Access::Item)
                    .harmless()
            })
        {
            return;
        }
        let walk = getopt_walk(args, SYSRC_VALUED, &[]);
        let removes = walk.unknown || given(&['x', 'X']);
        if let Some(word) = walk
            .operands
            .iter()
            .find(|word| sysrc_disables(word, removes))
        {
            self.disable_service(Some(word));
        }
    }

    /// `s6-svc [options] servicedir...`: `-d` and `-D` take each service
    /// down, and `-p` and `-P` (or `-s STOP`) pause it, which freezes it.
    /// `-u`, `-r`, `-o` and the signals that end the process, which s6 then
    /// starts again, are everyday work, but after `-O`, `-o` or `-Q` s6 does
    /// not start it again, so a signal that ends it ([`ends`]) or a restart
    /// (`-r`, `-l`) stops it. An option only known when it runs may be any
    /// of them. A folder is named as [`Checker::service_folder`] reads it.
    pub(super) fn s6_svc(&mut self, unit: &Unit) {
        let args = unit.args.as_slice();
        let walk = getopt_walk(args, S6_SVC_VALUED, &[]);
        let options = short_options(args, S6_SVC_VALUED);
        let once = options
            .iter()
            .any(|(letter, _)| matches!(letter, 'O' | 'o' | 'Q'));
        let stops = walk.unknown
            || options.iter().any(|(letter, given)| match (letter, given) {
                ('d' | 'D' | 'p' | 'P', _) => true,
                ('s', Given::Attached(signal)) => pauses(signal) || once && ends(signal),
                ('s', Given::Next(signal)) => signal
                    .known()
                    .is_none_or(|signal| pauses(signal) || once && ends(signal)),
                ('s', Given::Nothing) => false,
                (letter, _) => once && S6_SVC_ENDS.contains(*letter),
            });
        if stops {
            for service in &walk.operands {
                let service = self.service_folder(unit, service);
                self.stop_service("stops", &service);
            }
        }
    }

    /// `s6-rc [options] command [service...]`: `change` with `-d` or `-D`
    /// (`-u` is its default), and `stop`, take each service down, and under
    /// `-a` every service that is up. `-p` (prune) takes down every service
    /// it is not given, as `systemctl isolate` does, and `-n` only shows what
    /// it would do. A command or an option only known when it runs may be
    /// any of them.
    pub(super) fn s6_rc(&mut self, args: &[Arg]) {
        let walk = getopt_walk(args, S6_RC_VALUED, &[]);
        let letters: Vec<char> = short_options(args, S6_RC_VALUED)
            .iter()
            .map(|(letter, _)| *letter)
            .collect();
        if letters.contains(&'n') {
            return;
        }
        let down = walk.unknown || letters.iter().any(|letter| matches!(letter, 'd' | 'D'));
        let stops = match first_word(&walk.operands) {
            Word::Missing => return,
            Word::Unknown => true,
            Word::Is(command) => match command.as_str() {
                "change" => down,
                "stop" => true,
                "start" => false,
                _ => return,
            },
        };
        if walk.unknown || letters.contains(&'p') {
            self.add(
                Rule::SystemSettings,
                "changes which services the system runs",
                None,
            );
        }
        if !stops {
            return;
        }
        if letters.contains(&'a') {
            self.add(Rule::SystemSettings, "stops every system service", None);
        }
        for service in walk.operands.get(1..).unwrap_or_default() {
            self.stop_service("stops", service);
        }
    }

    /// `dinitctl [options] command [service...]`: `stop` and `release` stop
    /// each service, `signal SIGNAL service` sends one to it, as `systemctl
    /// kill` does, `disable` takes it out of what starts at boot, and
    /// `shutdown` stops the system. `-u` (`--user`) talks to the user's own
    /// instance, unless a later `-s` (`--system`), a socket (`-p`,
    /// `--socket-path`), which `dinitctl` uses whatever `-u` says, or an
    /// option only known when it runs, names the system's.
    pub(super) fn dinitctl(&mut self, args: &[Arg]) {
        let mut user = false;
        let mut socket = false;
        let mut unknown = false;
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.known() {
                Some("--") => break,
                Some("-u" | "--user") => user = true,
                Some("-s" | "--system") => user = false,
                Some(text) if DINITCTL_VALUED.contains(&text) => {
                    socket |= matches!(text, "-p" | "--socket-path");
                    iter.next();
                }
                Some(text) if text.starts_with("--socket-path=") => socket = true,
                Some(_) => {}
                None => unknown = true,
            }
        }
        if user && !socket && !unknown {
            return;
        }
        let words = operands(args, &DINITCTL_VALUED);
        let rest = words.get(1..).unwrap_or_default();
        let command = match first_word(&words) {
            Word::Missing => return,
            Word::Unknown => {
                self.add(Rule::SystemSettings, UNKNOWN_VERB, None);
                return;
            }
            Word::Is(command) => command,
        };
        match command.as_str() {
            "stop" | "release" => {
                for service in rest {
                    self.stop_service("stops", service);
                }
            }
            "signal" => {
                if let Some(service) = rest.get(1) {
                    self.stop_service("kills", service);
                }
            }
            "disable" => {
                if let Some(service) = rest.first() {
                    self.disable_service(Some(service));
                }
            }
            "shutdown" => self.add(
                Rule::StopSystem,
                "shuts the computer down or restarts it",
                None,
            ),
            _ => {}
        }
    }

    /// `insserv -r script` (`--remove`, or a prefix of it such as `--rem`,
    /// as `getopt_long` reads one) takes a script out of the boot sequence,
    /// whatever the service; `-n` (`--dryrun`) only shows what it
    /// would do. An option only known when it runs may be `-r`.
    pub(super) fn insserv(&mut self, args: &[Arg]) {
        if has_flag(args, Some('n'), Some("dryrun")) {
            return;
        }
        let walk = getopt_walk(args, "cop", &["config", "override", "path"]);
        if walk.unknown || has_flag(args, Some('r'), None) || has_long(args, "remove", 3) {
            if let Some(script) = walk.operands.first() {
                self.disable_service(Some(script));
            }
        }
    }

    /// `brew services command formula...`, Homebrew's: `stop` and `kill`
    /// stop each formula's service, and under `--all` every one Homebrew
    /// runs, any of which may protect the machine. A command only known when
    /// it runs may be either, and a subcommand only known when it runs may
    /// be `services` and what follows it.
    pub(super) fn brew_services(&mut self, args: &[Arg]) {
        let words = operands(args, &["--file", "--sudo-service-user", "--max-wait"]);
        match first_word(&words) {
            Word::Is(sub) if sub == "services" => {}
            Word::Unknown => {
                self.add(Rule::SystemSettings, UNKNOWN_VERB, None);
                return;
            }
            _ => return,
        }
        let rest = &words[1..];
        let stops = match first_word(rest) {
            Word::Missing => false,
            Word::Unknown => true,
            Word::Is(command) => matches!(command.as_str(), "stop" | "kill"),
        };
        if !stops {
            return;
        }
        if has_long(args, "all", 3) {
            self.add(
                Rule::SystemSettings,
                "stops services that may protect the system",
                None,
            );
        }
        for formula in &rest[1..] {
            self.stop_service("stops", formula);
        }
    }
}
