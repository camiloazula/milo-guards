//! The settings of the machine on macOS and Linux: security switches, the
//! firewall, the services the system runs, backups, and machine-wide
//! preferences. Each is `system_settings`; what stays everyday work (reading
//! a setting, an application's own preferences, a user's own services) is
//! left alone.

use super::Checker;
use crate::path::Place;
use crate::unit::{has_flag, operands, Arg, Unit};
use crate::{Rule, Shell};

/// Units that protect the machine: stopping one turns protection off, as
/// disabling the firewall does.
const PROTECTORS: [&str; 9] = [
    "firewalld",
    "ufw",
    "nftables",
    "iptables",
    "ip6tables",
    "apparmor",
    "auditd",
    "fail2ban",
    "selinux-autorelabel",
];

/// The first operand of a command.
enum Word {
    /// There is none.
    Missing,
    /// It is only known when the line runs.
    Unknown,
    /// Its text, in lower case.
    Is(String),
}

/// The first of `operands`.
fn first_word(operands: &[&Arg]) -> Word {
    match operands.first() {
        None => Word::Missing,
        Some(arg) => arg
            .known()
            .map_or(Word::Unknown, |text| Word::Is(text.to_ascii_lowercase())),
    }
}

/// Options of `systemctl` whose next argument is their value.
const SYSTEMCTL_VALUES: [&str; 20] = [
    "-t",
    "-p",
    "-s",
    "-H",
    "-M",
    "-n",
    "-o",
    "-P",
    "--type",
    "--property",
    "--signal",
    "--host",
    "--machine",
    "--lines",
    "--output",
    "--root",
    "--state",
    "--job-mode",
    "--kill-whom",
    "--kill-value",
];

/// Files that hold `SELinux`'s mode, where a write turns it off at boot.
const SELINUX_FILES: [&str; 2] = ["/|etc/selinux/config", "/|etc/sysconfig/selinux"];

/// The long options of `args` as written, without their `=value`, up to
/// `--`.
fn long_names(args: &[Arg]) -> impl Iterator<Item = &str> {
    args.iter()
        .filter_map(Arg::known)
        .take_while(|text| *text != "--")
        .filter_map(|text| text.strip_prefix("--"))
        .map(|name| name.split('=').next().unwrap_or(name))
}

/// Whether `name`, a long option as written, is `full` or a prefix of it of
/// at least `least` letters: programs that read their options with
/// `getopt_long` take a unique prefix.
fn is_option(name: &str, full: &str, least: usize) -> bool {
    name.len() >= least && full.starts_with(name)
}

/// Whether `args` give the long option `full`, or a prefix of it of at least
/// `least` letters.
fn has_long(args: &[Arg], full: &str, least: usize) -> bool {
    long_names(args).any(|name| is_option(name, full, least))
}

/// The program's name without the suffix of its legacy and nftables builds.
fn base_name(key: &str) -> &str {
    key.strip_suffix("-legacy")
        .or_else(|| key.strip_suffix("-nft"))
        .unwrap_or(key)
}

/// A unit's name without its `.service` suffix.
fn unit_name(name: &str) -> &str {
    name.strip_suffix(".service").unwrap_or(name)
}

/// Whether `name` is one of the units that protect the machine.
fn protects(name: &str) -> bool {
    PROTECTORS.contains(&unit_name(&name.to_ascii_lowercase()))
}

impl Checker<'_> {
    /// Machine settings of macOS and Linux.
    pub(super) fn settings(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        match base_name(key) {
            "spctl" => self.spctl(args),
            "csrutil" => self.csrutil(args),
            "setenforce" => self.setenforce(args),
            "nvram" => self.nvram(args),
            "iptables" | "ip6tables" => self.iptables(args),
            "nft" => self.nft(args),
            "ufw" => self.ufw(args),
            "firewall-cmd" => {
                if has_long(args, "panic-on", 8) || has_long(args, "set-default-zone", 16) {
                    self.add(Rule::SystemSettings, "changes the firewall", None);
                }
            }
            "pfctl" => self.pfctl(args),
            "socketfilterfw" => self.socketfilterfw(args),
            "systemctl" => self.systemctl(args),
            "service" if unit.shell == Shell::Posix => self.service(args),
            "launchctl" => self.launchctl(unit),
            "tmutil" => self.tmutil(args),
            "defaults" => self.defaults(unit),
            "pmset" => self.pmset(args),
            "networksetup" | "systemsetup" => self.set_options(args),
            "scutil" => {
                if has_long(args, "set", 3) {
                    self.add(
                        Rule::SystemSettings,
                        "changes the computer's name or network settings",
                        None,
                    );
                }
            }
            "hostnamectl" | "timedatectl" => self.set_commands(args, key),
            "hostname" if unit.shell == Shell::Posix => self.hostname(args),
            _ => {}
        }
    }

    /// Writes to the files `SELinux` reads its mode from.
    pub(super) fn selinux_file(&mut self, shell: Shell, dir: Option<&Arg>, target: &Arg) {
        let Some(key) = self.resolver.file_key(dir, target, shell) else {
            return;
        };
        if SELINUX_FILES
            .iter()
            .any(|file| file.eq_ignore_ascii_case(&key))
        {
            self.add(
                Rule::SystemSettings,
                "changes SELinux settings",
                Some(target),
            );
        }
    }

    fn spctl(&mut self, args: &[Arg]) {
        if has_long(args, "master-disable", 8)
            || has_long(args, "global-disable", 8)
            || has_long(args, "disable", 1)
        {
            self.add(Rule::SystemSettings, "turns off Gatekeeper", None);
        }
    }

    fn csrutil(&mut self, args: &[Arg]) {
        let off = args.iter().any(|arg| match arg.known() {
            Some(text) => matches!(text.to_ascii_lowercase().as_str(), "disable" | "--without"),
            None => true,
        });
        if off {
            self.add(
                Rule::SystemSettings,
                "turns off System Integrity Protection",
                None,
            );
        }
    }

    fn setenforce(&mut self, args: &[Arg]) {
        // The mode is the only operand: `1` and `Enforcing` keep SELinux on.
        let words = operands(args, &[]);
        let on = words.first().is_some_and(|mode| {
            mode.known()
                .is_some_and(|text| text == "1" || text.eq_ignore_ascii_case("enforcing"))
        });
        if !on && !words.is_empty() {
            self.add(Rule::SystemSettings, "turns off SELinux enforcement", None);
        }
    }

    fn nvram(&mut self, args: &[Arg]) {
        // Setting a variable (`name=value`), deleting one, clearing them
        // all, or setting them from a file; printing is everyday work.
        let writes = has_flag(args, Some('d'), None)
            || has_flag(args, Some('c'), None)
            || has_flag(args, Some('f'), None)
            || args.iter().any(|arg| match arg.known() {
                Some(text) => text.contains('='),
                None => true,
            });
        if writes {
            self.add(
                Rule::SystemSettings,
                "changes the computer's startup settings",
                None,
            );
        }
    }

    fn iptables(&mut self, args: &[Arg]) {
        let flushes = has_flag(args, Some('F'), None) || has_long(args, "flush", 2);
        let deletes = has_flag(args, Some('X'), None) || has_long(args, "delete-chain", 8);
        let opens = self.accepts_by_default(args);
        if flushes || deletes || opens {
            self.add(Rule::SystemSettings, "changes the firewall", None);
        }
    }

    /// Whether `-P chain ACCEPT` (or `--policy`) sets a chain's default to
    /// let everything in, or to a policy only known when it runs.
    fn accepts_by_default(&self, args: &[Arg]) -> bool {
        let at = args
            .iter()
            .take_while(|arg| arg.known() != Some("--"))
            .position(|arg| {
                arg.known()
                    .is_some_and(|text| match text.strip_prefix("--") {
                        Some(name) => is_option(name, "policy", 2),
                        None => text.len() > 1 && text.starts_with('-') && text[1..].contains('P'),
                    })
            });
        at.is_some_and(|at| match args.get(at + 2) {
            Some(policy) => policy
                .known()
                .is_none_or(|text| text.eq_ignore_ascii_case("accept")),
            None => false,
        })
    }

    fn nft(&mut self, args: &[Arg]) {
        let words = operands(
            args,
            &["-f", "--file", "-I", "--includepath", "-D", "--define"],
        );
        let risky = match first_word(&words) {
            Word::Missing => false,
            Word::Unknown => true,
            Word::Is(verb) => {
                let what = words
                    .get(1)
                    .and_then(|arg| arg.known())
                    .map(str::to_ascii_lowercase);
                match verb.as_str() {
                    "flush" => matches!(what.as_deref(), Some("ruleset" | "table" | "chain")),
                    "delete" | "destroy" => matches!(what.as_deref(), Some("table" | "chain")),
                    _ => false,
                }
            }
        };
        if risky {
            self.add(Rule::SystemSettings, "changes the firewall", None);
        }
    }

    fn ufw(&mut self, args: &[Arg]) {
        let words = operands(args, &[]);
        let reason = match first_word(&words) {
            Word::Missing => None,
            Word::Unknown => Some("changes the firewall"),
            Word::Is(sub) => match sub.as_str() {
                "disable" => Some("turns the firewall off"),
                "reset" => Some("resets the firewall's rules"),
                "default" => words
                    .get(1)
                    .is_none_or(|arg| {
                        arg.known()
                            .is_none_or(|text| text.eq_ignore_ascii_case("allow"))
                    })
                    .then_some("lets everything through the firewall"),
                _ => None,
            },
        };
        if let Some(reason) = reason {
            self.add(Rule::SystemSettings, reason, None);
        }
    }

    fn pfctl(&mut self, args: &[Arg]) {
        let off = has_flag(args, Some('d'), None);
        // `-F` takes what to flush: the rules, the translation rules, or
        // all of it.
        let flushes = args
            .iter()
            .position(|arg| {
                arg.known().is_some_and(|text| {
                    text.starts_with('-')
                        && !text.starts_with("--")
                        && text.len() > 1
                        && text[1..].contains('F')
                })
            })
            .is_some_and(|at| match args.get(at + 1) {
                Some(what) => what.known().is_none_or(|text| {
                    ["all", "rules", "nat"]
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(text))
                }),
                None => false,
            });
        if off || flushes {
            self.add(Rule::SystemSettings, "changes the firewall", None);
        }
    }

    fn socketfilterfw(&mut self, args: &[Arg]) {
        let off = args
            .iter()
            .position(|arg| {
                arg.known()
                    .is_some_and(|text| text.eq_ignore_ascii_case("--setglobalstate"))
            })
            .is_some_and(|at| match args.get(at + 1) {
                Some(state) => state.known().is_none_or(|text| {
                    ["off", "0", "no", "false"]
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(text))
                }),
                None => false,
            });
        if off {
            self.add(Rule::SystemSettings, "turns the firewall off", None);
        }
    }

    /// `systemctl disable` and `mask` change which services the system runs,
    /// and `stop` of a unit that protects the machine turns that protection
    /// off. Stopping any other unit is everyday work (`stop docker`), and
    /// `--user` units are the user's own.
    fn systemctl(&mut self, args: &[Arg]) {
        let mut user = false;
        for name in long_names(args) {
            if is_option(name, "user", 2) {
                user = true;
            } else if is_option(name, "system", 4) || name == "global" {
                user = false;
            }
        }
        if user {
            return;
        }
        let words = operands(args, &SYSTEMCTL_VALUES);
        match first_word(&words) {
            Word::Missing => {}
            Word::Unknown => self.add(
                Rule::SystemSettings,
                "changes a system service only known when it runs",
                None,
            ),
            Word::Is(sub) => match sub.as_str() {
                "disable" | "mask" => self.add(
                    Rule::SystemSettings,
                    if sub == "mask" {
                        "masks a system service"
                    } else {
                        "disables a system service"
                    },
                    words.get(1).copied(),
                ),
                "stop" => {
                    for unit in words.iter().skip(1) {
                        if unit.known().is_none_or(protects) {
                            self.add(
                                Rule::SystemSettings,
                                "stops a service that protects the system",
                                Some(unit),
                            );
                        }
                    }
                }
                _ => {}
            },
        }
    }

    /// `service name stop` is `systemctl stop`.
    fn service(&mut self, args: &[Arg]) {
        let words = operands(args, &[]);
        let stops = words
            .get(1)
            .and_then(|arg| arg.known())
            .is_some_and(|action| action.eq_ignore_ascii_case("stop"));
        if let (true, Some(name)) = (stops, words.first()) {
            if name.known().is_none_or(protects) {
                self.add(
                    Rule::SystemSettings,
                    "stops a service that protects the system",
                    Some(name),
                );
            }
        }
    }

    /// `launchctl bootout`, `unload`, `remove` and `disable` take a service
    /// away from the system. The one thing read as the user's own is a
    /// plist inside the workspace, which the workspace installed.
    fn launchctl(&mut self, unit: &Unit) {
        let words = operands(&unit.args, &["-S", "-D"]);
        let sub = match first_word(&words) {
            Word::Missing => return,
            Word::Is(sub) => sub,
            Word::Unknown => {
                self.add(
                    Rule::SystemSettings,
                    "changes a system service only known when it runs",
                    None,
                );
                return;
            }
        };
        let rest = &words[1..];
        let paths: &[&Arg] = match sub.as_str() {
            "unload" => rest,
            // The first operand is the domain: `system`, `gui/501`.
            "bootout" => {
                let system = rest.first().is_none_or(|domain| {
                    domain.known().is_none_or(|text| text.starts_with("system"))
                });
                if system {
                    &[]
                } else {
                    &rest[1..]
                }
            }
            "remove" | "disable" => {
                self.add(
                    Rule::SystemSettings,
                    "removes a service the system runs",
                    None,
                );
                return;
            }
            _ => return,
        };
        let own = !paths.is_empty()
            && paths
                .iter()
                .all(|path| self.place(unit.shell, unit.scope(), path).harmless());
        if !(own || sub == "unload" && paths.is_empty()) {
            self.add(
                Rule::SystemSettings,
                "removes a service the system runs",
                paths.first().copied(),
            );
        }
    }

    fn tmutil(&mut self, args: &[Arg]) {
        let words = operands(args, &[]);
        let reason = match first_word(&words) {
            Word::Missing => None,
            Word::Unknown => Some("changes Time Machine backups"),
            Word::Is(sub) => match sub.as_str() {
                "delete" | "deletelocalsnapshots" | "deleteinprogress" | "thinlocalsnapshots" => {
                    Some("deletes Time Machine backups")
                }
                "disable" | "disablelocal" | "removedestination" => Some("turns Time Machine off"),
                _ => None,
            },
        };
        if let Some(reason) = reason {
            self.add(Rule::SystemSettings, reason, words.get(1).copied());
        }
    }

    /// `defaults` changes preferences. An application's own keys are
    /// everyday work; deleting or importing over a whole domain, or any
    /// change to a file beyond the user's own, is not.
    fn defaults(&mut self, unit: &Unit) {
        let args = unit.args.as_slice();
        let words = operands(args, &["-host", "-app"]);
        let verb = match first_word(&words) {
            Word::Missing => return,
            Word::Unknown => {
                self.add(
                    Rule::SystemSettings,
                    "changes preferences only known when it runs",
                    None,
                );
                return;
            }
            Word::Is(verb) => verb,
        };
        if !matches!(verb.as_str(), "write" | "delete" | "import" | "rename") {
            return;
        }
        // `-g`, `-globalDomain` and `-app name` give the domain themselves.
        let domain_option = args
            .iter()
            .filter_map(Arg::known)
            .any(|text| matches!(text, "-g" | "-globalDomain" | "-app"));
        let rest = &words[1..];
        // `import` replaces the domain's whole content, and `delete` with no
        // key deletes all of it.
        let whole =
            verb == "import" || (verb == "delete" && rest.len() + usize::from(domain_option) <= 1);
        if whole {
            self.add(
                Rule::SystemSettings,
                "replaces all of an application's preferences",
                rest.first().copied(),
            );
            return;
        }
        if domain_option {
            return;
        }
        if let Some(domain) = rest.first() {
            let machine_wide = match domain.known() {
                None => true,
                Some(text) if text.contains('/') => {
                    matches!(
                        self.place(unit.shell, unit.scope(), domain),
                        Place::Top(_) | Place::Unknown
                    )
                }
                Some(_) => false,
            };
            if machine_wide {
                self.add(
                    Rule::SystemSettings,
                    "changes machine-wide preferences",
                    Some(domain),
                );
            }
        }
    }

    fn pmset(&mut self, args: &[Arg]) {
        // `-a`, `-b`, `-c` and `-u` pick which power source a setting is for;
        // `-g` reads.
        let sets = !has_flag(args, Some('g'), None)
            && (args
                .iter()
                .filter_map(Arg::known)
                .any(|text| matches!(text, "-a" | "-b" | "-c" | "-u"))
                || operands(args, &[]).first().is_some_and(|sub| {
                    sub.known().is_some_and(|text| {
                        matches!(
                            text.to_ascii_lowercase().as_str(),
                            "schedule" | "repeat" | "relative" | "restoredefaults"
                        )
                    })
                }));
        if sets {
            self.add(Rule::SystemSettings, "changes power settings", None);
        }
    }

    /// `networksetup` and `systemsetup` change a setting with an option that
    /// starts `-set`, `-add`, `-remove` and the like; `-get` and `-list`
    /// read.
    fn set_options(&mut self, args: &[Arg]) {
        let sets = args.iter().filter_map(Arg::known).any(|text| {
            let lower = text.to_ascii_lowercase();
            [
                "-set",
                "-add",
                "-remove",
                "-create",
                "-delete",
                "-rename",
                "-duplicate",
                "-order",
                "-import",
                "-switchtolocation",
            ]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        });
        if sets {
            self.add(
                Rule::SystemSettings,
                "changes system or network settings",
                None,
            );
        }
    }

    /// `hostnamectl set-hostname` and `timedatectl set-timezone`: the
    /// commands that start `set-`.
    fn set_commands(&mut self, args: &[Arg], key: &str) {
        let words = operands(args, &["-H", "--host", "-M", "--machine"]);
        let sets = match first_word(&words) {
            Word::Missing => false,
            Word::Unknown => true,
            Word::Is(sub) => sub.starts_with("set-"),
        };
        if sets {
            let reason = if key == "hostnamectl" {
                "changes the computer's name"
            } else {
                "changes the computer's clock settings"
            };
            self.add(Rule::SystemSettings, reason, words.get(1).copied());
        }
    }

    /// `hostname name` (or `-F file`) sets the computer's name; with no
    /// name it prints it.
    fn hostname(&mut self, args: &[Arg]) {
        if !operands(args, &["-F", "--file"]).is_empty() || has_flag(args, Some('F'), Some("file"))
        {
            self.add(Rule::SystemSettings, "changes the computer's name", None);
        }
    }
}
