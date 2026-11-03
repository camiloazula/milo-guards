//! The settings of the machine on macOS and Linux: security switches, the
//! firewall, the services the system runs, backups, and machine-wide
//! preferences. Each is `system_settings`; what stays everyday work (reading
//! a setting, an application's own preferences, a user's own services) is
//! left alone.

use super::processes::{is_system_label, is_system_unit};
use super::Checker;
use crate::path::{Access, Place};
use crate::unit::{has_flag, operands, Arg, Unit};
use crate::{Rule, Shell};

/// Units that protect the machine: stopping one turns protection off, as
/// disabling the firewall does. The firewalls, the mandatory access control
/// and audit daemons, and the common antivirus and endpoint daemons, with
/// the names their units have on the usual distributions and BSDs.
const PROTECTORS: [&str; 22] = [
    "firewalld",
    "ufw",
    "nftables",
    "iptables",
    "ip6tables",
    "netfilter-persistent",
    "pf",
    "ipfw",
    "apparmor",
    "auditd",
    "fail2ban",
    "clamav-daemon",
    "clamav-freshclam",
    "clamav-clamd",
    "clamd",
    "freshclam",
    "mdatp",
    "falcon-sensor",
    "sentinelone",
    "osqueryd",
    "wazuh-agent",
    "ossec",
];

/// The launchd labels of the daemons that protect a Mac: the application
/// firewall, the audit daemon, Gatekeeper's policy daemon, `XProtect`,
/// Endpoint Security, and the common endpoint agents. A label is one of
/// them, or starts with one and a dot (`com.apple.XProtect.daemon.scan`).
const PROTECTING_LABELS: [&str; 9] = [
    "com.apple.alf",
    "com.apple.auditd",
    "com.apple.syspolicyd",
    "com.apple.xprotect",
    "com.apple.endpointsecurity",
    "com.crowdstrike",
    "com.microsoft.wdav",
    "com.sentinelone",
    "at.obdev.littlesnitchd",
];

/// The folders init scripts are run from: System V's (`/etc/init.d/ufw stop`),
/// Red Hat's older one, and the BSDs'.
const INIT_FOLDERS: [&str; 4] = [
    "etc/init.d",
    "etc/rc.d/init.d",
    "etc/rc.d",
    "usr/local/etc/rc.d",
];

/// Whether an action of an init script, `service`, `invoke-rc.d` or
/// `rc-service` stops the service or takes its protection down: `stop` and
/// the BSD spellings of it, and the actions of the firewall and `AppArmor`
/// scripts that empty the rules or unload the profiles.
fn stops(action: &str) -> bool {
    matches!(
        action.to_ascii_lowercase().as_str(),
        "stop"
            | "onestop"
            | "forcestop"
            | "faststop"
            | "quietstop"
            | "force-stop"
            | "kill"
            | "flush"
            | "teardown"
    )
}

/// Whether a command of runit's `sv` takes the service down. `sv` reads
/// most commands by their first letter: `d` (down), `x` and `e` (exit), `p`
/// (pause, which freezes it), and `D`, `X` and `E` (the same, killing it if
/// it does not stop); `stop`, `shutdown`, `force-stop` and `force-shutdown`
/// are its spelled-out ones.
fn sv_stops(command: &str) -> bool {
    matches!(
        command,
        "stop" | "shutdown" | "force-stop" | "force-shutdown"
    ) || command.starts_with(['d', 'D', 'x', 'X', 'e', 'E', 'p'])
}

/// Whether a launchd label or target (`system/com.apple.alf`) names a daemon
/// that protects the machine.
fn is_protecting_label(target: &str) -> bool {
    let label = target
        .rsplit('/')
        .next()
        .unwrap_or(target)
        .to_ascii_lowercase();
    PROTECTING_LABELS.iter().any(|known| {
        label
            .strip_prefix(known)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
    })
}

/// Whether a `systemctl` target is one the system boots into for everyday
/// work: the graphical and the multi-user one.
fn is_everyday_target(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let target = lower.strip_suffix(".target").unwrap_or(&lower);
    matches!(target, "graphical" | "multi-user")
}

/// Whether a `systemctl` target shuts the computer down, restarts it, or
/// leaves only a rescue shell, as `systemctl poweroff` and `rescue` do.
fn is_stopping_target(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let target = lower.strip_suffix(".target").unwrap_or(&lower);
    matches!(
        target,
        "poweroff" | "reboot" | "halt" | "kexec" | "rescue" | "emergency" | "soft-reboot"
    )
}

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

/// Short options of `systemctl` whose value is the rest of the bundle or the
/// next argument.
const SYSTEMCTL_SHORT: &str = "tpsHMnoPC";

/// Long options of `systemctl` whose value is the next argument (or after
/// `=`).
const SYSTEMCTL_LONG: [&str; 26] = [
    "type",
    "property",
    "signal",
    "host",
    "machine",
    "lines",
    "output",
    "root",
    "state",
    "job-mode",
    "kill-whom",
    "kill-value",
    "message",
    "capsule",
    "what",
    "timestamp",
    "preset-mode",
    "boot-loader-entry",
    "boot-loader-menu",
    "reboot-argument",
    "image",
    "image-policy",
    "drop-in",
    "when",
    "check-inhibitors",
    "legend",
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

/// What a short option was given.
enum Given<'a> {
    /// Nothing: it is last, or takes no value.
    Nothing,
    /// The rest of its bundle (`-Fall`).
    Attached(&'a str),
    /// The next argument (`-F all`).
    Next(&'a Arg),
}

/// The short options of `args` as `getopt` reads them: each letter of a
/// bundle in order, and for a letter in `takes_value` the rest of the bundle
/// or else the next argument as its value, which ends the bundle. Options
/// end at `--`.
fn short_options<'a>(args: &'a [Arg], takes_value: &str) -> Vec<(char, Given<'a>)> {
    let mut found = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        let Some(bundle) = text
            .strip_prefix('-')
            .filter(|bundle| !bundle.starts_with('-'))
        else {
            continue;
        };
        for (at, letter) in bundle.char_indices() {
            if !takes_value.contains(letter) {
                found.push((letter, Given::Nothing));
                continue;
            }
            let rest = &bundle[at + letter.len_utf8()..];
            let given = if rest.is_empty() {
                iter.next().map_or(Given::Nothing, Given::Next)
            } else {
                Given::Attached(rest)
            };
            found.push((letter, given));
            break;
        }
    }
    found
}

/// The arguments of a program that reads them with `getopt_long`, told
/// apart: `shorts` are the short options that take a value, `longs` the long
/// ones, which may be abbreviated (an abbreviation that fits two options is
/// an error to the program, so it changes nothing).
struct Walk<'a> {
    /// The arguments that are not options.
    operands: Vec<&'a Arg>,
    /// The long options given as options, as written and without their
    /// `=value`: an argument that is another option's value is not one.
    longs: Vec<&'a str>,
}

/// Walks `args` the way `getopt_long` does.
fn getopt_walk<'a>(args: &'a [Arg], shorts: &str, longs: &[&str]) -> Walk<'a> {
    let mut walk = Walk {
        operands: Vec::new(),
        longs: Vec::new(),
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.known() {
            Some("--") => {
                walk.operands.extend(iter);
                break;
            }
            Some(text) if text.len() > 1 && text.starts_with('-') => {
                let takes_next = match text.strip_prefix("--") {
                    Some(name) => {
                        walk.longs.push(name.split('=').next().unwrap_or(name));
                        !name.contains('=') && longs.iter().any(|full| is_option(name, full, 1))
                    }
                    None => text[1..]
                        .char_indices()
                        .find(|(_, letter)| shorts.contains(*letter))
                        .is_some_and(|(at, letter)| at + letter.len_utf8() == text.len() - 1),
                };
                if takes_next {
                    iter.next();
                }
            }
            _ => walk.operands.push(arg),
        }
    }
    walk
}

/// The arguments that are not options, for a program that reads them with
/// `getopt_long`.
fn getopt_operands<'a>(args: &'a [Arg], shorts: &str, longs: &[&str]) -> Vec<&'a Arg> {
    getopt_walk(args, shorts, longs).operands
}

/// Whether a unit name is a pattern, which `systemctl` matches against the
/// loaded units.
fn is_pattern(name: &str) -> bool {
    name.contains(['*', '?', '['])
}

/// One word of an `nft` command: its text in lower case, or `None` when it
/// is only known when the line runs.
type NftWord = Option<String>;

/// The commands in the operands of `nft`, which joins its arguments with
/// spaces and reads them as one line: a command ends at `;` or a newline,
/// whichever argument it is in.
fn nft_commands(words: &[&Arg]) -> Vec<Vec<NftWord>> {
    let mut commands = Vec::new();
    let mut current = Vec::new();
    for arg in words {
        let text = match arg {
            Arg::Known(text) | Arg::Template { text, .. } => text.as_str(),
            Arg::Unknown(_) | Arg::Input | Arg::Null => {
                current.push(None);
                continue;
            }
        };
        for (n, part) in text.split([';', '\n']).enumerate() {
            if n > 0 {
                commands.push(std::mem::take(&mut current));
            }
            for word in part.split_whitespace() {
                let known = !word.contains(['$', '`']);
                current.push(known.then(|| word.to_ascii_lowercase()));
            }
        }
    }
    commands.push(current);
    commands
}

/// What `nft flush` empties without losing the ruleset: the rest are
/// `ruleset`, `table` and `chain`, and a word that is none of these is not
/// read.
const NFT_FLUSH_OBJECTS: [&str; 3] = ["set", "map", "meter"];

/// What `nft delete` and `nft destroy` remove that is not a table or chain.
const NFT_DELETE_OBJECTS: [&str; 12] = [
    "rule",
    "set",
    "map",
    "element",
    "flowtable",
    "counter",
    "quota",
    "limit",
    "ct",
    "synproxy",
    "secmark",
    "meter",
];

/// Whether one `nft` command empties or removes the firewall's rules, or
/// is something only known when it runs.
fn nft_empties(command: &[NftWord]) -> bool {
    let Some(verb) = command.first() else {
        return false;
    };
    let Some(verb) = verb else { return true };
    let safe: &[&str] = match verb.as_str() {
        "flush" => &NFT_FLUSH_OBJECTS,
        "delete" | "destroy" => &NFT_DELETE_OBJECTS,
        _ => return false,
    };
    match command.get(1) {
        None => false,
        Some(None) => true,
        Some(Some(object)) => !safe.contains(&object.as_str()),
    }
}

/// Whether a `pfctl -F` modifier, which may be abbreviated, is `all`,
/// `rules` or `nat`.
fn flushes(modifier: &str) -> bool {
    let modifier = modifier.to_ascii_lowercase();
    ["all", "rules", "nat"]
        .iter()
        .any(|name| name.starts_with(&modifier))
}

/// The program's name without the suffix of its legacy and nftables builds.
fn base_name(key: &str) -> &str {
    key.strip_suffix("-legacy")
        .or_else(|| key.strip_suffix("-nft"))
        .unwrap_or(key)
}

/// A unit's name without its `.service` suffix and its instance
/// (`clamd@scan`), or a runit service's without its folder
/// (`/etc/service/ufw`).
fn unit_name(name: &str) -> &str {
    let name = name.trim_end_matches('/');
    let name = name.rsplit('/').next().unwrap_or(name);
    let name = name.strip_suffix(".service").unwrap_or(name);
    name.split('@').next().unwrap_or(name)
}

/// Whether `name` is one of the units that protect the machine.
fn protects(name: &str) -> bool {
    PROTECTORS.contains(&unit_name(&name.to_ascii_lowercase()))
}

impl Checker<'_> {
    /// Machine settings of macOS and Linux.
    pub(super) fn settings(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        if unit.shell == Shell::Posix {
            self.init_script(unit);
        }
        match base_name(key) {
            "spctl" => self.spctl(args),
            "csrutil" => self.csrutil(args),
            "setenforce" => self.setenforce(args),
            "nvram" => self.nvram(args),
            "iptables" | "ip6tables" => self.iptables(args),
            "nft" => self.nft(args),
            "ufw" => self.ufw(args),
            "firewall-cmd" => {
                if has_long(args, "panic-on", 8) || has_long(args, "set-default-zone", 7) {
                    self.add(Rule::SystemSettings, "changes the firewall", None);
                }
            }
            "pfctl" => self.pfctl(args),
            "socketfilterfw" => self.socketfilterfw(args),
            "systemctl" => self.systemctl(args),
            "service" if unit.shell == Shell::Posix => self.service(args),
            "invoke-rc.d" => self.service(args),
            "rc-service" => self.rc_service(args),
            "rc-update" => self.rc_update(args),
            "update-rc.d" => self.update_rc(args),
            "chkconfig" => self.chkconfig(args),
            "sv" if unit.shell == Shell::Posix => self.sv(args),
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
    /// let everything in, or to a policy only known when it runs. The
    /// chain may be attached (`-PINPUT`, `-nPINPUT`, `--policy=INPUT`), and
    /// then the policy is the next argument, not the one after. `OUTPUT`
    /// accepting is the default, so it is not read.
    fn accepts_by_default(&self, args: &[Arg]) -> bool {
        let args: Vec<&Arg> = args
            .iter()
            .take_while(|arg| arg.known() != Some("--"))
            .collect();
        for (at, arg) in args.iter().enumerate() {
            let Some(text) = arg.known() else { continue };
            let attached = if let Some(name) = text.strip_prefix("--") {
                let (name, value) = name
                    .split_once('=')
                    .map_or((name, None), |(name, value)| (name, Some(value)));
                if !is_option(name, "policy", 2) {
                    continue;
                }
                value
            } else {
                let Some(bundle) = text.strip_prefix('-') else {
                    continue;
                };
                let Some(p) = bundle.find('P') else { continue };
                Some(&bundle[p + 1..]).filter(|rest| !rest.is_empty())
            };
            let (chain, policy) = match attached {
                Some(chain) => (Some(chain), args.get(at + 1)),
                None => (
                    args.get(at + 1).and_then(|arg| arg.known()),
                    args.get(at + 2),
                ),
            };
            if chain.is_some_and(|chain| chain.eq_ignore_ascii_case("output")) {
                return false;
            }
            return policy.is_some_and(|policy| {
                policy
                    .known()
                    .is_none_or(|text| text.eq_ignore_ascii_case("accept"))
            });
        }
        false
    }

    /// `nft` joins its arguments and reads them as one command line, so
    /// `nft 'flush ruleset'` and `nft flush ruleset` are the same, and
    /// `;` starts another command. A command that empties the ruleset,
    /// removes a table or chain, or names something not read, is risky.
    fn nft(&mut self, args: &[Arg]) {
        let words = getopt_operands(args, "fIDd", &["file", "includepath", "define", "debug"]);
        // Under `-j` the operands are JSON, which is not read: any object or
        // array in them could hold a flush.
        let json = short_options(args, "fIDd")
            .iter()
            .any(|(letter, _)| *letter == 'j')
            || has_long(args, "json", 1);
        let holds_json = json
            && words.iter().any(|arg| match arg {
                Arg::Known(text) | Arg::Template { text, .. } => text.contains(['{', '[']),
                Arg::Unknown(_) | Arg::Input | Arg::Null => false,
            });
        if holds_json
            || nft_commands(&words)
                .iter()
                .any(|command| nft_empties(command))
        {
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
                // `default allow` opens incoming traffic unless it names
                // `outgoing`, which is ufw's own default.
                "default" => {
                    let allows = words.get(1).is_none_or(|arg| {
                        arg.known()
                            .is_none_or(|text| text.eq_ignore_ascii_case("allow"))
                    });
                    let outgoing = words.get(2).is_some_and(|arg| {
                        arg.known()
                            .is_some_and(|text| text.eq_ignore_ascii_case("outgoing"))
                    });
                    (allows && !outgoing).then_some("lets everything through the firewall")
                }
                _ => None,
            },
        };
        if let Some(reason) = reason {
            self.add(Rule::SystemSettings, reason, None);
        }
    }

    /// `pfctl -d` turns the firewall off, and `-F` flushes what its
    /// modifier names: all, the rules or the translation rules. The
    /// modifier may be abbreviated and attached (`-Fa`, `-qFrules`).
    fn pfctl(&mut self, args: &[Arg]) {
        let mut risky = false;
        for (letter, given) in short_options(args, "aDfFikKopsTtxX") {
            risky |= match (letter, given) {
                ('d', _) => true,
                ('F', Given::Attached(modifier)) => flushes(modifier),
                ('F', Given::Next(modifier)) => modifier.known().is_none_or(flushes),
                _ => false,
            };
        }
        if risky {
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
    /// off. `isolate`, `set-default` to a target that is not an everyday one
    /// and `preset-all` change many units at once, and `edit`, `revert` and
    /// `preset` of a protecting unit change how it runs. Stopping any other
    /// unit is everyday work (`stop docker`), and `--user` units are the
    /// user's own.
    fn systemctl(&mut self, args: &[Arg]) {
        let walk = getopt_walk(args, SYSTEMCTL_SHORT, &SYSTEMCTL_LONG);
        let mut user = false;
        for name in &walk.longs {
            if is_option(name, "user", 2) {
                user = true;
            } else if is_option(name, "system", 2) || is_option(name, "global", 1) {
                user = false;
            }
        }
        if user {
            return;
        }
        let words = walk.operands;
        let units = words.get(1..).unwrap_or_default();
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
                // A pattern (`firewall*`) matches the loaded units, so it may
                // stop one that protects the machine. `kill` sends SIGTERM
                // unless told otherwise, which ends a daemon as `stop` does.
                "stop" | "kill" => {
                    let verb = if sub == "kill" { "kills" } else { "stops" };
                    for unit in units {
                        if unit
                            .known()
                            .is_some_and(|name| is_pattern(name) && !protects(name))
                        {
                            self.add(
                                Rule::SystemSettings,
                                format!("{verb} services that may protect the system"),
                                Some(unit),
                            );
                        } else {
                            self.stop_service(verb, unit);
                        }
                    }
                }
                // `isolate` starts the target and stops every unit it does
                // not want; a target that shuts the computer down or leaves
                // a rescue shell stops the system as `systemctl poweroff`
                // and `rescue` do.
                "isolate" => {
                    let target = words.get(1).copied();
                    if target.and_then(Arg::known).is_some_and(is_stopping_target) {
                        self.add(
                            Rule::StopSystem,
                            "shuts the computer down or restarts it",
                            target,
                        );
                    }
                    self.add(
                        Rule::SystemSettings,
                        "changes which services the system runs",
                        target,
                    );
                }
                "set-default" => {
                    if let Some(target) = words.get(1) {
                        if !target.known().is_some_and(is_everyday_target) {
                            self.add(
                                Rule::SystemSettings,
                                "changes what the system starts at boot",
                                Some(target),
                            );
                        }
                    }
                }
                "preset-all" => self.add(
                    Rule::SystemSettings,
                    "changes which services the system runs",
                    None,
                ),
                "edit" | "revert" | "preset" => {
                    for unit in units {
                        let protecting = unit
                            .known()
                            .is_none_or(|name| is_pattern(name) || protects(name));
                        if protecting {
                            self.add(
                                Rule::SystemSettings,
                                "changes a service that protects the system",
                                Some(unit),
                            );
                        }
                    }
                }
                _ => {}
            },
        }
    }

    /// One service a stop names: the unit that runs a process the system
    /// needs (`systemd-logind`) ends the session it serves, and stopping one
    /// that protects the machine, or one only known when it runs, turns
    /// that protection off. Any other is everyday work.
    fn stop_service(&mut self, verb: &str, unit: &Arg) {
        match unit.known() {
            Some(name) if is_system_unit(unit_name(name)) => self.add(
                Rule::StopSystem,
                format!("{verb} a process the system needs"),
                Some(unit),
            ),
            Some(name) if !protects(name) => {}
            _ => self.add(
                Rule::SystemSettings,
                format!("{verb} a service that protects the system"),
                Some(unit),
            ),
        }
    }

    /// One service an init system takes out of what the system starts at
    /// boot, as `systemctl disable` does.
    fn disable_service(&mut self, unit: Option<&Arg>) {
        self.add(Rule::SystemSettings, "disables a system service", unit);
    }

    /// `service name action` is `systemctl stop` when the action stops the
    /// service ([`stops`]); `invoke-rc.d name action`, Debian's way for
    /// package scripts, reads the same. An action only known when it runs
    /// may be `stop`; a name only known when it runs may protect the
    /// machine.
    fn service(&mut self, args: &[Arg]) {
        let words = operands(args, &[]);
        let (Some(name), Some(action)) = (words.first(), words.get(1)) else {
            return;
        };
        if action.known().is_none_or(stops) {
            self.stop_service("stops", name);
        }
    }

    /// A program run from an init script folder (`/etc/init.d/ufw stop`,
    /// `/etc/rc.d/pf stop`) is the service of its name, and its first
    /// operand the action, as `service ufw stop`. The program is placed
    /// where it lands, so `cd /etc/init.d && ./ufw stop` is the same.
    fn init_script(&mut self, unit: &Unit) {
        let Some(program) = unit.program.known() else {
            return;
        };
        // A name without a folder is looked up on `PATH`, never here.
        if !program.contains('/') {
            return;
        }
        let Some(key) = self
            .resolver
            .file_key(unit.dir.as_ref(), &unit.program, unit.shell)
        else {
            return;
        };
        let Some((folder, name)) = key
            .strip_prefix("/|")
            .and_then(|path| path.rsplit_once('/'))
        else {
            return;
        };
        if !INIT_FOLDERS
            .iter()
            .any(|init| init.eq_ignore_ascii_case(folder))
        {
            return;
        }
        let words = operands(&unit.args, &[]);
        let Some(action) = words.first() else {
            return;
        };
        if action.known().is_none_or(stops) {
            self.stop_service("stops", &Arg::Known(name.to_string()));
        }
    }

    /// `rc-service name command`, `OpenRC`'s `service`. `-e` and `-r` take a
    /// service name.
    fn rc_service(&mut self, args: &[Arg]) {
        let words = operands(args, &["-e", "--exists", "-r", "--resolve", "-U", "--user"]);
        let (Some(name), Some(action)) = (words.first(), words.get(1)) else {
            return;
        };
        if action.known().is_none_or(stops) {
            self.stop_service("stops", name);
        }
    }

    /// `rc-update del name [runlevel]` takes a service out of a runlevel.
    fn rc_update(&mut self, args: &[Arg]) {
        let words = operands(args, &[]);
        match first_word(&words) {
            Word::Missing => {}
            Word::Unknown => self.disable_service(words.get(1).copied()),
            Word::Is(verb) => {
                if matches!(verb.as_str(), "del" | "delete") {
                    self.disable_service(words.get(1).copied());
                }
            }
        }
    }

    /// `update-rc.d name disable|remove` takes a service out of what starts
    /// at boot.
    fn update_rc(&mut self, args: &[Arg]) {
        let words = operands(args, &[]);
        let Some(action) = words.get(1) else { return };
        if action.known().is_none_or(|action| {
            matches!(action.to_ascii_lowercase().as_str(), "disable" | "remove")
        }) {
            self.disable_service(words.first().copied());
        }
    }

    /// `chkconfig name off` and `chkconfig --del name` take a service out of
    /// what starts at boot; `--level` takes the runlevels.
    fn chkconfig(&mut self, args: &[Arg]) {
        let words = operands(args, &["--level"]);
        if has_long(args, "del", 3) {
            self.disable_service(words.first().copied());
            return;
        }
        let Some(state) = words.get(1) else { return };
        if state
            .known()
            .is_none_or(|state| state.eq_ignore_ascii_case("off"))
        {
            self.disable_service(words.first().copied());
        }
    }

    /// `sv command service...`, runit's: a command that takes the service
    /// down ([`sv_stops`]) is a stop of each one. `-w` takes a number of
    /// seconds.
    fn sv(&mut self, args: &[Arg]) {
        let words = operands(args, &["-w"]);
        let Some(command) = words.first() else { return };
        if command.known().is_none_or(sv_stops) {
            for service in &words[1..] {
                self.stop_service("stops", service);
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
        // `kill signal target` and `stop label` end the process of a
        // service: one the system needs is `stop_system`, one that protects
        // the machine is `system_settings`, and one only known when it runs
        // is `stop_unknown`. The target is the last operand.
        if matches!(sub.as_str(), "kill" | "stop") {
            match rest.last().map(|target| (target, target.known())) {
                Some((target, Some(label))) if is_system_label(label) => self.add(
                    Rule::StopSystem,
                    "stops a process the system needs",
                    Some(target),
                ),
                // A daemon that protects the machine: stopping it is a
                // bootout of it.
                Some((target, Some(label))) if is_protecting_label(label) => self.add(
                    Rule::SystemSettings,
                    "stops a service that protects the system",
                    Some(target),
                ),
                Some((target, None)) => self.add(
                    Rule::StopUnknown,
                    "stops a service only known when it runs",
                    Some(target),
                ),
                _ => {}
            }
            return;
        }
        let paths: &[&Arg] = match sub.as_str() {
            // `-D domain` unloads every plist in that search path.
            "unload" => {
                if short_options(&unit.args, "SD")
                    .iter()
                    .any(|(letter, _)| *letter == 'D')
                {
                    self.add(
                        Rule::SystemSettings,
                        "removes a service the system runs",
                        None,
                    );
                    return;
                }
                rest
            }
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
            && paths.iter().all(|path| {
                self.place(unit.shell, unit.scope(), path, Access::Item)
                    .harmless()
            });
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
        let deletes_all = verb == "delete" && rest.len() + usize::from(domain_option) <= 1;
        if verb == "import" || deletes_all {
            self.add(
                Rule::SystemSettings,
                if deletes_all {
                    "deletes all of an application's preferences"
                } else {
                    "replaces all of an application's preferences"
                },
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
                        self.place(unit.shell, unit.scope(), domain, Access::Item),
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

    /// `pmset [-a | -b | -c | -u] [setting value]`: the flag is optional,
    /// so any first operand sets a power setting, except the actions that
    /// only act or read. `-g` reads.
    fn pmset(&mut self, args: &[Arg]) {
        if has_flag(args, Some('g'), None) {
            return;
        }
        let source = args
            .iter()
            .filter_map(Arg::known)
            .any(|text| matches!(text, "-a" | "-b" | "-c" | "-u"));
        let sets = source
            || match first_word(&operands(args, &[])) {
                Word::Missing => false,
                Word::Unknown => true,
                Word::Is(word) => !matches!(
                    word.as_str(),
                    "sleepnow" | "displaysleepnow" | "touch" | "noidle" | "boot"
                ),
            };
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
    /// commands that start `set-`; and, since systemd 249, the commands of
    /// `hostnamectl` that set a value when they are given one (`hostname
    /// NAME`, `chassis vm`) and print it when they are not.
    fn set_commands(&mut self, args: &[Arg], key: &str) {
        // `timedatectl` also takes `-p NTP` (`--property`), whose value is
        // not the command.
        let (shorts, longs): (&str, &[&str]) = if key == "timedatectl" {
            ("HMp", &["host", "machine", "property"])
        } else {
            // `hostnamectl --json MODE` takes its value too.
            ("HM", &["host", "machine", "json"])
        };
        let words = getopt_operands(args, shorts, longs);
        let sets = match first_word(&words) {
            Word::Missing => false,
            Word::Unknown => true,
            Word::Is(sub) => {
                sub.starts_with("set-")
                    || (key == "hostnamectl"
                        && words.len() > 1
                        && matches!(
                            sub.as_str(),
                            "hostname" | "icon-name" | "chassis" | "deployment" | "location"
                        ))
            }
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
