//! The settings of the machine on macOS and Linux: security switches, the
//! firewall, the services the system runs, backups, and machine-wide
//! preferences. Each is `system_settings`; what stays everyday work (reading
//! a setting, an application's own preferences, a user's own services) is
//! left alone.

pub(super) mod firewall;

use super::processes::{
    is_system_label, is_system_unit, unit_pattern_matches, unit_pattern_stops_system,
};
use super::{hedged, script_operand, Checker, CONTENTS};
use crate::launch::SHELLS;
use crate::path::{Access, Place};
use crate::unit::{has_flag, operands, unread_option, Arg, Unit};
use crate::{Rule, Shell};
use milo_guards_core::spelling::glob;
use milo_guards_core::Flavour;

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

/// The units that hold every system service: the root slice holds all
/// units, and `system.slice` the system's services, the ones that protect
/// the machine among them. Stopping one stops them all.
const SYSTEM_SLICES: [&str; 2] = ["-.slice", "system.slice"];

/// The units the users' sessions, the virtual machines and containers, and
/// systemd itself run in, with a stand-in for each kind of instance
/// (`user-0.slice`, `user@0.service`, `session-1.scope`), which a pattern is
/// tested against: stopping one ends what runs in it.
const SESSION_UNITS: [&str; 7] = [
    "user.slice",
    "machine.slice",
    "init.scope",
    "user-0.slice",
    "user@0.service",
    "session-1.scope",
    "machine-0.scope",
];

/// The launchd labels of the daemons that protect a Mac: the application
/// firewall, the audit daemon, Gatekeeper's policy daemon, `XProtect`,
/// Endpoint Security, and the common endpoint agents. A label is one of
/// them, or starts with one and a dot (`com.apple.XProtect.daemon.scan`,
/// `com.apple.XprotectFramework.PluginService`).
const PROTECTING_LABELS: [&str; 10] = [
    "com.apple.alf",
    "com.apple.auditd",
    "com.apple.syspolicyd",
    "com.apple.xprotect",
    "com.apple.xprotectframework",
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
/// work: the graphical and the multi-user one, and the System V runlevels
/// that are their aliases (`runlevel2` to `runlevel4` are multi-user,
/// `runlevel5` graphical).
fn is_everyday_target(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let target = lower.strip_suffix(".target").unwrap_or(&lower);
    matches!(
        target,
        "graphical" | "multi-user" | "runlevel2" | "runlevel3" | "runlevel4" | "runlevel5"
    )
}

/// Whether a `systemctl` target shuts the computer down, restarts it, or
/// leaves only a rescue shell, as `systemctl poweroff` and `rescue` do, and
/// the System V runlevels that are their aliases (`runlevel0` is poweroff,
/// `runlevel1` rescue, `runlevel6` reboot).
fn is_stopping_target(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let target = lower.strip_suffix(".target").unwrap_or(&lower);
    matches!(
        target,
        "poweroff"
            | "reboot"
            | "halt"
            | "kexec"
            | "rescue"
            | "emergency"
            | "soft-reboot"
            | "shutdown"
            | "exit"
            | "final"
            | "runlevel0"
            | "runlevel1"
            | "runlevel6"
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

/// Long options of `spctl` whose value is the next argument.
const SPCTL_LONG: [&str; 4] = ["type", "label", "context", "priority"];

/// Short options of `pfctl` whose value is the rest of the bundle or the
/// next argument.
const PFCTL_VALUED: &str = "aDfFikKopsTtxX";

/// The reason for a firewall program given an option only known when it
/// runs, said as what may happen (see [`hedged`]): only that option turns
/// it on.
const FIREWALL_UNKNOWN: &str = "may change the firewall with an option only known when it runs";

/// Preference keys that keep a protection of the machine on, with their
/// domain and the reason a change of one gives: `LSQuarantine` marks what is
/// downloaded so that Gatekeeper checks it before it first runs.
const PROTECTING_DEFAULTS: [(&str, &str, &str); 1] = [(
    "com.apple.LaunchServices",
    "LSQuarantine",
    "changes the quarantine of downloaded files",
)];

/// Short options of `apparmor_parser` whose value is the rest of the bundle
/// or the next argument.
const APPARMOR_SHORT: &str = "IbfmMoLODj";

/// Long options of `apparmor_parser` whose value is the next argument.
const APPARMOR_LONG: [&str; 15] = [
    "Include",
    "base",
    "subdomainfs",
    "match-string",
    "features-file",
    "ofile",
    "cache-loc",
    "Optimize",
    "dump",
    "jobs",
    "max-jobs",
    "config-file",
    "kernel-features",
    "compile-features",
    "policy-features",
];

/// Short options of `auditctl` whose value is the rest of the bundle or the
/// next argument.
const AUDITCTL_VALUED: &str = "aAbCdefFkmpqrRSwW";

/// Short options of `semanage`'s subcommands (but `module`) whose value is
/// the rest of the bundle or the next argument.
const SEMANAGE_VALUED: &str = "tsrfpLRPeT";

/// The reason for a change to `SELinux`'s mode, booleans or policy.
const SELINUX_CHANGES: &str = "changes SELinux settings";

/// The reason for a change to the boot loader or the firmware's boot
/// entries.
const BOOT_CHANGES: &str = "changes how the computer starts";

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

/// Whether `text`, an argument as written, is the long option `full`, or a
/// prefix of it of at least `least` letters, with or without its `=value`.
fn is_long_of(text: &str, full: &str, least: usize) -> bool {
    text.strip_prefix("--")
        .map(|name| name.split('=').next().unwrap_or(name))
        .is_some_and(|name| is_option(name, full, least))
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
    /// Whether an argument only known when it runs is not an option's
    /// value: it may be an option itself.
    unknown: bool,
}

/// Walks `args` the way `getopt_long` does.
fn getopt_walk<'a>(args: &'a [Arg], shorts: &str, longs: &[&str]) -> Walk<'a> {
    let mut walk = Walk {
        operands: Vec::new(),
        longs: Vec::new(),
        unknown: false,
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.known() {
            Some("--") => {
                walk.operands.extend(iter);
                break;
            }
            Some(text) if text.len() > 1 && text.starts_with('-') => {
                if let Some(name) = text.strip_prefix("--") {
                    walk.longs.push(name.split('=').next().unwrap_or(name));
                }
                if takes_value(text, shorts, longs) {
                    iter.next();
                }
            }
            Some(_) => walk.operands.push(arg),
            None => {
                walk.unknown |= may_be_option(arg);
                walk.operands.push(arg);
            }
        }
    }
    walk
}

/// Whether `text`, an option as written, takes the next argument as its
/// value, to a program that reads its options with `getopt_long`: a long
/// one in `longs` (or a prefix of it) without `=`, or a bundle whose first
/// letter in `shorts` that takes a value is its last.
fn takes_value(text: &str, shorts: &str, longs: &[&str]) -> bool {
    match text.strip_prefix("--") {
        Some(name) => !name.contains('=') && longs.iter().any(|full| is_option(name, full, 1)),
        None => text
            .get(1..)
            .unwrap_or_default()
            .char_indices()
            .find(|(_, letter)| shorts.contains(*letter))
            .is_some_and(|(at, letter)| at + letter.len_utf8() == text.len() - 1),
    }
}

/// Whether `args` hold an argument only known when it runs that may be an
/// option: one before `--` that is not the value of the option before it,
/// and whose known start is empty or a `-` ([`may_be_option`]). `valued`
/// says whether a known option, as written, takes the next argument as its
/// value; one written with `=` (`--zone=public`) holds its value, and never
/// takes the next. Such an argument may be the option that turns a
/// protection off (`spctl $x`, `iptables $flag`), so a program that reads
/// one is changed in a way only known when it runs.
fn unknown_option(args: &[Arg], valued: impl Fn(&str) -> bool) -> bool {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.known() {
            Some("--") => return false,
            Some(text) => {
                if text.len() > 1 && text.starts_with('-') && !text.contains('=') && valued(text) {
                    iter.next();
                }
            }
            None if may_be_option(arg) => return true,
            None => {}
        }
    }
    false
}

/// Whether an argument only known when it runs may be an option: what it
/// starts with for certain is nothing, or a `-` (`app-$name` is not one).
/// What a pipeline hands on (`xargs`) may be anything.
fn may_be_option(arg: &Arg) -> bool {
    let start = literal_start(arg);
    matches!(arg, Arg::Input) || start.is_empty() || start.starts_with('-')
}

/// Long options of `firewall-cmd` whose value is the next argument, unless
/// it is written after `=`; the others take none (`--permanent`,
/// `--reload`, `--state`).
const FIREWALL_CMD_VALUED: [&str; 44] = [
    "zone",
    "policy",
    "service",
    "ipset",
    "icmptype",
    "helper",
    "get-zone-of-interface",
    "get-zone-of-source",
    "info-zone",
    "info-policy",
    "info-service",
    "info-ipset",
    "info-icmptype",
    "info-helper",
    "add-service",
    "remove-service",
    "query-service",
    "add-port",
    "remove-port",
    "query-port",
    "add-protocol",
    "remove-protocol",
    "query-protocol",
    "add-source-port",
    "remove-source-port",
    "query-source-port",
    "add-interface",
    "remove-interface",
    "query-interface",
    "change-interface",
    "add-source",
    "remove-source",
    "query-source",
    "change-source",
    "add-forward-port",
    "remove-forward-port",
    "query-forward-port",
    "add-icmp-block",
    "remove-icmp-block",
    "query-icmp-block",
    "add-rich-rule",
    "remove-rich-rule",
    "query-rich-rule",
    "set-description",
];

/// Whether a `firewall-cmd` option, as written, takes the next argument as
/// its value: one of [`FIREWALL_CMD_VALUED`], or a prefix of one, which
/// its parser takes as that option (or refuses, when it fits two).
fn firewall_cmd_valued(text: &str) -> bool {
    text.strip_prefix("--").is_some_and(|name| {
        FIREWALL_CMD_VALUED
            .iter()
            .any(|full| is_option(name, full, 1))
    })
}

/// Whether a `socketfilterfw` option, as written, takes the next argument
/// as its value: the path of an application. A setting's value (`--setstealthmode off`)
/// is not skipped: only known when it runs, it may turn a protection off.
fn socketfilterfw_valued(text: &str) -> bool {
    [
        "--getappblocked",
        "--add",
        "--remove",
        "--blockapp",
        "--unblockapp",
    ]
    .iter()
    .any(|name| name.eq_ignore_ascii_case(text))
}

/// Whether a `scutil` option, as written, takes the next argument as its
/// value: the preference `--get` reads, the host `-r` reaches, and the key
/// and timeout of `-w` and `-t`.
fn scutil_valued(text: &str) -> bool {
    matches!(text, "--get" | "-r" | "-w" | "-t")
}

/// Whether a `networksetup` option, as written, takes the next argument as
/// its value: the `-get` options (but `-getcomputername` and
/// `-getcurrentlocation`) read the setting of the service or port named
/// next, as a few `-list` and `-show` options do. `systemsetup`'s `-get`
/// options take none.
fn networksetup_valued(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    (lower.starts_with("-get")
        && !matches!(lower.as_str(), "-getcomputername" | "-getcurrentlocation"))
        || matches!(
            lower.as_str(),
            "-listpreferredwirelessnetworks"
                | "-listvalidmturange"
                | "-listvalidmedia"
                | "-showpppoestatus"
        )
}

/// The arguments that are not options, for a program that reads them with
/// `getopt_long`.
fn getopt_operands<'a>(args: &'a [Arg], shorts: &str, longs: &[&str]) -> Vec<&'a Arg> {
    getopt_walk(args, shorts, longs).operands
}

/// Whether a unit name is a pattern, which `systemctl` matches against the
/// loaded units, or holds a brace list, which the shell expands to several
/// (`{ufw,nginx}`).
fn is_pattern(name: &str) -> bool {
    name.contains(['*', '?', '[', '{'])
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

/// Whether `iptables` arguments name a command (`-A`, `-L`, `--flush`).
/// The program refuses a second one, so once a command is named an
/// argument only known when it runs cannot add one: without one, it may be
/// any (`iptables $flag`). A bundle is read up to its first letter that
/// takes a value (`-nL`, but not `-jACCEPT`).
fn names_tables_command(args: &[Arg]) -> bool {
    const COMMANDS: [&str; 13] = [
        "append",
        "check",
        "delete",
        "insert",
        "replace",
        "list",
        "list-rules",
        "flush",
        "zero",
        "new-chain",
        "delete-chain",
        "policy",
        "rename-chain",
    ];
    args.iter()
        .filter_map(Arg::known)
        .take_while(|text| *text != "--")
        .any(|text| match text.strip_prefix("--") {
            Some(name) => {
                let name = name.split('=').next().unwrap_or(name);
                COMMANDS.iter().any(|full| is_option(name, full, 3))
            }
            None => text.strip_prefix('-').is_some_and(|bundle| {
                bundle
                    .chars()
                    .take_while(|letter| !"tpsdiojgmcwW".contains(*letter))
                    .any(|letter| "ACDIRLSFZNXPE".contains(letter))
            }),
        })
}

/// The programs that read the rules of a firewall as `iptables` does.
const TABLES: [&str; 4] = ["iptables", "ip6tables", "ebtables", "arptables"];

/// Whether `key` is the `-restore` of one of [`TABLES`], which loads a
/// whole ruleset (`iptables-restore`, `iptables-legacy-restore`).
fn is_restore(key: &str) -> bool {
    key.strip_suffix("-restore")
        .is_some_and(|name| TABLES.contains(&base_name(name)))
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

/// Whether `name`, a unit as written, is a slice that holds every system
/// service ([`SYSTEM_SLICES`]).
fn holds_system(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SYSTEM_SLICES.contains(&lower.as_str())
}

/// Whether `name`, a unit as written, is one the users' sessions, the
/// virtual machines and containers, or systemd itself run in (see
/// [`SESSION_UNITS`]): `user.slice`, a user's slice (`user-1000.slice`), a
/// user's manager (`user@1000.service`, `user@1000`), a session
/// (`session-3.scope`), a machine's scope, and `init.scope`.
fn holds_sessions(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let instance = |start: &str, end: &str| {
        lower
            .strip_prefix(start)
            .and_then(|rest| rest.strip_suffix(end))
            .is_some_and(|rest| !rest.is_empty())
    };
    matches!(
        lower.as_str(),
        "user.slice" | "machine.slice" | "init.scope"
    ) || instance("user-", ".slice")
        || instance("session-", ".scope")
        || instance("machine-", ".scope")
        || lower.strip_prefix("user@").is_some_and(|rest| {
            let id = rest.strip_suffix(".service").unwrap_or(rest);
            !id.is_empty() && !id.contains('.')
        })
}

/// Whether `name` is one of the units that protect the machine, or a
/// pattern that may match one.
fn may_protect(name: &str) -> bool {
    if is_pattern(name) {
        unit_pattern_matches(name, &PROTECTORS)
    } else {
        protects(name)
    }
}

impl Checker<'_> {
    /// Machine settings of macOS and Linux. An argument of one of these
    /// programs that may split into words when it runs (`iptables $flag`)
    /// may be the option that changes a setting, so a line the program's
    /// own reading finds nothing in is a change all the same. `service`,
    /// `launchctl` and the other service managers take no option that
    /// changes what their words do, which their own reading judges one by
    /// one, an unknown one included.
    pub(super) fn settings(&mut self, at: usize, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        // pwsh on Linux and macOS runs a path under `/etc/init.d` as the
        // init script it is; cmd never does.
        if unit.shell != Shell::Cmd {
            self.init_script(unit, &unit.program, args, false);
            self.shell_runs_init_script(unit, key);
        }
        let before = self.found.len();
        let name = base_name(key);
        match name {
            "spctl" => self.spctl(args),
            "csrutil" => self.csrutil(args),
            "setenforce" => self.setenforce(args),
            "nvram" => self.nvram(args),
            name if TABLES.contains(&name) => self.iptables(args),
            name if is_restore(name) => {
                if self.restore_loads(at, unit) {
                    self.add(Rule::SystemSettings, firewall::REPLACES, None);
                }
            }
            "nft" => self.nft(at, unit),
            "ufw" => self.ufw(args),
            "firewall-cmd" => self.firewall_cmd(args),
            "pfctl" => self.pfctl(args),
            "socketfilterfw" => self.socketfilterfw(args),
            "systemctl" => self.systemctl(args),
            // pwsh on Linux and macOS runs the native `service` and
            // `hostname`; cmd's `hostname` is Windows', which sets nothing.
            "service" if unit.shell != Shell::Cmd => self.service(args),
            // `--query` only asks whether the action would be allowed.
            "invoke-rc.d" => {
                if !args.iter().any(|arg| arg.known() == Some("--query")) {
                    self.service(args);
                }
            }
            "rc-service" => self.rc_service(args),
            "rc-update" => self.rc_update(args),
            "update-rc.d" => self.update_rc(args),
            "chkconfig" => self.chkconfig(args),
            "sv" if unit.shell == Shell::Posix => self.sv(args),
            "launchctl" => self.launchctl(unit),
            "tmutil" => self.tmutil(args),
            "defaults" => self.defaults(unit),
            "pmset" => self.pmset(args),
            "networksetup" => self.set_options(args, networksetup_valued),
            "systemsetup" => self.set_options(args, |_| false),
            "scutil" => {
                // What follows `--nc` is its own command and the service
                // it names, not options.
                let options = args
                    .iter()
                    .position(|arg| arg.known() == Some("--nc"))
                    .map_or(args, |at| &args[..at]);
                let reason = "changes the computer's name or network settings";
                if has_long(args, "set", 3) {
                    self.add(Rule::SystemSettings, reason, None);
                } else if unknown_option(options, scutil_valued) {
                    self.add(Rule::SystemSettings, hedged(reason), None);
                }
            }
            "hostnamectl" | "timedatectl" => self.set_commands(args, key),
            "hostname" if unit.shell != Shell::Cmd => self.hostname(args),
            "aa-disable" | "aa-complain" if !operands(args, &["-d", "--dir"]).is_empty() => {
                self.add(Rule::SystemSettings, "turns off an AppArmor profile", None);
            }
            "aa-teardown" if !has_flag(args, Some('h'), Some("help")) => {
                self.add(Rule::SystemSettings, "turns off AppArmor", None);
            }
            "apparmor_parser" => self.apparmor_parser(args),
            "auditctl" => self.auditctl(args),
            // Every boolean is a switch of the machine's policy.
            "setsebool" if !operands(args, &[]).is_empty() => {
                self.add(Rule::SystemSettings, SELINUX_CHANGES, None);
            }
            "semanage" => self.semanage(args),
            "semodule" => self.semodule(args),
            "sysctl" => self.sysctl(args),
            "grubby" => self.grubby(args),
            "efibootmgr" => self.efibootmgr(args),
            "grub-editenv" | "grub2-editenv" => self.grub_editenv(args),
            "bootctl" => self.bootctl(args),
            // The entry the computer starts next, or always.
            "grub-set-default" | "grub2-set-default" | "grub-reboot" | "grub2-reboot"
                if !operands(args, &["--boot-directory"]).is_empty() =>
            {
                self.add(Rule::SystemSettings, BOOT_CHANGES, None);
            }
            _ => return,
        }
        if self.found.len() == before
            && !matches!(
                name,
                "service"
                    | "invoke-rc.d"
                    | "rc-service"
                    | "rc-update"
                    | "update-rc.d"
                    | "chkconfig"
                    | "sv"
                    | "launchctl"
            )
            && unread_option(args, unit.shell)
        {
            self.add(
                Rule::SystemSettings,
                hedged("changes a machine setting"),
                None,
            );
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
            self.add(Rule::SystemSettings, SELINUX_CHANGES, Some(target));
        }
    }

    /// A file copied or moved into a folder lands there at its own name
    /// (`cp config /etc/selinux/`), and a folder copied whole replaces what
    /// is below where it lands (`cp -r selinux /etc/`): either may be a
    /// file `SELinux` reads its mode from. `leaves` are the names of what is
    /// copied; one that is a pattern, or a folder's contents
    /// ([`CONTENTS`]), may be any. The folder is placed once,
    /// however many there are.
    pub(super) fn selinux_landing(
        &mut self,
        (shell, dir): (Shell, Option<&Arg>),
        (folder, leaves): (&str, &[&str]),
        recursive: bool,
        destination: &Arg,
    ) {
        let Some(key) = self
            .resolver
            .file_key(dir, &Arg::Known(folder.to_string()), shell)
        else {
            return;
        };
        let lands = SELINUX_FILES.iter().any(|file| {
            // The path of the file below the folder.
            let below = if key.ends_with('|') {
                file.strip_prefix(key.as_str())
            } else {
                file.strip_prefix(key.as_str())
                    .and_then(|below| below.strip_prefix('/'))
            };
            let Some(below) = below else { return false };
            let name = match below.split_once('/') {
                None => below,
                Some((first, _)) if recursive => first,
                Some(_) => return false,
            };
            leaves
                .iter()
                .any(|leaf| *leaf == CONTENTS || glob::matches(leaf, name, Flavour::Posix, true))
        });
        if lands {
            self.add_once(
                Rule::SystemSettings,
                SELINUX_CHANGES.to_string(),
                destination,
            );
        }
    }

    /// `spctl`: turning Gatekeeper off, adding a rule that lets what it
    /// names pass Gatekeeper's check (`--add`), letting kernel extensions
    /// load without the user's consent (`kext-consent disable`, or `add` of
    /// a team), and letting the terminal's programs skip Gatekeeper
    /// (`developer-mode enable-terminal`). An option or a command word only
    /// known when it runs may be any of them.
    fn spctl(&mut self, args: &[Arg]) {
        let reason = if has_long(args, "master-disable", 8)
            || has_long(args, "global-disable", 8)
            || has_long(args, "disable", 1)
        {
            Some("turns off Gatekeeper".to_string())
        } else if has_long(args, "add", 2) {
            // A rule that lets what it names pass Gatekeeper's check.
            Some("lets programs skip Gatekeeper".to_string())
        } else {
            let walk = getopt_walk(args, "t", &SPCTL_LONG);
            // The action after the command word, in lower case, or `None`
            // when it is only known when it runs.
            let action = walk
                .operands
                .get(1)
                .map(|arg| arg.known().map(str::to_ascii_lowercase));
            let named = match (first_word(&walk.operands), action) {
                (Word::Is(sub), Some(action)) if sub == "kext-consent" => action
                    .is_none_or(|action| matches!(action.as_str(), "disable" | "add"))
                    .then_some("lets kernel extensions load without consent"),
                (Word::Is(sub), Some(action)) if sub == "developer-mode" => action
                    .is_none_or(|action| action.starts_with("enable"))
                    .then_some("lets programs skip Gatekeeper"),
                _ => None,
            };
            named
                .map(str::to_string)
                .or_else(|| walk.unknown.then(|| hedged("changes Gatekeeper")))
        };
        if let Some(reason) = reason {
            self.add(Rule::SystemSettings, reason, None);
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

    /// `iptables`, and `ebtables` and `arptables`, which take the same
    /// commands: emptying the rules (`ebtables --init-table` too), deleting
    /// a chain, an ACCEPT policy, and a rule that lets everything in.
    fn iptables(&mut self, args: &[Arg]) {
        let flushes = has_flag(args, Some('F'), None)
            || has_long(args, "flush", 2)
            || has_long(args, "init-table", 2);
        let deletes = has_flag(args, Some('X'), None) || has_long(args, "delete-chain", 8);
        let accepts = self.accepts_by_default(args);
        if flushes || deletes || accepts {
            self.add(Rule::SystemSettings, "changes the firewall", None);
        } else if firewall::opens_everything(args) {
            self.add(Rule::SystemSettings, firewall::OPENS, None);
        } else if !names_tables_command(args) && args.iter().any(|arg| arg.known().is_none()) {
            self.add(Rule::SystemSettings, FIREWALL_UNKNOWN, None);
        }
    }

    /// `firewall-cmd`: panic mode, the default zone, a zone that accepts
    /// everything, and the direct interface, whose pass-through and rules
    /// are iptables arguments.
    fn firewall_cmd(&mut self, args: &[Arg]) {
        if has_long(args, "panic-on", 8) || has_long(args, "set-default-zone", 7) {
            self.add(Rule::SystemSettings, "changes the firewall", None);
            return;
        }
        if let Some(rule) = firewall::direct_rule(args) {
            self.iptables(&rule);
            return;
        }
        if firewall::zone_opens(args) {
            self.add(Rule::SystemSettings, firewall::OPENS, None);
        } else if unknown_option(args, firewall_cmd_valued) {
            self.add(Rule::SystemSettings, FIREWALL_UNKNOWN, None);
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
    /// So is a chain whose policy lets everything in, and a ruleset loaded
    /// with `-f` or `-i` that may add anything.
    fn nft(&mut self, at: usize, unit: &Unit) {
        let args = unit.args.as_slice();
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
        let commands = nft_commands(&words);
        if holds_json || commands.iter().any(|command| nft_empties(command)) {
            self.add(Rule::SystemSettings, "changes the firewall", None);
        } else if firewall::nft_opens(&commands) {
            self.add(Rule::SystemSettings, firewall::OPENS, None);
        } else if self.nft_loads(at, unit) {
            self.add(Rule::SystemSettings, firewall::REPLACES, None);
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
                    (allows && !outgoing).then_some(firewall::OPENS)
                }
                _ => firewall::ufw_opens(&words).then_some(firewall::OPENS),
            },
        };
        if let Some(reason) = reason {
            self.add(Rule::SystemSettings, reason, None);
        }
    }

    /// `pfctl -d` turns the firewall off, and `-F` flushes what its
    /// modifier names: all, the rules or the translation rules. The
    /// modifier may be abbreviated and attached (`-Fa`, `-qFrules`). `-f`
    /// replaces the rules with what it loads, unless `-n` only parses it.
    fn pfctl(&mut self, args: &[Arg]) {
        let mut risky = false;
        let mut loads = false;
        let mut parses = false;
        for (letter, given) in short_options(args, PFCTL_VALUED) {
            risky |= match (letter, given) {
                ('d', _) => true,
                ('F', Given::Attached(modifier)) => flushes(modifier),
                ('F', Given::Next(modifier)) => modifier.known().is_none_or(flushes),
                _ => false,
            };
            loads |= letter == 'f';
            parses |= letter == 'n';
        }
        if risky {
            self.add(Rule::SystemSettings, "changes the firewall", None);
        } else if loads && !parses {
            self.add(Rule::SystemSettings, firewall::REPLACES, None);
        } else if unknown_option(args, |text| takes_value(text, PFCTL_VALUED, &[])) {
            self.add(Rule::SystemSettings, FIREWALL_UNKNOWN, None);
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
        } else if unknown_option(args, socketfilterfw_valued) {
            self.add(Rule::SystemSettings, FIREWALL_UNKNOWN, None);
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
        // An argument only known when it runs may be `--system`, after
        // `--user`.
        if user && !walk.unknown {
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
                // `kill` sends SIGTERM unless told otherwise, which ends a
                // daemon as `stop` does.
                "stop" | "kill" => {
                    let verb = if sub == "kill" { "kills" } else { "stops" };
                    for unit in units {
                        self.stop_service(verb, unit);
                    }
                }
                // `isolate` starts the target and stops every unit it does
                // not want; a target that shuts the computer down or leaves
                // a rescue shell stops the system as `systemctl poweroff`
                // and `rescue` do.
                // Without a target it is an error.
                "isolate" => {
                    let Some(target) = words.get(1).copied() else {
                        return;
                    };
                    let target = Some(target);
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
                        let protecting = unit.known().is_none_or(may_protect);
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
    /// needs (`systemd-logind`), and a unit the sessions or systemd run in
    /// (`user.slice`, `session-3.scope`), end what they serve, and stopping
    /// one that protects the machine, a slice that holds every system
    /// service (`system.slice`), or one only known when it runs, turns that
    /// protection off. A pattern (`firewall*`, `*.slice`, `/etc/service/*`)
    /// is tested against the names of them all: `systemctl` matches it
    /// against the loaded units, and the shell expands it against the
    /// files. Any other is everyday work (`docker*`).
    fn stop_service(&mut self, verb: &str, unit: &Arg) {
        match unit.known() {
            Some(name) if is_pattern(name) => {
                if unit_pattern_matches(name, &PROTECTORS)
                    || unit_pattern_matches(name, &SYSTEM_SLICES)
                {
                    self.add(
                        Rule::SystemSettings,
                        format!("{verb} services that may protect the system"),
                        Some(unit),
                    );
                } else if unit_pattern_stops_system(name)
                    || unit_pattern_matches(name, &SESSION_UNITS)
                {
                    self.add(
                        Rule::StopSystem,
                        format!("{verb} services the system may need"),
                        Some(unit),
                    );
                }
            }
            Some(name) if holds_system(name) => self.add(
                Rule::SystemSettings,
                format!("{verb} every system service"),
                Some(unit),
            ),
            Some(name) if holds_sessions(name) => self.add(
                Rule::StopSystem,
                format!("{verb} what the system or a session runs in"),
                Some(unit),
            ),
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

    /// A script a shell runs (`sh /etc/init.d/ufw stop`, `bash -x …`) or the
    /// line sources (`. /etc/init.d/ufw stop`, `source …`) is read as the
    /// script run as the program: the operands after it are its own.
    fn shell_runs_init_script(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        let sourced = unit.shell == Shell::Posix && matches!(key, "source" | ".");
        if !sourced && !SHELLS.contains(&key) {
            return;
        }
        let Some(script) = script_operand(key, args) else {
            return;
        };
        let Some(at) = args.iter().position(|arg| std::ptr::eq(arg, script)) else {
            return;
        };
        // `-c` runs its operand as a line of its own, which is read as one,
        // and no script.
        if !has_flag(&args[..at], Some('c'), None) {
            // A shell reads a script named without a folder from the
            // working folder; `.` and `source` look it up on `PATH` first.
            self.init_script(unit, script, &args[at + 1..], !sourced);
        }
    }

    /// A program run from an init script folder (`/etc/init.d/ufw stop`,
    /// `/etc/rc.d/pf stop`) is the service of its name, and its first
    /// operand the action, as `service ufw stop`. The program is placed
    /// where it lands, so `cd /etc/init.d && ./ufw stop` is the same.
    /// `bare` says a name without a folder is a file in the working folder,
    /// as it is to a shell given a script.
    fn init_script(&mut self, unit: &Unit, program: &Arg, args: &[Arg], bare: bool) {
        let Some(text) = program.known() else {
            return;
        };
        // A program named without a folder is looked up on `PATH`, never
        // here.
        if !bare && !text.contains('/') {
            return;
        }
        let Some(key) = self
            .resolver
            .file_key(unit.dir.as_ref(), program, unit.shell)
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
        let words = operands(args, &[]);
        let Some(action) = words.first() else {
            return;
        };
        if action.known().is_none_or(stops) {
            self.stop_service("stops", &Arg::Known(name.to_string()));
        }
    }

    /// `rc-service name command`, `OpenRC`'s `service`. `-e` and `-r` take a
    /// service name. `-U` (`--user`) runs the user's own services, as
    /// `systemctl --user` does.
    fn rc_service(&mut self, args: &[Arg]) {
        if has_flag(args, Some('U'), Some("user")) {
            return;
        }
        let words = operands(args, &["-e", "--exists", "-r", "--resolve"]);
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

    /// `chkconfig name off` and `chkconfig --del name` (`-d` on SUSE) take a
    /// service out of what starts at boot; `--level` takes the runlevels.
    fn chkconfig(&mut self, args: &[Arg]) {
        let words = operands(args, &["--level"]);
        if has_long(args, "del", 3) || has_flag(args, Some('d'), None) {
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
        // `config system|user KEY VALUE` sets what launchd starts every
        // service with, for good.
        if sub == "config" {
            if !rest.is_empty() {
                self.add(
                    Rule::SystemSettings,
                    "changes how the system starts services",
                    None,
                );
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
            // The first operand is the domain: `system`, `gui/501`. One only
            // known when it runs is a user's when its known start says so
            // (`gui/$UID`).
            "bootout" => {
                let system = rest.first().is_none_or(|domain| {
                    domain.known().map_or_else(
                        || {
                            let start = literal_start(domain);
                            !(start.starts_with("gui/") || start.starts_with("user/"))
                        },
                        |text| text.starts_with("system"),
                    )
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
        // A domain given as a path in the workspace is a file of the
        // workspace's own (`defaults delete ./Info.plist`).
        let own_file = !domain_option
            && rest.first().is_some_and(|domain| {
                domain.known().is_some_and(|text| text.contains('/'))
                    && self
                        .place(unit.shell, unit.scope(), domain, Access::Item)
                        .harmless()
            });
        if own_file {
            return;
        }
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
        if let Some(reason) = protecting_default(&verb, rest) {
            self.add(Rule::SystemSettings, reason, rest.first().copied());
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
    /// `valued` says whether an option, as written, takes the next argument
    /// as its value.
    fn set_options(&mut self, args: &[Arg], valued: impl Fn(&str) -> bool) {
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
        // Each setting is an option, followed by its values.
        let reason = "changes system or network settings";
        if sets {
            self.add(Rule::SystemSettings, reason, None);
        } else if unknown_option(args, valued) {
            self.add(Rule::SystemSettings, hedged(reason), None);
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

    /// `apparmor_parser -R` removes a profile and `-C` loads it in complain
    /// mode, where it no longer enforces anything.
    fn apparmor_parser(&mut self, args: &[Arg]) {
        let off = short_options(args, APPARMOR_SHORT)
            .iter()
            .any(|(letter, _)| matches!(letter, 'R' | 'C'))
            || has_long(args, "remove", 3)
            || has_long(args, "complain", 5);
        if off {
            self.add(Rule::SystemSettings, "turns off an AppArmor profile", None);
        } else if unknown_option(args, |text| {
            takes_value(text, APPARMOR_SHORT, &APPARMOR_LONG)
        }) {
            self.add(Rule::SystemSettings, hedged("changes AppArmor"), None);
        }
    }

    /// `auditctl -D` deletes every audit rule, `-e` with anything but `1`
    /// (on) or `2` (on and locked) turns auditing off, and so does a rule
    /// `-a` or `-A` adds whose action is `never` or whose list is `exclude`
    /// (`-a never,task`, `-a always,exclude -F msgtype=SYSCALL`). `-d` and
    /// `-W` delete a rule or a watch, and `-R` loads rules from a file the
    /// line does not show, which may delete them all.
    fn auditctl(&mut self, args: &[Arg]) {
        let keeps_on = |mode: &str| matches!(mode, "1" | "2");
        // The action and list of a rule, in either order (`exit,never`).
        let silences = |rule: &str| {
            rule.split(',').any(|part| {
                part.eq_ignore_ascii_case("never") || part.eq_ignore_ascii_case("exclude")
            })
        };
        let mut off = false;
        let mut deletes = false;
        let mut loads = false;
        for (letter, given) in short_options(args, AUDITCTL_VALUED) {
            let value = match given {
                Given::Nothing => None,
                Given::Attached(text) => Some(Some(text)),
                Given::Next(arg) => Some(arg.known()),
            };
            match (letter, value) {
                ('D', _) => off = true,
                ('e', Some(mode)) => off |= mode.is_none_or(|mode| !keeps_on(mode)),
                ('a' | 'A', Some(rule)) => off |= rule.is_none_or(silences),
                ('d' | 'W', _) => deletes = true,
                ('R', _) => loads = true,
                _ => {}
            }
        }
        let reason = if off {
            "turns off auditing"
        } else if loads {
            "replaces the audit rules"
        } else if deletes {
            "changes the audit rules"
        } else if unknown_option(args, |text| takes_value(text, AUDITCTL_VALUED, &[])) {
            self.add(Rule::SystemSettings, hedged("changes auditing"), None);
            return;
        } else {
            return;
        };
        self.add(Rule::SystemSettings, reason, None);
    }

    /// `semanage`: a subcommand that adds, deletes or modifies a piece of
    /// `SELinux`'s policy (`permissive -a`, `boolean -m`, `module -r`), and
    /// `import`, change it; listing and `export` do not. A word only known
    /// when it runs may be any of them.
    fn semanage(&mut self, args: &[Arg]) {
        let Some(first) = args.first() else { return };
        let changes = match first.known().map(str::to_ascii_lowercase) {
            None => true,
            // `-i FILE` (`--input`) is the older spelling of `import`.
            Some(sub) if sub == "import" || sub == "-i" || is_long_of(&sub, "input", 3) => true,
            Some(sub) if sub == "export" || sub.starts_with('-') => false,
            Some(sub) => {
                let module = sub == "module";
                let (letters, longs, valued): (&str, &[&str], &str) = if module {
                    ("ard", &["add", "remove", "disable"], "")
                } else {
                    (
                        "admD",
                        &["add", "delete", "modify", "deleteall"],
                        SEMANAGE_VALUED,
                    )
                };
                let rest = &args[1..];
                short_options(rest, valued)
                    .iter()
                    .any(|(letter, _)| letters.contains(*letter))
                    || long_names(rest)
                        .any(|name| longs.iter().any(|full| is_option(name, full, 3)))
            }
        };
        if changes || args.iter().any(|arg| arg.known().is_none()) {
            self.add(Rule::SystemSettings, SELINUX_CHANGES, None);
        }
    }

    /// `sysctl` sets a kernel setting with `-w` or a `name=value` operand,
    /// and loads them from a file with `-p` (`-f` on the BSDs) or
    /// `--system`; a name alone reads it.
    fn sysctl(&mut self, args: &[Arg]) {
        let walk = getopt_walk(args, "r", &["pattern"]);
        let writes = short_options(args, "r")
            .iter()
            .any(|(letter, _)| matches!(letter, 'w' | 'p' | 'f'))
            || walk.longs.iter().any(|name| {
                is_option(name, "write", 2)
                    || is_option(name, "load", 2)
                    || is_option(name, "system", 2)
            })
            || walk
                .operands
                .iter()
                .any(|arg| arg.known().is_none_or(|text| text.contains('=')));
        if writes {
            self.add(Rule::SystemSettings, "changes kernel settings", None);
        }
    }

    /// `grubby` reads the boot entries with `--info` and the `--default-…`
    /// options; any other option changes them (`--update-kernel ALL --args
    /// selinux=0`, `--set-default`).
    fn grubby(&mut self, args: &[Arg]) {
        let mut iter = args.iter();
        let mut reads = true;
        while let Some(arg) = iter.next() {
            match arg.known() {
                Some("--info") => {
                    iter.next();
                }
                Some(text) => {
                    let name = text.split('=').next().unwrap_or(text);
                    reads &= matches!(
                        name,
                        "--info"
                            | "--default-kernel"
                            | "--default-index"
                            | "--default-title"
                            | "--bootloader-probe"
                            | "--help"
                            | "--usage"
                            | "--version"
                            | "-h"
                            | "-?"
                    );
                }
                None => reads = false,
            }
        }
        if !reads {
            self.add(Rule::SystemSettings, BOOT_CHANGES, None);
        }
    }

    /// `efibootmgr` lists the boot entries, alone or with `-v` or `-q`; any
    /// other option changes them (`-B` deletes one, `-o` the order, `-n`
    /// the next).
    fn efibootmgr(&mut self, args: &[Arg]) {
        let reads = args.iter().all(|arg| {
            arg.known().is_some_and(|text| {
                matches!(text, "--verbose" | "--quiet" | "--version" | "--help")
                    || text.strip_prefix('-').is_some_and(|bundle| {
                        !bundle.is_empty() && bundle.chars().all(|c| "vqVh".contains(c))
                    })
            })
        });
        if !reads {
            self.add(Rule::SystemSettings, BOOT_CHANGES, None);
        }
    }

    /// `semodule` installs, upgrades, enables, disables and removes the
    /// modules of `SELinux`'s policy (`-r`, as `semanage module -r` runs
    /// it); listing them does not. An option only known when it runs may
    /// be any of them.
    fn semodule(&mut self, args: &[Arg]) {
        // The short options that take a value; `-l` takes one only in its
        // bundle (`-lfull`).
        const VALUED: &str = "sbiruXedpSE";
        const LONGS: [&str; 11] = [
            "store",
            "base",
            "install",
            "remove",
            "upgrade",
            "priority",
            "enable",
            "disable",
            "path",
            "store-path",
            "extract",
        ];
        const CHANGES: [&str; 5] = ["install", "upgrade", "remove", "disable", "enable"];
        let named = args
            .iter()
            .filter_map(Arg::known)
            .take_while(|text| *text != "--")
            .any(|text| match text.strip_prefix("--") {
                Some(name) => {
                    let name = name.split('=').next().unwrap_or(name);
                    CHANGES.iter().any(|full| is_option(name, full, 3))
                }
                None => text.strip_prefix('-').is_some_and(|bundle| {
                    bundle
                        .chars()
                        .take_while(|letter| *letter != 'l')
                        .scan(false, |valued, letter| {
                            // The rest of a bundle after a letter that
                            // takes a value is that value.
                            let read = (!*valued).then_some(letter);
                            *valued |= VALUED.contains(letter);
                            read
                        })
                        .any(|letter| "iurde".contains(letter))
                }),
            });
        if named {
            self.add(Rule::SystemSettings, SELINUX_CHANGES, None);
        } else if unknown_option(args, |text| takes_value(text, VALUED, &LONGS)) {
            self.add(Rule::SystemSettings, hedged(SELINUX_CHANGES), None);
        }
    }

    /// `grub-editenv FILE set NAME=VALUE` (and `unset`) changes the boot
    /// loader's variables, the entry it starts next (`next_entry`, what
    /// `grub-reboot` sets) or always (`saved_entry`) among them; `list` and
    /// `create` do not. A command only known when it runs may be `set`.
    fn grub_editenv(&mut self, args: &[Arg]) {
        let words = operands(args, &[]);
        let sets = words.get(1).is_some_and(|command| {
            command
                .known()
                .is_none_or(|text| matches!(text.to_ascii_lowercase().as_str(), "set" | "unset"))
        });
        if sets {
            self.add(Rule::SystemSettings, BOOT_CHANGES, None);
        }
    }

    /// `bootctl` installs, updates and removes the boot loader, and sets
    /// the entry the computer starts always or next; `status` and `list`
    /// read. A command only known when it runs may be any of them.
    fn bootctl(&mut self, args: &[Arg]) {
        const LONGS: [&str; 12] = [
            "esp-path",
            "boot-path",
            "root",
            "image",
            "image-policy",
            "install-source",
            "efi-boot-option-description",
            "make-entry-directory",
            "entry-token",
            "random-seed",
            "variables",
            "json",
        ];
        let words = getopt_operands(args, "", &LONGS);
        let changes = match first_word(&words) {
            Word::Missing => false,
            Word::Unknown => true,
            Word::Is(command) => matches!(
                command.as_str(),
                "install"
                    | "update"
                    | "remove"
                    | "set-default"
                    | "set-oneshot"
                    | "unlink"
                    | "cleanup"
            ),
        };
        if changes {
            self.add(Rule::SystemSettings, BOOT_CHANGES, None);
        }
    }
}

/// The reason for a protecting key `defaults` changes, when `verb` (`write`,
/// `delete`, `rename`) with the operands after it, `rest`, changes one: the
/// key is named, only known when it runs, or (a `write` of the domain's
/// whole content) left out. The domain may be a path to its file.
fn protecting_default(verb: &str, rest: &[&Arg]) -> Option<&'static str> {
    let domain = rest.first()?.known()?;
    let name = domain.trim_end_matches('/');
    let name = name.rsplit('/').next().unwrap_or(name);
    let name = name
        .len()
        .checked_sub(".plist".len())
        .filter(|&at| name.is_char_boundary(at) && name[at..].eq_ignore_ascii_case(".plist"))
        .map_or(name, |at| &name[..at]);
    let whole = verb == "write" && rest.len() == 2;
    PROTECTING_DEFAULTS
        .iter()
        .find(|(known, key, _)| {
            known.eq_ignore_ascii_case(name)
                && (whole
                    || rest.get(1).is_some_and(|arg| {
                        arg.known()
                            .is_none_or(|text| text.eq_ignore_ascii_case(key))
                    }))
        })
        .map(|(_, _, reason)| *reason)
}

/// The text an argument starts with that is the same however it expands:
/// all of a known one, and of one only known when it runs, what comes
/// before its first expansion, quote or wildcard (`gui/` of `gui/$UID`).
fn literal_start(arg: &Arg) -> &str {
    let text = match arg {
        Arg::Template { text, .. } => text.as_str(),
        _ => arg.text(),
    };
    let end = text
        .find(['$', '`', '"', '\'', '\\', '%', '(', '{', '*', '?', '[', '~'])
        .unwrap_or(text.len());
    &text[..end]
}
