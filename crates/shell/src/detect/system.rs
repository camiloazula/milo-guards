//! The rules about the system: disks, permissions, stopping it, and its
//! settings (Windows, services, scheduled jobs, accounts, the firewall).

use super::Checker;
use crate::powershell::Params;
use crate::unit::{has_flag, has_switch, operands, plain, Arg, Unit};
use crate::{Rule, Shell};

impl Checker<'_> {
    /// Disks, permissions, stopping the system and its settings.
    pub(super) fn system(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        let shell = unit.shell;
        match key {
            // Disks.
            key if DISK_TOOLS.contains(&key)
                || key.starts_with("mkfs")
                || key.starts_with("newfs") =>
            {
                let listing = matches!(key, "fdisk" | "sfdisk" | "parted" | "gdisk")
                    && has_flag(args, Some('l'), Some("list"));
                if !listing {
                    self.add(Rule::WipeDisk, "formats or repartitions a disk", None);
                }
            }
            "format" if shell != Shell::Posix => {
                self.add(
                    Rule::WipeDisk,
                    "formats a disk",
                    plain(args).first().copied(),
                );
            }
            "diskutil" => self.diskutil(args),

            // Permissions.
            "chmod" => self.chmod(unit),
            "chown" | "chgrp" => {
                let (_, targets) = owner_and_targets(args);
                self.permissions(unit, &targets, "changes the owner of");
            }
            "icacls" | "cacls" => {
                if let Some(target) = plain(args).first() {
                    let everyone = args.iter().filter_map(Arg::known).any(|text| {
                        let lower = text.to_ascii_lowercase();
                        (lower.contains("everyone:") || lower.contains("*s-1-1-0:"))
                            && ["(f)", "(m)", "(w)"]
                                .iter()
                                .any(|right| lower.contains(right))
                    });
                    if everyone {
                        self.add(Rule::Permissions, "lets everyone change it", Some(target));
                    }
                    self.permissions(unit, &[target], "changes permissions of");
                }
            }
            "takeown" => {
                if let Some(target) = value_after(args, &["/f", "/F"]) {
                    self.permissions(unit, &[target], "takes ownership of");
                }
            }
            "set-acl" => {
                let params = Params::read(args);
                let mut targets = params.values(&["path", "literalpath"]);
                if targets.is_empty() {
                    targets.extend(params.positional.first().copied());
                }
                self.permissions(unit, &targets, "changes permissions of");
            }

            // Stopping the system.
            "kill" if shell == Shell::Posix => self.kill(args),
            "killall5" => self.add(Rule::StopSystem, "stops every process", None),
            "killall" => self.killall(args),
            "pkill" => self.pkill(args),
            "taskkill" => self.taskkill(args),
            "stop-process" => self.stop_process(unit),
            "shutdown" | "reboot" | "halt" | "poweroff" | "stop-computer" | "restart-computer" => {
                let cancels = args.iter().filter_map(Arg::known).any(|text| {
                    matches!(
                        text.to_ascii_lowercase().as_str(),
                        "-c" | "/a" | "-a" | "--help" | "/?" | "-?"
                    )
                });
                if !cancels {
                    self.add(
                        Rule::StopSystem,
                        "shuts the computer down or restarts it",
                        None,
                    );
                }
            }
            "systemctl" => {
                let sub = operands(args, &[])
                    .first()
                    .and_then(|arg| arg.known())
                    .map(str::to_string);
                if matches!(
                    sub.as_deref(),
                    Some("poweroff" | "reboot" | "halt" | "kexec" | "emergency" | "rescue")
                ) {
                    self.add(
                        Rule::StopSystem,
                        "shuts the computer down or restarts it",
                        None,
                    );
                }
            }
            "init" | "telinit" => {
                if args
                    .iter()
                    .any(|arg| matches!(arg.known(), Some("0" | "6" | "1" | "s" | "S")))
                {
                    self.add(
                        Rule::StopSystem,
                        "shuts the computer down or restarts it",
                        None,
                    );
                }
            }
            "launchctl" => {
                if args.first().and_then(Arg::known) == Some("reboot") {
                    self.add(
                        Rule::StopSystem,
                        "shuts the computer down or restarts it",
                        None,
                    );
                }
            }

            // System settings.
            "reg" => {
                let sub = plain(args)
                    .first()
                    .and_then(|arg| arg.known())
                    .map(str::to_ascii_lowercase);
                if matches!(
                    sub.as_deref(),
                    Some("delete" | "add" | "import" | "restore" | "load" | "unload" | "copy")
                ) {
                    self.add(
                        Rule::SystemSettings,
                        "changes the registry",
                        plain(args).get(1).copied(),
                    );
                }
            }
            "bcdedit" => {
                let reads = args.iter().filter_map(Arg::known).all(|text| {
                    matches!(
                        text.to_ascii_lowercase().as_str(),
                        "/enum" | "/v" | "/?" | "all" | "active"
                    )
                });
                if !reads {
                    self.add(
                        Rule::SystemSettings,
                        "changes how the computer starts",
                        None,
                    );
                }
            }
            "vssadmin" | "wbadmin" | "wmic" => {
                let words = lower_words(args);
                let deletes = words
                    .iter()
                    .any(|word| word == "delete" || word == "resize");
                let shadow = key != "wmic" || words.iter().any(|word| word == "shadowcopy");
                if deletes && shadow {
                    self.add(
                        Rule::SystemSettings,
                        "deletes the system's restore points or backups",
                        None,
                    );
                }
                // `wmic process call create "cmdline"` starts a program.
                if key == "wmic"
                    && words.iter().any(|word| word == "process")
                    && words.iter().any(|word| word == "create")
                {
                    self.add(Rule::Unknown, "starts a program through wmic", None);
                }
            }
            "net" | "net1" => {
                let words = lower_words(args);
                let accounts = words.first().is_some_and(|sub| {
                    matches!(sub.as_str(), "user" | "localgroup" | "group" | "accounts")
                });
                if accounts
                    && words
                        .iter()
                        .any(|word| word == "/add" || word == "/delete" || word == "/del")
                {
                    self.add(
                        Rule::SystemSettings,
                        "changes user accounts or groups",
                        None,
                    );
                }
            }
            "netsh" => {
                let words = lower_words(args);
                let firewall = words.iter().any(|word| word.contains("firewall"));
                if firewall
                    && words
                        .iter()
                        .any(|word| matches!(word.as_str(), "off" | "disable" | "reset" | "delete"))
                {
                    self.add(Rule::SystemSettings, "changes the firewall", None);
                }
            }
            "sc" if shell != Shell::PowerShell => {
                let sub = plain(args)
                    .first()
                    .and_then(|arg| arg.known())
                    .map(str::to_ascii_lowercase);
                if matches!(sub.as_deref(), Some("delete" | "config" | "create")) {
                    self.add(
                        Rule::SystemSettings,
                        "changes a system service",
                        plain(args).get(1).copied(),
                    );
                }
            }
            "setx" if has_switch(args, "m") => {
                self.add(
                    Rule::SystemSettings,
                    "changes environment variables for every user",
                    None,
                );
            }
            "set-executionpolicy" => {
                self.add(
                    Rule::SystemSettings,
                    "changes which scripts PowerShell runs",
                    None,
                );
            }
            "set-mppreference" | "add-mppreference" => {
                self.add(Rule::SystemSettings, "changes antivirus settings", None);
            }
            "schtasks" if shell != Shell::Posix && has_switch(args, "create") => {
                self.add(Rule::SystemSettings, "creates a scheduled task", None);
            }
            "forfiles" if shell != Shell::Posix && has_switch(args, "c") => {
                self.add(Rule::Unknown, "runs a command for each matched file", None);
            }
            "set-netfirewallprofile"
            | "set-netfirewallrule"
            | "disable-netfirewallrule"
            | "remove-netfirewallrule"
            | "new-netfirewallrule" => {
                self.add(Rule::SystemSettings, "changes the firewall", None);
            }
            "add-localgroupmember"
            | "remove-localgroupmember"
            | "new-localuser"
            | "remove-localuser"
            | "set-localuser"
            | "enable-localuser" => {
                self.add(
                    Rule::SystemSettings,
                    "changes user accounts or groups",
                    None,
                );
            }
            "crontab" => {
                if has_flag(args, Some('r'), Some("remove")) {
                    self.add(Rule::Delete, "deletes your scheduled jobs", None);
                } else if let Some(table) = operands(args, &["-u"]).first() {
                    self.add(
                        Rule::SystemSettings,
                        "replaces your scheduled jobs",
                        Some(table),
                    );
                }
            }
            _ => {}
        }
    }

    fn chmod(&mut self, unit: &Unit) {
        let (mode, targets) = owner_and_targets(&unit.args);
        let everyone = mode.and_then(Arg::known).is_some_and(|mode| {
            matches!(mode, "777" | "0777" | "666" | "0666" | "a=rwx" | "o=rwx")
                || mode.split(',').any(|clause| {
                    clause.contains('+')
                        && (clause.starts_with('a') || clause.starts_with('o'))
                        && clause.contains('w')
                })
        });
        if everyone {
            for target in &targets {
                self.add(Rule::Permissions, "lets everyone change it", Some(target));
            }
        }
        self.permissions(unit, &targets, "changes permissions of");
    }

    /// `kill [-s SIG | -n SIG | -SIG] [--] ID...`. A signal to process 0
    /// goes to every process in the caller's own group, the program that ran
    /// the line included, and one to a negative id goes to a whole group
    /// (`-1`: every process). An id only known when it runs may be any of
    /// them, so it is judged the same way. A job (`%1`), an ordinary
    /// process, and signal 0 (which sends nothing: `kill -0 $pid` asks
    /// whether a process is there) are everyday work.
    fn kill(&mut self, args: &[Arg]) {
        let mut rest = args;
        // The options are read as the shell's own loop reads them: `-s SIG`,
        // `-n SIG`, `-sNAME` and `-nNUM` at any point, the last one winning,
        // and a bare `-SIG` while no signal is named yet; a later bare one,
        // `--`, or any other word ends them. So a signal 0 first does not
        // make the line one that sends nothing (`kill -s 0 -s KILL -1`): it
        // does only when every signal read is 0.
        let mut sends = false;
        let mut zero = false;
        let mut named = false;
        while let Some(text) = rest.first().and_then(Arg::known) {
            // The signal this word names; `None` is a signal only known when it
            // runs.
            let signal: Option<&str>;
            let mut used = 1;
            if matches!(text, "-s" | "-n") {
                signal = rest.get(1).and_then(Arg::known);
                used = 2;
            } else if text == "--" || text.len() < 2 || !text.starts_with('-') {
                break;
            } else if text.starts_with("--") {
                // `--list` names signals, but only as the first word; later
                // it is read like any other long option. A long option has
                // its value, a name or a number, which is not read as an id
                // either way, and the programs that take long options read
                // `--signal` among them, so it may send a real signal.
                if text == "--list" && rest.len() == args.len() {
                    return;
                }
                sends = true;
                rest = &rest[1..];
                break;
            } else {
                let name = &text[1..];
                // The listing options count only as the first word; later
                // they are words the shell skips, and the ids are judged.
                if matches!(name, "l" | "L") {
                    if rest.len() == args.len() {
                        return;
                    }
                    break;
                }
                let attached = name.strip_prefix('s').or_else(|| {
                    name.strip_prefix('n')
                        .filter(|n| n.starts_with(|c: char| c.is_ascii_digit()))
                });
                if attached.is_some() {
                    // `-sNAME`, `-nNUM`.
                    signal = attached;
                } else {
                    // A bare signal once one is named, or a number past the
                    // last signal, is not one: an id.
                    let past_signals = name.bytes().all(|b| b.is_ascii_digit())
                        && !is_signal_zero(name)
                        && name
                            .trim_start_matches('0')
                            .parse::<u8>()
                            .map_or(true, |number| number > 64);
                    if named || past_signals {
                        break;
                    }
                    signal = Some(name);
                }
            }
            named = true;
            if signal.is_some_and(is_signal_zero) {
                zero = true;
            } else {
                sends = true;
            }
            rest = rest.get(used..).unwrap_or_default();
        }
        // The words after the options, up to `--`, may still hold a signal
        // option: the `kill` program reorders its words and reads `-s SIG`
        // and `--signal SIG` after an id (`kill -0 4242 -s 9 -1`). A word that
        // is `-s` or starts with it, a long option, or a word only known when
        // it runs with more after it (it may hold `-s`) means the line may
        // send a real signal, so it is not taken as signal 0. Nothing after
        // such a word (`kill -0 $pid`), or one that is always a number
        // (`-$$`), leaves the line as it reads. A negative id right after the
        // options (`kill -0 -1 -s 9`) is signalled with 0 and the program
        // exits, so what follows it is not read.
        let ends_at_negative_id = rest
            .first()
            .and_then(Arg::known)
            .is_some_and(|text| text.len() > 1 && text != "--" && text.starts_with('-'));
        let unread_option = !ends_at_negative_id
            && rest
                .iter()
                .take_while(|arg| arg.known() != Some("--"))
                .enumerate()
                .any(|(index, arg)| {
                    if let Some(text) = arg.known() {
                        text.starts_with("-s") || text.starts_with("--")
                    } else {
                        let text = arg.text();
                        index + 1 < rest.len()
                            && !is_positive_expansion(text.strip_prefix('-').unwrap_or(text))
                    }
                });
        if zero && !sends && !unread_option {
            return;
        }
        if rest.first().and_then(Arg::known) == Some("--") {
            rest = &rest[1..];
        }
        for arg in rest {
            match arg.known() {
                // A job.
                Some(text) if text.starts_with('%') => {}
                Some(text) => match process_id(text) {
                    Some(Id::Process(1)) => {
                        self.add(Rule::StopSystem, "stops the system's first process", None);
                    }
                    Some(Id::Process(_)) => {}
                    Some(Id::Own) => self.add(
                        Rule::StopSystem,
                        "stops every process in its own group",
                        Some(arg),
                    ),
                    Some(Id::All) => self.add(Rule::StopSystem, "stops every process", None),
                    Some(Id::Group) => {
                        self.add(Rule::StopSystem, "stops a whole process group", Some(arg));
                    }
                    Some(Id::Unreadable) => self.add(
                        Rule::StopSystem,
                        "may stop a whole process group",
                        Some(arg),
                    ),
                    // A word, which `kill` refuses; a pattern may expand to
                    // an id.
                    None if text.contains(['*', '?', '[', '{']) => self.add(
                        Rule::StopSystem,
                        "may stop a whole process group",
                        Some(arg),
                    ),
                    None => {}
                },
                None if is_positive_expansion(arg.text()) => {}
                None => self.add(
                    Rule::StopSystem,
                    "may stop a whole process group",
                    Some(arg),
                ),
            }
        }
    }

    fn diskutil(&mut self, args: &[Arg]) {
        let words = lower_words(args);
        let sub = words.first().map(String::as_str).unwrap_or_default();
        let wipes = sub.starts_with("erase")
            || matches!(
                sub,
                "zerodisk"
                    | "randomdisk"
                    | "secureerase"
                    | "partitiondisk"
                    | "reformat"
                    | "splitpartition"
                    | "mergepartitions"
            )
            || (sub == "apfs"
                && words.get(1).is_some_and(|action| {
                    matches!(
                        action.as_str(),
                        "deletecontainer" | "deletevolume" | "erasevolume"
                    )
                }));
        if wipes {
            self.add(Rule::WipeDisk, "formats or repartitions a disk", None);
        }
    }
}

/// Programs that format, repartition or wipe a disk whenever they change
/// anything.
const DISK_TOOLS: [&str; 15] = [
    "mke2fs",
    "mkswap",
    "wipefs",
    "fdisk",
    "sfdisk",
    "gdisk",
    "sgdisk",
    "cfdisk",
    "parted",
    "blkdiscard",
    "diskpart",
    "format-volume",
    "clear-disk",
    "initialize-disk",
    "remove-partition",
];

/// Whether a signal is 0, which sends nothing.
fn is_signal_zero(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b == b'0')
}

/// What a process id of `kill` stands for.
#[derive(Debug, PartialEq, Eq)]
enum Id {
    /// An ordinary process, or the first (`1`).
    Process(u32),
    /// 0: every process in the caller's own group.
    Own,
    /// -1: every process.
    All,
    /// Another negative id: a whole group.
    Group,
    /// A number `kill` may take as 0 or a negative id (past what a process
    /// id holds, it wraps).
    Unreadable,
}

/// The process id `text` is, when it is a number as `kill` reads one: blanks
/// around it and a sign are allowed, and leading zeros are not octal.
fn process_id(text: &str) -> Option<Id> {
    let text = text.trim();
    let (negative, digits) = match text.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let Ok(number) = digits
        .trim_start_matches('0')
        .parse::<u32>()
        .or_else(|error| {
            // All zeros is the number 0; anything else that does not fit is long.
            if digits.bytes().all(|b| b == b'0') {
                Ok(0)
            } else {
                Err(error)
            }
        })
    else {
        return Some(Id::Unreadable);
    };
    Some(match (negative, number) {
        (_, 0) => Id::Own,
        (_, number) if number > i32::MAX as u32 => Id::Unreadable,
        (true, 1) => Id::All,
        (true, _) => Id::Group,
        (false, number) => Id::Process(number),
    })
}

/// Whether an id only known when it runs is always a process: `$!` (the
/// last background job) and `$$`, quoted or not. `$PPID` is not: it is the
/// program that ran the line, usually the caller itself.
fn is_positive_expansion(text: &str) -> bool {
    let text = text.trim_matches(['"', '\'']);
    matches!(text, "$!" | "$$" | "${!}" | "${$}")
}

/// `chmod`/`chown` operands: the mode or owner first, the files after.
/// Their options are a few letters (`-R`, `-f`, `-v`); a mode like `-x`
/// is the mode, not an option.
fn owner_and_targets(args: &[Arg]) -> (Option<&Arg>, Vec<&Arg>) {
    // `--reference=FILE` stands for the mode or owner: every operand is a
    // target.
    if args.iter().any(|arg| {
        arg.known()
            .is_some_and(|text| text.starts_with("--reference"))
    }) {
        let mut targets = Vec::new();
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.known() {
                Some("--reference") => {
                    iter.next();
                }
                Some(text) if text.len() > 1 && text.starts_with('-') => {}
                _ => targets.push(arg),
            }
        }
        return (None, targets);
    }
    let mut iter = args.iter().skip_while(|arg| {
        arg.known().is_some_and(|text| {
            text.starts_with("--")
                || (text.len() > 1
                    && text.starts_with('-')
                    && text[1..].chars().all(|c| "RfvchHLPEi".contains(c)))
        })
    });
    let first = iter.next();
    (first, iter.collect())
}

/// The argument after the first of `names`.
fn value_after<'a>(args: &'a [Arg], names: &[&str]) -> Option<&'a Arg> {
    let at = args
        .iter()
        .position(|arg| arg.known().is_some_and(|text| names.contains(&text)))?;
    args.get(at + 1)
}

/// The known arguments in lower case.
fn lower_words(args: &[Arg]) -> Vec<String> {
    args.iter()
        .filter_map(Arg::known)
        .map(str::to_ascii_lowercase)
        .collect()
}
