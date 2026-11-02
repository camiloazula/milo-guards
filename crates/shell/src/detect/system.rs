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
            "tskill" => self.tskill(args, shell),
            "stop-process" => self.stop_process(unit),
            "invoke-cimmethod" | "invoke-wmimethod" => self.wmi_method(args),
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
                // `process` is the alias of the class `path win32_process`
                // (and of its base class `cim_process`) names.
                let process = key == "wmic"
                    && (words.iter().any(|word| word == "process")
                        || words.windows(2).any(|pair| {
                            pair[0] == "path"
                                && matches!(pair[1].as_str(), "win32_process" | "cim_process")
                        }));
                // `wmic process call create "cmdline"` starts a program.
                if process && words.iter().any(|word| word == "create") {
                    self.add(Rule::Unknown, "starts a program through wmic", None);
                }
                // `wmic process … call terminate` and `… delete` stop them.
                if process {
                    self.wmic_process(args, shell);
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
    /// process, and a line that is plainly signal 0 (which sends nothing:
    /// `kill -0 $pid` asks whether a process is there) are everyday work.
    fn kill(&mut self, args: &[Arg]) {
        // The `kill` program reorders its words and reads a signal option
        // after an id, so how a line is read is not modelled: it is signal 0
        // only in the one plain shape below, and every other line is judged
        // by its ids.
        if is_plain_signal_zero(args) {
            return;
        }
        let mut rest = args;
        // The options are read as the shell's own loop reads them: `-s SIG`,
        // `-n SIG`, `-sNAME` and `-nNUM` at any point, and a bare `-SIG`
        // while no signal is named yet; a later bare one, `--`, or any other
        // word ends them.
        let mut named = false;
        while let Some(text) = rest.first().and_then(Arg::known) {
            let mut used = 1;
            if matches!(text, "-s" | "-n") {
                used = 2;
            } else if text == "--" || text.len() < 2 || !text.starts_with('-') {
                break;
            } else if text.starts_with("--") {
                // `--list` names signals, but only as the first word; later
                // it is read like any other long option. A long option has
                // its value, a name or a number, which is not read as an id
                // either way.
                if text == "--list" && rest.len() == args.len() {
                    return;
                }
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
                let attached = name.starts_with('s')
                    || (name.starts_with('n')
                        && name[1..].starts_with(|c: char| c.is_ascii_digit()));
                if !attached {
                    // `-sNAME`, `-nNUM` are signals; anything else is a bare
                    // one.
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
                }
            }
            named = true;
            rest = rest.get(used..).unwrap_or_default();
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
                        Rule::StopUnknown,
                        "may stop a whole process group",
                        Some(arg),
                    ),
                    // A word, which `kill` refuses; a pattern may expand to
                    // an id.
                    None if text.contains(['*', '?', '[', '{']) => self.add(
                        Rule::StopUnknown,
                        "may stop a whole process group",
                        Some(arg),
                    ),
                    None => {}
                },
                None if is_positive_expansion(arg.text()) => {}
                None => self.add(
                    Rule::StopUnknown,
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

/// Whether a `kill` line is plainly signal 0, which sends nothing. The first
/// word after `kill` is exactly `-0`, `-s 0`, `-n 0` or `--signal=0`, and every
/// word after it is a literal positive decimal id, a job (`%1`), `$!`, `$$`,
/// `$PPID`, or a plain variable (`$pid`, `"$pid"`). No other option, no `--`,
/// no brace list, wildcard or substitution and no dash anywhere else is read:
/// the `kill` program reorders its words and reads a signal option after an
/// id, so any other line is judged by its ids.
fn is_plain_signal_zero(args: &[Arg]) -> bool {
    let after = match args.first().and_then(Arg::known) {
        Some("-0" | "--signal=0") => 1,
        Some("-s" | "-n") if args.get(1).and_then(Arg::known) == Some("0") => 2,
        _ => return false,
    };
    args[after..].iter().all(|arg| match arg.known() {
        Some(text) => is_plain_id(text),
        None => is_plain_variable(arg.text()),
    })
}

/// Whether `text` is a literal positive decimal id or a job such as `%1`.
fn is_plain_id(text: &str) -> bool {
    match text.strip_prefix('%') {
        Some(job) => {
            !job.is_empty()
                && job
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'%' | b'+' | b'_'))
        }
        None => {
            text.bytes().all(|b| b.is_ascii_digit())
                && matches!(process_id(text), Some(Id::Process(_)))
        }
    }
}

/// Whether `text` is `$!`, `$$` or a plain variable such as `$pid`, quoted or
/// not.
fn is_plain_variable(text: &str) -> bool {
    let text = text.trim_matches(['"', '\'']);
    if is_positive_expansion(text) {
        return true;
    }
    let name = text
        .strip_prefix("${")
        .and_then(|name| name.strip_suffix('}'))
        .or_else(|| text.strip_prefix('$'));
    name.is_some_and(|name| {
        name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
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
