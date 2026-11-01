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

    fn kill(&mut self, args: &[Arg]) {
        for (at, arg) in args.iter().enumerate() {
            match arg.known() {
                Some("1") => self.add(Rule::StopSystem, "stops the system's first process", None),
                Some("-1") if at > 0 => self.add(Rule::StopSystem, "stops every process", None),
                _ => {}
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
