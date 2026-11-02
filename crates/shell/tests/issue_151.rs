//! A stop the guard cannot read for sure has its own rule. `stop_system` is
//! for a stop that is certain (process 0, a group, process 1, a system
//! process by name, a shutdown); `stop_unknown` is for an id, a name, a
//! listing, a substitution or an object it cannot follow, which may be any
//! process. Only the rule a finding carries changed: no line moved between
//! safe and risky.

mod common;

use common::{check, check_effect, posix, rules, windows};
use milo_guards_shell::{Effect, Paths, Rule, Shell};

/// Every `lines` row breaks `has` and does not break `lacks`; the rows that
/// do not are named together.
fn only(shell: Shell, paths: &Paths, has: Rule, lacks: Rule, lines: &[&str]) {
    let wrong: Vec<String> = lines
        .iter()
        .filter_map(|line| {
            let found = rules(line, shell, paths);
            (!found.contains(&has) || found.contains(&lacks))
                .then(|| format!("expected {has:?} without {lacks:?}: {line}\n    got {found:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Every `lines` row breaks both rules.
fn both(shell: Shell, paths: &Paths, lines: &[&str]) {
    let wrong: Vec<String> = lines
        .iter()
        .filter_map(|line| {
            let found = rules(line, shell, paths);
            (!found.contains(&Rule::StopSystem) || !found.contains(&Rule::StopUnknown))
                .then(|| format!("expected both rules: {line}\n    got {found:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn the_rule_is_named_beside_stop_system() {
    assert_eq!(Rule::StopUnknown.name(), "stop_unknown");
    let at = |rule: Rule| Rule::ALL.iter().position(|&listed| listed == rule);
    assert_eq!(
        at(Rule::StopUnknown),
        at(Rule::StopSystem).map(|position| position + 1)
    );
}

#[test]
fn an_id_a_listing_or_a_substitution_the_guard_cannot_read_is_stop_unknown() {
    only(
        Shell::Posix,
        &posix(),
        Rule::StopUnknown,
        Rule::StopSystem,
        &[
            "kill $pid",
            "kill $(lsof -ti:3000)",
            "pgrep node | xargs kill",
            "lsof -ti:3000 | xargs kill -9",
            "xargs kill",
            "kill -9 $(pgrep node)",
            "kill \"$(cat app.pid)\"",
            "sudo kill $pid",
            "kill 99999999999999999999",
            "kill 4294967296",
            "kill '*'",
            "kill 12*",
            "kill {1,2}",
            "kill -s KILL $pid",
            "kill -9 $pid",
            // The group of a process the line names with a variable: the
            // guard cannot say it is the caller's own.
            "kill -- -$$",
            "kill -9 -$$",
            "kill -- -$PPID",
        ],
    );
}

#[test]
fn a_name_the_guard_cannot_read_is_stop_unknown() {
    only(
        Shell::Posix,
        &posix(),
        Rule::StopUnknown,
        Rule::StopSystem,
        &[
            "killall $NAME",
            "pkill \"$PATTERN\"",
            "xargs pkill",
            "launchctl stop $label",
            "launchctl kill TERM $target",
        ],
    );
}

#[test]
fn a_certain_stop_stays_stop_system() {
    only(
        Shell::Posix,
        &posix(),
        Rule::StopSystem,
        Rule::StopUnknown,
        &[
            "kill 0",
            "kill -9 0",
            "kill -9 -1234",
            "kill -- -1",
            "kill -- -1234",
            "kill -s KILL -1",
            "kill 1",
            "kill -9 1",
            "trap 'kill 0' INT",
            "bash -c 'kill -9 0'",
            "sudo kill -9 0",
            "pkill loginwindow",
            "killall loginwindow",
            "killall WindowServer",
            "pkill -v node",
            "pkill -u me",
            "pkill -f .",
            "pkill '.*'",
            "killall5",
            "shutdown now",
            "systemctl stop systemd-logind",
            "launchctl kill TERM system/com.apple.WindowServer",
            ":(){ :|:& };:",
        ],
    );
}

#[test]
fn a_line_with_a_certain_stop_and_an_unknown_one_has_both_rules() {
    both(
        Shell::Posix,
        &posix(),
        &[
            "kill 0; kill $pid",
            "kill $pid 0",
            "kill $pid -1",
            "pkill loginwindow; pkill $NAME",
            "kill $(pgrep node) 1",
        ],
    );
    both(
        Shell::PowerShell,
        &windows(),
        &[
            "Stop-Process -Id 0; Stop-Process -Id $id",
            "Stop-Process -Name explorer; Stop-Process -Id $id",
        ],
    );
}

#[test]
fn a_powershell_stop_the_guard_cannot_read_is_stop_unknown() {
    only(
        Shell::PowerShell,
        &windows(),
        Rule::StopUnknown,
        Rule::StopSystem,
        &[
            "Stop-Process -Id $id",
            "Stop-Process -InputObject $p",
            "Stop-Process -Name $n",
            "Stop-Process -Id (Get-Content app.pid)",
            "Stop-Process -Id (Get-NetTCPConnection -LocalPort 3000).OwningProcess",
            "kill $id",
            "taskkill /F /PID $id",
            "taskkill /IM $n",
            "taskkill /F /FI \"PID eq $id\"",
            "tskill $n",
            "$p.Kill()",
            "(Get-Process node).Parent.Kill()",
            "Get-Process | Where-Object CPU -gt 100 | Stop-Process",
            "Get-Process | Select-Object -First 1 | Stop-Process",
            "Get-Process | Where-Object { $_.Name -notmatch 'node' } | Stop-Process",
            "Get-Process | Where-Object { $_.Name -match $p } | Stop-Process",
            "Get-Process | Where-Object { $_.Name -match '^(?!node)' } | Stop-Process",
            "Stop-Process -InputObject (Get-Process node).Parent",
            "Invoke-CimMethod -MethodName Terminate",
            "wmic process where name=$n call terminate",
            "wmic process where name like 'n%' call terminate",
        ],
    );
}

#[test]
fn a_cmd_stop_the_guard_cannot_read_is_stop_unknown() {
    only(
        Shell::Cmd,
        &windows(),
        Rule::StopUnknown,
        Rule::StopSystem,
        &["tskill %n%", "tskill %id% /a", "taskkill /PID %p%"],
    );
}

#[test]
fn a_certain_powershell_or_cmd_stop_stays_stop_system() {
    only(
        Shell::PowerShell,
        &windows(),
        Rule::StopSystem,
        Rule::StopUnknown,
        &[
            "Stop-Process -Id 0",
            "Stop-Process -Id 1",
            "Stop-Process -Name explorer",
            "Stop-Process -Name *",
            "Get-Process | Stop-Process",
            "Get-Process | Where-Object { $_.Name -match 'explorer' } | Stop-Process",
            "Get-Process | Where-Object { $_.Name -match '.*' } | Stop-Process",
            "taskkill /IM *",
            "taskkill /PID 1",
            "taskkill /IM explorer.exe",
            "taskkill /F /FI \"USERNAME eq me\"",
            "taskkill /F /FI \"STATUS eq RUNNING\"",
            "tskill explorer",
            "tskill 0",
            "wmic process call terminate",
            "wmic process where name=\"explorer.exe\" call terminate",
        ],
    );
    only(
        Shell::Cmd,
        &windows(),
        Rule::StopSystem,
        Rule::StopUnknown,
        &["taskkill /IM *", "taskkill /PID 1", "tskill explorer"],
    );
}

#[test]
fn no_line_changed_between_safe_and_risky() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "kill 1234",
            "kill 4242",
            "kill %1",
            "kill -0 $pid",
            "kill -0 4242",
            "kill -l",
            "killall node",
            "pkill node",
            "pgrep node",
        ],
        &[
            ("kill $pid", Rule::StopUnknown),
            ("kill $(lsof -ti:3000)", Rule::StopUnknown),
            ("pgrep node | xargs kill", Rule::StopUnknown),
            ("lsof -ti:3000 | xargs kill -9", Rule::StopUnknown),
            ("kill 0", Rule::StopSystem),
            ("kill -9 -1234", Rule::StopSystem),
            ("kill -- -1", Rule::StopSystem),
            ("trap 'kill 0' INT", Rule::StopSystem),
            ("pkill loginwindow", Rule::StopSystem),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Stop-Process -Id 1234",
            "Stop-Process -Name node",
            "taskkill /PID 1234",
            "Get-Process node | Stop-Process",
            "(Get-Process node).Kill()",
        ],
        &[
            ("Stop-Process -Id $id", Rule::StopUnknown),
            ("Stop-Process -Id 0", Rule::StopSystem),
        ],
    );
}

#[test]
fn a_stop_the_guard_cannot_read_still_changes_the_machine() {
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::Changes,
        &[
            "kill $pid",
            "kill $(lsof -ti:3000)",
            "pgrep node | xargs kill",
            "lsof -ti:3000 | xargs kill -9",
        ],
    );
}
