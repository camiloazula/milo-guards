//! Stopping processes in PowerShell and cmd. `Stop-Process`, `taskkill`,
//! `tskill`, `wmic`, a method such as `.Kill()` and WMI's `Terminate` stop a
//! process safely only when the guard reads which one for sure: a name that
//! is not the system's, a `Get-Process` listing of those, or an id written
//! out in digits other than 0 and 1. A name, a filter or a listing that picks
//! every process or one the system needs (`explorer`, `svchost`, the
//! compositor, the remote login) is `stop_system`; an id, a variable, another
//! cmdlet's listing, a filter or a `-match` pattern the guard cannot read may
//! be any process and is `stop_unknown`.

mod common;

use common::{check, only, reason, took, windows};
use milo_guards_shell::{classify, Rule, Shell};
use std::time::Duration;

#[test]
fn stopping_a_process_by_name_is_safe_unless_the_system_needs_it() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Stop-Process -Name node",
            "Stop-Process -Name node -Force",
            "Stop-Process -Name node,chrome",
            "Stop-Process -Name 'node*'",
            "stop-process -name NODE",
            "kill -Name node",
            "spps -Name node",
            "Stop-Process -Id 1234",
            "Stop-Process -Id 1234 -Force",
            "Get-Process node | Stop-Process",
            "Get-Process -Name node | Stop-Process -Force",
            "gps node | kill",
            "Get-Process",
            "Get-Process | Format-Table",
            "Stop-Process -Name svc",
        ],
        &[
            ("Stop-Process -Name explorer", Rule::StopSystem),
            ("Stop-Process -Name explorer -Force", Rule::StopSystem),
            ("Stop-Process -Name Explorer.exe", Rule::StopSystem),
            ("Stop-Process -Name csrss", Rule::StopSystem),
            ("Stop-Process -Name winlogon", Rule::StopSystem),
            ("Stop-Process -Name node,explorer", Rule::StopSystem),
            ("Stop-Process -Name explorer,node", Rule::StopSystem),
            ("Stop-Process -Name *", Rule::StopSystem),
            ("Stop-Process -Name '*' -Force", Rule::StopSystem),
            ("Stop-Process -Name ?*", Rule::StopSystem),
            ("Stop-Process -Name '[a-z]*'", Rule::StopSystem),
            ("Stop-Process -Name s*", Rule::StopSystem),
            ("Stop-Process -Name expl*", Rule::StopSystem),
            ("Stop-Process -Name $name", Rule::StopUnknown),
            ("Stop-Process -Name e?plorer", Rule::StopSystem),
            ("Stop-Process -Name 'explore[r]'", Rule::StopSystem),
            ("kill -Name explorer", Rule::StopSystem),
            ("Get-Process | Stop-Process", Rule::StopSystem),
            ("Get-Process | Stop-Process -Force", Rule::StopSystem),
            ("gps | kill", Rule::StopSystem),
            ("Get-Process -Name * | Stop-Process", Rule::StopSystem),
            ("Get-Process explorer | Stop-Process", Rule::StopSystem),
            (
                "Get-Process | Where-Object CPU -gt 100 | Stop-Process",
                Rule::StopUnknown,
            ),
            ("$procs | Stop-Process", Rule::StopUnknown),
            (
                "Get-CimInstance Win32_Process | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "powershell -Command \"Stop-Process -Name *\"",
                Rule::StopSystem,
            ),
            ("Stop-Process -Name svchost -Force", Rule::StopSystem),
            ("Stop-Process -Name SvcHost.exe", Rule::StopSystem),
            ("Stop-Process -Name svc*", Rule::StopSystem),
            // The compositor and the remote login.
            ("Stop-Process -Name dwm", Rule::StopSystem),
            ("Stop-Process -Name dwm -Force", Rule::StopSystem),
            ("Stop-Process -Name DWM.exe", Rule::StopSystem),
            ("Stop-Process -Name sshd", Rule::StopSystem),
            ("Stop-Process -Name node, dwm", Rule::StopSystem),
            ("Stop-Process -Name dw*", Rule::StopSystem),
            ("Get-Process dwm | Stop-Process", Rule::StopSystem),
            ("Stop-Process -Name $n", Rule::StopUnknown),
        ],
    );
}

#[test]
fn stop_process_reads_its_own_parameters() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Stop-Process -N node",
            "Stop-Process -ProcessName node",
            "Stop-Process -Proc node -Force",
            "Stop-Process -Name:node",
            "Stop-Process -Name node -ErrorAction SilentlyContinue",
            "Stop-Process -ErrorAction SilentlyContinue -Name node",
            "spps -ea 0 -Name node",
            "kill -n node",
            "Stop-Process -Name node -PassThru -WhatIf",
            "Stop-Process -Id 12 -Confirm:$false",
        ],
        &[
            ("Stop-Process -N explorer", Rule::StopSystem),
            ("Stop-Process -Na explorer", Rule::StopSystem),
            ("Stop-Process -ProcessName explorer", Rule::StopSystem),
            ("Stop-Process -Proc explorer", Rule::StopSystem),
            ("Stop-Process -Name:explorer", Rule::StopSystem),
            (
                "Stop-Process -ErrorAction SilentlyContinue -Name explorer",
                Rule::StopSystem,
            ),
            ("Stop-Process -ea 0 -N explorer -Force", Rule::StopSystem),
            ("kill -n *", Rule::StopSystem),
            ("kill -ProcessName winlogon", Rule::StopSystem),
            ("Stop-Process -N node,explorer", Rule::StopSystem),
            ("Stop-Process -N $n", Rule::StopUnknown),
        ],
    );
}

/// A `Get-Process` listing piped or handed to `Stop-Process` is judged like
/// the listing: a name, an id or a filter the guard reads narrows it, a
/// `Select-Object` that hands on other objects does not, and a member read
/// off it is the listing only for `Id` and `Name`. Another cmdlet's listing,
/// a variable and a part beside the listing are only known when it runs.
#[test]
fn stop_process_given_a_listing_is_judged_like_the_listing() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Stop-Process -InputObject (Get-Process node)",
            "Stop-Process -Id (Get-Process -Name node).Id",
            "Stop-Process -Id (Get-Process node | Select-Object -First 1).Id",
            "Stop-Process (Get-Process node)",
            "Stop-Process -Id (Get-Process -Id $pid).Id",
            "Get-Process node | % { Stop-Process -Id $_.Id }",
            "Get-Process node | ForEach-Object { Stop-Process -InputObject $_ -Force }",
            "Get-Process | % { $_.Name }",
            "Get-Process -Id 123 | Stop-Process",
            "Get-Process -Id $pid | Stop-Process",
            // Ids 12 and 13: 1 is the system's first process.
            "gps -Id 12,13 | kill",
            "Get-Process | Where-Object { $_.ProcessName -eq 'node' } | Stop-Process",
            "Get-Process | Where-Object { $_.Name -like 'node*' } | Stop-Process -Force",
            "Get-Process | Where-Object { $PSItem.Name -eq 'node' } | Stop-Process -WhatIf",
            "gps | ? Name -eq node | kill",
            "Get-Process | Where-Object ProcessName -like 'node*' | Stop-Process",
            "Get-Process | Where-Object -Property ProcessName -eq -Value node | Stop-Process",
            "Get-Process | Where-Object -FilterScript { $_.Name -eq 'node' } | Stop-Process",
            "Get-Process node | Where-Object { $_.CPU -gt 100 } | Stop-Process",
            "Get-Process node | Sort-Object CPU | Select-Object -First 1 | Stop-Process",
            "Get-Process | Where-Object { $_.ProcessName -ceq 'node' } | Stop-Process",
            "Get-Process node | Select-Object -First 1 | Stop-Process",
            "Get-Process node | select -Property Name | kill",
            "Get-Process node | Select-Object Id | Stop-Process",
            "Get-Process node | Select-Object -Last 2 | Stop-Process",
            "Get-Process node | Sort-Object CPU | Select-Object -First 1 | kill",
            "Get-Process node | select -ex 1 | kill",
            "Stop-Process -Id (Get-Process node).Id",
            "Stop-Process -Id ((Get-Process node).Id)",
            "Stop-Process -Id (Get-Process node).Id, 4242",
            "Stop-Process -InputObject (Get-Process node), (Get-Process vite)",
            "Stop-Process -Id (Get-Process node).ID",
            "Stop-Process -InputObject (Get-Process node).Name",
            "Stop-Process -InputObject ((Get-Process node).ProcessName)",
            "Stop-Process -Id (Get-Process -Id $PID).Id",
        ],
        &[
            // Another cmdlet's listing, a variable and the item of a block
            // that no `Get-Process` feeds are processes only known when it
            // runs, as `kill $(lsof -ti:3000)` is.
            (
                "Stop-Process -Id (Get-NetTCPConnection -LocalPort 3000).OwningProcess",
                Rule::StopUnknown,
            ),
            ("Stop-Process -InputObject $p", Rule::StopUnknown),
            ("$procs | % { Stop-Process -Id $_.Id }", Rule::StopUnknown),
            (
                "Get-NetTCPConnection -LocalPort 3000 | % { Stop-Process -Id $_.OwningProcess }",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -InputObject (Get-Process) -Force",
                Rule::StopSystem,
            ),
            (
                "Stop-Process -InputObject (Get-Process explorer)",
                Rule::StopSystem,
            ),
            ("Stop-Process -Id (Get-Process).Id", Rule::StopSystem),
            ("Stop-Process -Id $(Get-Process)", Rule::StopSystem),
            ("Stop-Process (Get-Process)", Rule::StopSystem),
            (
                "Stop-Process -Id (Get-Process | Where-Object CPU -gt 1).Id",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id (Get-Process).Where({ $_.CPU -gt 1 }).Id",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | % { Stop-Process -InputObject $_ }",
                Rule::StopSystem,
            ),
            (
                "Get-Process | % { Stop-Process -Id $_.Id }",
                Rule::StopSystem,
            ),
            (
                "Get-Process | ForEach-Object { Stop-Process -Id $PSItem.Id -Force }",
                Rule::StopSystem,
            ),
            (
                "Get-Process -Name explorer | % { Stop-Process -Id $_.Id }",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object CPU -gt 1 | % { Stop-Process -Id $_.Id }",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | % { if ($_.CPU -gt 1) { Stop-Process -Id $_.Id } }",
                Rule::StopSystem,
            ),
            // A variable picks the processes only when it runs.
            (
                "Get-Process -InputObject $x | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.ProcessName -eq 'explorer' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.Name -like 'e*' } | Stop-Process",
                Rule::StopSystem,
            ),
            ("gps | ? Name -eq svchost | kill", Rule::StopSystem),
            (
                "Get-Process | Where-Object { $_.CPU -gt 100 } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.ProcessName -ne 'node' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.ProcessName -eq 'a' -or $_.CPU -gt 1 } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.ProcessName -eq $n } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.Id -eq 5 } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Select-Object -First 1 | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | ForEach-Object { $_ } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process node | ForEach-Object { Get-Process } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.ProcessName -eq 'node' } | Stop-Process; Get-Process | Stop-Process",
                Rule::StopSystem,
            ),
            // A `Select-Object` that hands on other objects.
            (
                "Get-Process node | Select-Object -ExpandProperty Parent | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process node | select -exp Parent | kill",
                Rule::StopUnknown,
            ),
            (
                "Get-Process node | select -ExpandProperty:Parent | kill",
                Rule::StopUnknown,
            ),
            (
                "Get-Process node | select -expa Parent | kill",
                Rule::StopUnknown,
            ),
            (
                "Get-Process node | select @{n='x';e={$_.Parent}} | kill",
                Rule::StopUnknown,
            ),
            (
                "Get-Process node | Select-Object -Property @{Name='P';Expression={$_.Parent}} | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -InputObject (Get-Process node | select -exp Parent)",
                Rule::StopUnknown,
            ),
            (
                "Get-Process node | select -exp Parent | Select-Object -First 1 | kill",
                Rule::StopUnknown,
            ),
            // The listing says nothing of the id or the object beside it.
            (
                "Stop-Process -Id ((Get-Process node).Id, $x)",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id ($x, (Get-Process node).Id)",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id $((Get-Process node).Id; $x)",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id (Get-Process node).Id, $x",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -InputObject ((Get-Process node), $x)",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -InputObject (Get-Process node), $x",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id ((Get-Process node).Id + 1)",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id (Get-Process node).Id, (Get-Content app.pid)",
                Rule::StopUnknown,
            ),
            // A member other than `Id` and `Name`.
            (
                "Stop-Process -InputObject (Get-Process notepad).Parent",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -InputObject (Get-Process -Id $PID).Parent",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id (Get-Process node).Parent.Id",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -InputObject ((Get-Process node).Parent)",
                Rule::StopUnknown,
            ),
            (
                "(Get-Process node).Parent | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id (Get-Process node | Select-Object -ExpandProperty Parent).Id",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id ((Get-Process node).Parent.Id)",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id (Get-Process node).Threads.Id",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id (Get-Process node).ParentX",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id (Get-Process -Id (Get-Process explorer).Id).Id",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id (Get-Content pid.txt | % { (Get-Process $_).Parent.Id })",
                Rule::StopUnknown,
            ),
        ],
    );
}

/// The item `$_` of a block a `Get-Process` feeds is that process, wrapped
/// or not; a member other than the process's own, and the item after
/// anything but a `Get-Process`, is another process only known when it runs.
#[test]
fn the_item_of_a_block_is_the_process_only_with_its_own_members() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-Process notepad | % { Stop-Process -Id $_.Id }",
            "Get-Process notepad | % { Stop-Process -InputObject $_ }",
            "Get-Process notepad | % { Stop-Process $_.Id }",
            "Get-Process notepad | % { Stop-Process -Id $PSItem.Id -Force }",
            "Get-Process node | % { Stop-Process -Id ($_.Id) }",
            "Get-Process node | % { Stop-Process ($_) }",
            "Get-Process node | % { Stop-Process @($_) }",
            "Get-Process node | % { Stop-Process -InputObject ($_) }",
            "Get-Process node | % { Stop-Process -Id $($_.Id) }",
            "Get-Process node | % { Stop-Process -Id \"$($_.Id)\" }",
            "Get-Process node | % { Stop-Process -Id ([int]$_.Id) }",
            "Get-Process node | % { Stop-Process -Id \"$_\" }",
        ],
        &[
            (
                "Get-NetTCPConnection -LocalPort 3000 | % { Stop-Process -Id ($_.OwningProcess) }",
                Rule::StopUnknown,
            ),
            (
                "Get-Process notepad | % { Stop-Process -InputObject $_.Parent }",
                Rule::StopUnknown,
            ),
            (
                "Get-Process notepad | % { Stop-Process $_.Parent }",
                Rule::StopUnknown,
            ),
            (
                "Get-Process notepad | % { Stop-Process -Id $_.Parent.Id -Force }",
                Rule::StopUnknown,
            ),
            (
                "Get-Process notepad | % { Stop-Process -Id $_.Threads.Id }",
                Rule::StopUnknown,
            ),
            (
                "Get-Process notepad | % { Stop-Process -Id ($_.Parent.Id) }",
                Rule::StopUnknown,
            ),
            (
                "Get-Process notepad | % { Stop-Process -Id ($_.Id + 1) }",
                Rule::StopUnknown,
            ),
            (
                "Get-Process notepad | % { Stop-Process -Id $_.Id, $_.Parent.Id }",
                Rule::StopUnknown,
            ),
            ("Get-Process | % { Stop-Process ($_) }", Rule::StopSystem),
            ("Get-Process | % { Stop-Process @($_) }", Rule::StopSystem),
            (
                "Get-Process | % { Stop-Process -InputObject ($_) }",
                Rule::StopSystem,
            ),
            (
                "Get-Process | % { Stop-Process -Id ($_.Id) }",
                Rule::StopSystem,
            ),
            (
                "Get-Process | % { Stop-Process -Id $($_.Id) }",
                Rule::StopSystem,
            ),
            (
                "Get-Process | % { Stop-Process -Id \"$($_.Id)\" }",
                Rule::StopSystem,
            ),
            (
                "Get-Process | % { Stop-Process -Id ([int]$_.Id) }",
                Rule::StopSystem,
            ),
            // Not the item or one of its own members.
            (
                "Get-Process node | % { Stop-Process -Id (-not $_.Id) }",
                Rule::StopUnknown,
            ),
            (
                "Get-Process node | % { Stop-Process -Id ($_.Id + 1) }",
                Rule::StopUnknown,
            ),
            (
                "Get-Process node | % { Stop-Process -Id \"1$($_.Id)\" }",
                Rule::StopUnknown,
            ),
            (
                "Get-Process node | % { Stop-Process -Id ([int]$_.Parent.Id) }",
                Rule::StopUnknown,
            ),
            (
                "Get-Process node | % { Stop-Process -Id $(Get-Process explorer | % { $_.Id }) }",
                Rule::StopUnknown,
            ),
        ],
    );
}

/// `ps || Stop-Process -Id (Get-Process | Stop-Process -Id ×n x )×n`: a
/// listing in the arguments of a `Stop-Process`, `n` deep.
fn listing_chain(n: usize) -> String {
    format!(
        "ps || Stop-Process -Id {}x{}",
        "(Get-Process | Stop-Process -Id ".repeat(n),
        ")".repeat(n)
    )
}

#[test]
fn a_nested_listing_is_one_finding_and_a_command_with_none_is_not_one() {
    let windows = windows();
    let line = listing_chain(40);
    let findings = classify(&line, Shell::PowerShell, &windows);
    let stops: Vec<_> = findings
        .findings()
        .iter()
        .filter(|finding| finding.rule == Rule::StopUnknown)
        .collect();
    assert!(!stops.is_empty(), "{line}");
    check(
        Shell::PowerShell,
        &windows,
        &[],
        &[
            // No listing in them, so no listing finding, but a file's text
            // is an id only known when it runs.
            ("Stop-Process -Id (Get-Content pid.txt)", Rule::StopUnknown),
            (
                "Stop-Process -Id (cat pid.txt | Select-Object -First 1)",
                Rule::StopUnknown,
            ),
            (
                "Stop-Process -Id (Foo (Get-Process explorer).Id)",
                Rule::StopUnknown,
            ),
        ],
    );
    for line in [
        listing_chain(100),
        format!(
            "Stop-Process -InputObject {}x{}",
            "(Get-Process ".repeat(300),
            ")".repeat(300)
        ),
    ] {
        assert!(
            !classify(&line, Shell::PowerShell, &windows).is_safe(),
            "{} bytes",
            line.len()
        );
    }
}

/// A method that stops a process (`Kill`, `CloseMainWindow`, WMI's
/// `Terminate`) is judged like `Stop-Process` given the same object.
#[test]
fn a_method_that_stops_a_process_is_judged_like_stop_process() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "(Get-Process node).Kill()",
            "(Get-Process -Name node).Kill()",
            "(Get-Process node).Kill($true)",
            "(Get-Process node | Select-Object -First 1).Kill()",
            "(Get-Process node).CloseMainWindow()",
            "Get-Process node | ForEach-Object { $_.Kill() }",
            "Get-Process node | % { $_.Kill() }",
            "Get-Process node | Foreach { $PSItem.Kill() }",
            "Get-Process node | % Kill",
            "Get-Process node | ForEach-Object Kill",
            "Get-Process node | ForEach-Object -MemberName Kill",
            "Get-Process node | % { $_.CloseMainWindow() }",
            "Get-Process | Where-Object { $_.Name -like 'node' } | ForEach-Object { $_.Kill() }",
            "Get-Process node | Where-Object CPU -gt 100 | % { $_.Kill() }",
            "[System.Diagnostics.Process]::GetProcessById(1234).Kill()",
            "[Diagnostics.Process]::GetProcessById(4242).Kill()",
            "(Get-Process -Id 1234).Kill()",
            "(Get-Process -Id $pid).Kill()",
            "Get-Process node | % { $_.Name }",
            "Get-CimInstance Win32_Process",
            "Get-WmiObject Win32_Process",
            "Get-CimInstance Win32_Process | Select-Object Name, ProcessId",
        ],
        &[
            ("(Get-Process).Kill()", Rule::StopSystem),
            ("(Get-Process explorer).Kill()", Rule::StopSystem),
            ("(Get-Process node, explorer).Kill()", Rule::StopSystem),
            (
                "(Get-Process | Where-Object CPU -gt 100).Kill()",
                Rule::StopUnknown,
            ),
            // The array's `.ForEach('Kill')` is a line the grammar does not
            // read, so it is risky for that.
            ("(Get-Process).ForEach('Kill')", Rule::Unreadable),
            ("(Get-Process node).ForEach('Kill')", Rule::Unreadable),
            ("(Get-Process).CloseMainWindow()", Rule::StopSystem),
            (
                "Get-Process | ForEach-Object { $_.Kill() }",
                Rule::StopSystem,
            ),
            ("Get-Process | % { $_.Kill() }", Rule::StopSystem),
            ("Get-Process | Foreach { $_.Kill() }", Rule::StopSystem),
            ("Get-Process | % Kill", Rule::StopSystem),
            ("Get-Process | ForEach-Object Kill", Rule::StopSystem),
            (
                "Get-Process | ForEach-Object -MemberName Kill",
                Rule::StopSystem,
            ),
            ("Get-Process | % CloseMainWindow", Rule::StopSystem),
            ("Get-Process | % { $_.CloseMainWindow() }", Rule::StopSystem),
            (
                "Get-Process explorer | ForEach-Object { $_.Kill() }",
                Rule::StopSystem,
            ),
            ("Get-Process explorer | % Kill", Rule::StopSystem),
            (
                "Get-Process | Where-Object CPU -gt 100 | % { $_.Kill() }",
                Rule::StopUnknown,
            ),
            // Not the process itself: its parent, or an item of a list.
            ("(Get-Process node).Parent.Kill()", Rule::StopUnknown),
            (
                "Get-Process node | % { $_.Parent.Kill() }",
                Rule::StopUnknown,
            ),
            ("(Get-Process node)[0].Kill()", Rule::StopUnknown),
            ("((Get-Process node), $x).Kill()", Rule::StopUnknown),
            // An object only known when it runs.
            ("$p.Kill()", Rule::StopUnknown),
            ("$proc.Kill($true)", Rule::StopUnknown),
            ("$p = Get-Process; $p.Kill()", Rule::StopUnknown),
            ("$procs | % { $_.Kill() }", Rule::StopUnknown),
            ("$procs | % Kill", Rule::StopUnknown),
            ("$procs.ForEach({ $_.Kill() })", Rule::StopUnknown),
            ("% { $_.Kill() }", Rule::StopUnknown),
            (
                "Get-Content pids.txt | % { (Get-Process -Id $_).Kill() }",
                Rule::StopUnknown,
            ),
            // .NET's lists, and an id that is not written out in digits or
            // is the group's or the system's own.
            (
                "[System.Diagnostics.Process]::GetProcesses() | % { $_.Kill() }",
                Rule::StopUnknown,
            ),
            (
                "[System.Diagnostics.Process]::GetProcessesByName('explorer').Kill()",
                Rule::StopUnknown,
            ),
            (
                "[System.Diagnostics.Process]::GetProcessById(0).Kill()",
                Rule::StopSystem,
            ),
            (
                "[System.Diagnostics.Process]::GetProcessById(1).Kill()",
                Rule::StopSystem,
            ),
            (
                "[System.Diagnostics.Process]::GetProcessById($id).Kill()",
                Rule::StopUnknown,
            ),
            (
                "[System.Diagnostics.Process]::GetProcessById(1234 + 0).Kill()",
                Rule::StopUnknown,
            ),
            ("(Get-Process -Id 0).Kill()", Rule::StopSystem),
            ("(Get-Process -Id $id).Kill()", Rule::StopUnknown),
            // WMI stops processes through a method.
            (
                "Get-CimInstance Win32_Process | Invoke-CimMethod -MethodName Terminate",
                Rule::StopUnknown,
            ),
            (
                "Get-CimInstance Win32_Process -Filter \"name='node.exe'\" | Invoke-CimMethod -MethodName Terminate",
                Rule::StopUnknown,
            ),
            (
                "Invoke-CimMethod -InputObject $p -MethodName terminate",
                Rule::StopUnknown,
            ),
            (
                "Get-WmiObject Win32_Process | Invoke-WmiMethod -Name Terminate",
                Rule::StopUnknown,
            ),
            (
                "Get-CimInstance Win32_Process | icim -MethodName Terminate",
                Rule::StopUnknown,
            ),
            (
                "Get-WmiObject Win32_Process | iwmi -Name Terminate",
                Rule::StopUnknown,
            ),
            (
                "Get-WmiObject Win32_Process | % { $_.Terminate() }",
                Rule::StopUnknown,
            ),
            (
                "(Get-WmiObject Win32_Process -Filter \"name='explorer.exe'\").Terminate()",
                Rule::StopUnknown,
            ),
            (
                "(Get-CimInstance Win32_Process -Filter \"name='node.exe'\").Terminate()",
                Rule::StopUnknown,
            ),
        ],
    );
}

/// An id written out in digits is a process the agent picked, and so is the
/// shell's own `$PID`; 0 and 1 are the system's. An id only known when it
/// runs, or one that is not an id, may be any process.
#[test]
fn stop_process_judges_the_id_it_is_given() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Stop-Process 1234",
            "Stop-Process -Id 1234,5678",
            "Stop-Process -Id 1234, 5678 -Force",
            "Stop-Process -Id \"1234\"",
            "Stop-Process -Id:1234",
            "Stop-Process -Id 4",
            "spps -Id 4242",
            "kill 4242",
            "kill -Id 4242",
            "Get-Process -Id 1234 | Stop-Process",
            "Get-Process -Id 12,13 | Stop-Process",
            "Get-Process -Id 12,13 | % { $_.Kill() }",
            // The shell that runs the line.
            "Stop-Process -Id $PID",
            "Stop-Process -Id $pid -Force",
            "Stop-Process $PID",
            "Get-Process -Id $PID | Stop-Process",
        ],
        &[
            ("Stop-Process -Id 0", Rule::StopSystem),
            ("Stop-Process 0", Rule::StopSystem),
            ("Stop-Process -Id 00", Rule::StopSystem),
            ("Stop-Process -Id \"0\"", Rule::StopSystem),
            ("Stop-Process -Id 0 -Force", Rule::StopSystem),
            ("Stop-Process -Id 1234,0", Rule::StopSystem),
            ("Stop-Process -Id 0,1234", Rule::StopSystem),
            ("kill 0", Rule::StopSystem),
            ("kill -Id 0", Rule::StopSystem),
            ("spps -Id 0", Rule::StopSystem),
            ("Stop-Process -Id 1", Rule::StopSystem),
            ("Stop-Process 1 -Force", Rule::StopSystem),
            ("Get-Process -Id 0 | Stop-Process", Rule::StopSystem),
            ("Get-Process -Id 1 | % { $_.Kill() }", Rule::StopSystem),
            ("Get-Process -Id 1234,0 | kill", Rule::StopSystem),
            // A variable, a file's text and another cmdlet's listing.
            ("Stop-Process -Id $id", Rule::StopUnknown),
            ("Stop-Process $id", Rule::StopUnknown),
            ("Stop-Process -Id $env:APP_PID", Rule::StopUnknown),
            ("Stop-Process -Id 1234,$id", Rule::StopUnknown),
            (
                "Stop-Process -Id (Get-Content app.pid)",
                Rule::StopUnknown,
            ),
            ("Stop-Process -Id $(Get-Content app.pid)", Rule::StopUnknown),
            (
                "Stop-Process -Id (Get-NetTCPConnection -LocalPort 3000 -State Listen).OwningProcess -Force",
                Rule::StopUnknown,
            ),
            ("Stop-Process -Id (netstat -ano)", Rule::StopUnknown),
            ("kill $id", Rule::StopUnknown),
            ("kill (Get-Content app.pid)", Rule::StopUnknown),
            // Not an id.
            ("Stop-Process -Id ($x + 1)", Rule::StopUnknown),
            ("Stop-Process -Id 0x10", Rule::StopUnknown),
            ("Stop-Process -Id -1", Rule::StopUnknown),
            ("Stop-Process -Id 1.5", Rule::StopUnknown),
            ("Stop-Process -Id ' 1234'", Rule::StopUnknown),
            ("Stop-Process -Id 99999999999999999999", Rule::StopUnknown),
            ("Stop-Process -Id '1234,5678'", Rule::StopUnknown),
            ("Stop-Process -Id $null", Rule::StopUnknown),
            // The item of a block, when no `Get-Process` feeds it.
            ("$procs | % { Stop-Process $_ }", Rule::StopUnknown),
            (
                "Get-Content app.pid | % { Stop-Process -Id $_ }",
                Rule::StopUnknown,
            ),
            ("1..3 | % { Stop-Process -Id $_ }", Rule::StopUnknown),
            ("Get-Content app.pid | Stop-Process", Rule::StopUnknown),
            (
                "Get-NetTCPConnection -LocalPort 3000 | Stop-Process",
                Rule::StopUnknown,
            ),
            ("% { Stop-Process -Id $_ }", Rule::StopUnknown),
            // A listing by id takes the same ids.
            ("Get-Process -Id $id | Stop-Process", Rule::StopUnknown),
            (
                "Get-Process -Id (Get-Content app.pid) | Stop-Process",
                Rule::StopUnknown,
            ),
            ("Get-Process -Id $id | % { $_.Kill() }", Rule::StopUnknown),
            (
                "Stop-Process -Id (Get-Process -Id $id).Id",
                Rule::StopUnknown,
            ),
        ],
    );
}

/// `taskkill` and `tskill` judge the names, ids and `PID` filters they are
/// given as `Stop-Process` judges its own, in cmd and in PowerShell; a
/// variable of the other shell is a plain word.
#[test]
fn taskkill_and_tskill_judge_the_name_or_id_they_are_given() {
    for shell in [Shell::Cmd, Shell::PowerShell] {
        check(
            shell,
            &windows(),
            &[
                "taskkill /PID 1234",
                "taskkill /PID 1234 /F",
                "taskkill /F /PID 1234 /T",
                "taskkill /pid 4242 /f",
                "taskkill /PID 1234 /PID 5678",
                "taskkill /IM node.exe /F",
                "tskill node",
                "tskill node /a",
                "tskill node /v",
                "tskill 1234",
                "tskill 4242 /a /v",
                "tskill 1234 /server:build",
                "tskill.exe node",
                "tskill",
                "taskkill /F /FI \"PID eq 1234\"",
                "taskkill /FI \"PID eq 4242\" /F /T",
                "taskkill /FI \"pid EQ 1234\"",
                "taskkill /FI \"PID eq 1234\" /FI \"USERNAME eq me\"",
                "taskkill /FI \"PID eq 1234\" /FI \"MEMUSAGE gt 1\"",
            ],
            &[
                ("taskkill /PID 0", Rule::StopSystem),
                ("taskkill /F /PID 0", Rule::StopSystem),
                ("taskkill /PID 1", Rule::StopSystem),
                ("taskkill /PID 1234 /PID 0", Rule::StopSystem),
                ("taskkill /pid 00 /f", Rule::StopSystem),
                ("taskkill /PID abc", Rule::StopUnknown),
                ("taskkill /PID -1", Rule::StopUnknown),
                ("taskkill /PID 12.5", Rule::StopUnknown),
                ("taskkill /F /PID %pid%", Rule::StopUnknown),
                ("taskkill /F /PID $id", Rule::StopUnknown),
                ("tskill explorer", Rule::StopSystem),
                ("tskill explorer /a", Rule::StopSystem),
                ("tskill /a explorer", Rule::StopSystem),
                ("tskill.exe explorer", Rule::StopSystem),
                ("tskill svchost /v", Rule::StopSystem),
                ("tskill node explorer", Rule::StopSystem),
                ("tskill *", Rule::StopSystem),
                ("tskill 0", Rule::StopSystem),
                ("tskill 1", Rule::StopSystem),
                ("tskill 0 /a", Rule::StopSystem),
                ("taskkill /F /FI \"PID eq 0\"", Rule::StopSystem),
                ("taskkill /F /FI \"PID eq 1\"", Rule::StopSystem),
                ("taskkill /F /FI \"PID eq abc\"", Rule::StopUnknown),
                ("taskkill /F /FI \"PID eq 1234 or 0\"", Rule::StopUnknown),
                ("taskkill /F /FI \"PID eq\"", Rule::StopUnknown),
                ("taskkill /F /FI \"PID ne 1234\"", Rule::StopSystem),
                ("taskkill /F /FI \"PID gt 0\"", Rule::StopSystem),
                (
                    "taskkill /F /FI \"PID eq 1234\" /FI \"PID eq 0\"",
                    Rule::StopSystem,
                ),
                (
                    "taskkill /F /FI \"IMAGENAME ne node.exe\"",
                    Rule::StopSystem,
                ),
            ],
        );
    }
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "taskkill /F /IM node.exe /T",
            "taskkill /F /FI \"IMAGENAME eq node.exe\"",
            "taskkill /F /IM svchostx.exe",
            "taskkill /IM node.exe",
            "tskill $pid",
        ],
        &[
            ("taskkill /IM explorer.exe /F", Rule::StopSystem),
            ("taskkill /F /T /IM winlogon.exe", Rule::StopSystem),
            ("taskkill /F /IM *", Rule::StopSystem),
            ("taskkill /F /IM *.exe", Rule::StopSystem),
            ("taskkill /IM node.exe /IM explorer.exe", Rule::StopSystem),
            ("taskkill /F /FI \"USERNAME eq me\"", Rule::StopSystem),
            (
                "taskkill /F /FI \"IMAGENAME eq explorer.exe\"",
                Rule::StopSystem,
            ),
            ("taskkill /F /IM $name", Rule::StopUnknown),
            ("taskkill /F /FI $filter", Rule::StopUnknown),
            ("taskkill /F /IM svchost.exe", Rule::StopSystem),
            (
                "taskkill /F /FI \"IMAGENAME eq svchost.exe\"",
                Rule::StopSystem,
            ),
            ("taskkill /IM dwm.exe /F", Rule::StopSystem),
            ("taskkill /IM sshd.exe", Rule::StopSystem),
            ("taskkill /FI \"IMAGENAME eq dwm.exe\"", Rule::StopSystem),
            ("tskill dwm", Rule::StopSystem),
            ("taskkill /F /PID (Get-Content app.pid)", Rule::StopUnknown),
            ("taskkill /F /PID (Get-Process).Id", Rule::StopUnknown),
            (
                "Get-Process node | ForEach-Object { taskkill /F /PID $_.Id }",
                Rule::StopUnknown,
            ),
            (
                "Get-NetTCPConnection -LocalPort 3000 | % { taskkill /F /PID $_.OwningProcess }",
                Rule::StopUnknown,
            ),
            ("tskill $n", Rule::StopUnknown),
            ("tskill $n /a", Rule::StopUnknown),
            ("tskill $id", Rule::StopUnknown),
            ("tskill \"$n\"", Rule::StopUnknown),
            ("tskill (Get-Content app.pid)", Rule::StopUnknown),
            ("tskill ex$n", Rule::StopUnknown),
            ("taskkill /F /FI \"PID eq $id\"", Rule::StopUnknown),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            "taskkill /PID 12 /F",
            "tskill $n",
            "taskkill /IM node???????????????????.exe",
        ],
        &[
            ("taskkill /f /im explorer.exe", Rule::StopSystem),
            ("taskkill /F /IM *", Rule::StopSystem),
            ("taskkill /f /fi \"username eq me\"", Rule::StopSystem),
            ("tskill %n%", Rule::StopUnknown),
            ("tskill %id% /a", Rule::StopUnknown),
            ("taskkill /F /FI \"PID eq %p%\"", Rule::StopUnknown),
            // A wildcard longer than every name matches none of them.
            ("taskkill /IM l???n*", Rule::StopSystem),
            // A `for /f` loop over a listing is a line the grammar does not
            // read.
            (
                "for /f \"tokens=5\" %p in ('netstat -ano ^| findstr :3000') do taskkill /F /PID %p",
                Rule::Unreadable,
            ),
            (
                "for /f %i in ('tasklist') do taskkill /PID %i",
                Rule::Unreadable,
            ),
            (
                "for /f %i in (pids.txt) do taskkill /PID %i",
                Rule::Unreadable,
            ),
        ],
    );
}

#[test]
fn taskkill_with_only_a_filter_stops_what_the_filter_picks() {
    let risky = [
        "taskkill /F /FI \"STATUS eq RUNNING\"",
        "taskkill /F /FI \"MEMUSAGE gt 1\"",
        "taskkill /F /FI \"SESSION eq 1\"",
        "taskkill /F /FI \"WINDOWTITLE eq x*\"",
        "taskkill /F /FI \"CPUTIME gt 00:00:01\"",
        "taskkill /F /FI \"STATUS ne RUNNING\"",
        "taskkill /F /FI \"STATUS eq UNKNOWN\"",
        "taskkill /F /FI \"status eq running\" /T",
        "taskkill /F /FI \"MEMUSAGE gt 1\" /FI \"STATUS eq NOT RESPONDING\"",
        "taskkill /F /FI \"\"",
    ];
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "taskkill /F /IM node.exe /FI \"MEMUSAGE gt 1\"",
            "taskkill /PID 12 /FI \"STATUS eq RUNNING\"",
            "taskkill /F /FI \"STATUS eq NOT RESPONDING\"",
            "taskkill /F /FI \"status eq not responding\"",
            "taskkill /F /FI \"IMAGENAME eq node.exe\" /FI \"MEMUSAGE gt 1\"",
        ],
        &risky.map(|line| (line, Rule::StopSystem)),
    );
    check(
        Shell::Cmd,
        &windows(),
        &["taskkill /f /pid 4 /fi \"status eq running\""],
        &[
            ("taskkill /f /fi \"status eq running\"", Rule::StopSystem),
            ("taskkill /f /fi \"memusage gt 1\"", Rule::StopSystem),
        ],
    );
}

/// `wmic process` and `wmic path win32_process` stop the processes their
/// `where` clause picks; in PowerShell a value with a variable in it is only
/// known when it runs, while in cmd a `$` is a character of the name.
#[test]
fn wmic_stops_the_processes_its_where_clause_picks() {
    for shell in [Shell::Cmd, Shell::PowerShell] {
        check(
            shell,
            &windows(),
            &[
                "wmic process get name,processid",
                "wmic process where name=\"node.exe\" get processid",
                "wmic process where name=\"node.exe\" call terminate",
                "wmic process where name='node.exe' call terminate",
                "wmic process where \"name='node.exe'\" call terminate",
                "wmic process where name=\"node.exe\" delete",
                "wmic process where processid=1234 call terminate",
                "wmic process where processid=\"4242\" delete",
                "wmic path win32_process get name",
                "wmic path win32_process where name=\"node.exe\" get processid",
                "wmic path win32_process where name=\"node.exe\" call terminate",
                "wmic path Win32_Process where \"name='node.exe'\" delete",
                "wmic path win32_process where processid=1234 call terminate",
                "wmic PATH WIN32_PROCESS where name=\"node.exe\" delete",
            ],
            &[
                ("wmic process call terminate", Rule::StopSystem),
                ("wmic process delete", Rule::StopSystem),
                (
                    "wmic process where name=\"explorer.exe\" call terminate",
                    Rule::StopSystem,
                ),
                (
                    "wmic process where name=\"svchost.exe\" delete",
                    Rule::StopSystem,
                ),
                (
                    "wmic process where processid=0 call terminate",
                    Rule::StopSystem,
                ),
                ("wmic process where processid=1 delete", Rule::StopSystem),
                (
                    "wmic process where \"name like '%node%'\" call terminate",
                    Rule::StopUnknown,
                ),
                (
                    "wmic process where \"name='node.exe' or name='explorer.exe'\" call terminate",
                    Rule::StopUnknown,
                ),
                (
                    "wmic process where name!=\"node.exe\" call terminate",
                    Rule::StopUnknown,
                ),
                (
                    "wmic process where \"name='*'\" call terminate",
                    Rule::StopUnknown,
                ),
                (
                    "wmic process where parentprocessid=1234 call terminate",
                    Rule::StopUnknown,
                ),
                (
                    "wmic process where name=%NAME% call terminate",
                    Rule::StopUnknown,
                ),
                // `path win32_process` is the class the alias stands for.
                ("wmic path win32_process call terminate", Rule::StopSystem),
                (
                    "wmic path win32_process where name=\"explorer.exe\" call terminate",
                    Rule::StopSystem,
                ),
                (
                    "wmic path Win32_Process where \"name='explorer.exe'\" delete",
                    Rule::StopSystem,
                ),
                ("wmic PATH win32_process delete", Rule::StopSystem),
                ("wmic path cim_process delete", Rule::StopSystem),
                (
                    "wmic path win32_process where processid=0 call terminate",
                    Rule::StopSystem,
                ),
                (
                    "wmic path win32_process where \"name like '%node%'\" call terminate",
                    Rule::StopUnknown,
                ),
                (
                    "wmic path win32_process call create \"notepad.exe\"",
                    Rule::Unknown,
                ),
            ],
        );
    }
    check(
        Shell::PowerShell,
        &windows(),
        &["wmic process get name"],
        &[
            (
                "wmic process where name=$n call terminate",
                Rule::StopUnknown,
            ),
            ("wmic process where name=$n delete", Rule::StopUnknown),
            (
                "wmic process where name=\"$n\" call terminate",
                Rule::StopUnknown,
            ),
            (
                "wmic process where name=$env:P call terminate",
                Rule::StopUnknown,
            ),
            (
                "wmic process where processid=$id call terminate",
                Rule::StopUnknown,
            ),
            (
                "wmic process where name=$($n) call terminate",
                Rule::StopUnknown,
            ),
            (
                "wmic path win32_process where name=$n call terminate",
                Rule::StopUnknown,
            ),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &["wmic process where name=$n call terminate"],
        &[],
    );
}

/// A `Where-Object` name pattern (`-like`, `-match`) is read like a wildcard
/// around it. `-match` takes a .NET expression, read only in the subset it
/// shares with POSIX's: a lookaround, an inline option or comment, an escape
/// that spells a character (`\x6f`, `\157`, `\cO`), a Unicode class
/// (`\p{L}`), a named backreference, a backslash inside `[...]` (.NET reads
/// `[\]o]` as the set `]` and `o`; POSIX closes the set at the first `]`), and
/// a letter that is not ASCII (.NET ignores case by the current culture, so
/// `İ` and `ſ` can stand for `i` and `s`) are not read, so the filter is one
/// only known when it runs. (`\uXXXX` goes the same way, by the same code
/// path.)
#[test]
fn a_where_object_name_pattern_is_read_like_a_wildcard_around_it() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-Process | Where-Object { $_.Name -match 'node' } | Stop-Process",
            "Get-Process | Where-Object { $_.ProcessName -imatch 'vite' } | Stop-Process -Force",
            "Get-Process | Where-Object { $_.Name -cmatch \"node\" } | Stop-Process",
            "Get-Process | ? { $_.Name -match 'node' } | Stop-Process",
            "Get-Process | Where-Object Name -match node | Stop-Process",
            "Get-Process | Where-Object -Property Name -Match -Value 'node' | Stop-Process",
            "Get-Process | Where-Object { $_.Name -match 'node|vite' } | Stop-Process",
            "Get-Process | Where-Object { $_.Name -match 'node' } | ForEach-Object { $_.Kill() }",
            "Get-Process | Where-Object { $_.Name -match 'node' }",
            r"Get-Process | Where-Object { $_.Name -match 'node\d*' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'node\.exe' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match '^node\b' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match '^vite\w*$' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'node\\n' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'node[0-9]+' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match '^[nN]ode$' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'no[d]e' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'no[^x]e\.exe' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'node\[a' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'a/b' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'node/?x' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match '^*node' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'node$?' } | Stop-Process",
        ],
        &[
            (
                "Get-Process | Where-Object { $_.Name -match 'explorer' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match 'node|explorer' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match 'svc' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match '.*' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match '' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match '^' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match 'x|.*$|' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match 'a*' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match '\\w' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match '(' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match $pattern } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match \"$dir\" } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.Name -notmatch 'node' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.CPU -match 'node' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match 'explorer' } | ForEach-Object { $_.Kill() }",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object Name -match explorer | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match @('/?explorer') } | Stop-Process",
                Rule::StopSystem,
            ),
            // Lookarounds.
            (
                r"Get-Process | Where-Object { $_.Name -match '^(?!node)' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '^(?!node).*' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '^(?!node$).+' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object Name -match '^(?!(node|vite)$)' | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | ? { $_.Name -match '(?!x)' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where { $_.Name -match '(?!x)' } | kill",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '(?=e)' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '(?<!x)e' } | Stop-Process",
                Rule::StopUnknown,
            ),
            // Inline options, comments and conditionals.
            (
                r"Get-Process | Where-Object { $_.Name -match '(?x) e x p l o r e r' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '(?x)expl orer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '(?i:EXPLORER)' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '(?#node)' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'node(?(x)|)' } | Stop-Process",
                Rule::StopUnknown,
            ),
            // Escapes that spell out a character.
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl\x6frer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'ex\x70lorer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'lsas\x73' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'explor\x65r' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl\157rer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl\0157rer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl\cOrer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            // Unicode classes.
            (
                r"Get-Process | Where-Object { $_.Name -match '\p{L}' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '\p{L}+' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '\P{N}' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object -Property Name -Match -Value '\p{L}' | Stop-Process",
                Rule::StopUnknown,
            ),
            // Named backreferences.
            (
                r"Get-Process | Where-Object { $_.Name -match '(?<n>e)xplor\k<n>r' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '(?<n>e)xplor\k{n}r' } | Stop-Process",
                Rule::StopUnknown,
            ),
            // The same filters in front of a method that stops them.
            (
                r"Get-Process | Where-Object { $_.Name -match '^(?!node)' } | % Kill",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '^(?!node)' } | % { $_.Kill() }",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '^(?!node)' } | ForEach-Object { $_.Kill() }",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -imatch 'expl\x6frer' } | % Kill",
                Rule::StopUnknown,
            ),
            // A backslash in a bracket expression.
            (
                r"Get-Process | Where-Object { $_.Name -match '[\]a-z]' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '^[\]a-z]+$' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'ls[\]a]ss' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl[\]o]rer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl[o\]]rer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl[^\]x]rer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl[n-p\]]rer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'node|expl[\]o]rer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object Name -match 'expl[\]o]rer' | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl[]\]o]rer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl[^]\]x]rer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '[[:alpha:]\]o]rer' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '[\]a-z]' } | % Kill",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '[\]a-z]' } | ForEach-Object { $_.Kill() }",
                Rule::StopUnknown,
            ),
            (
                r"Get-Process | Where { $_.Name -match '[\]a-z]' } | kill",
                Rule::StopUnknown,
            ),
            // A letter that is not ASCII.
            (
                "Get-Process | Where-Object { $_.Name -match 'wİnlogon' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match 'İnit' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match 'İ' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match 'lſass' } | Stop-Process",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match 'wİnlogon' } | % Kill",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match 'İ' } | ForEach-Object { $_.Kill() }",
                Rule::StopUnknown,
            ),
            (
                "Get-Process | Where-Object Name -match 'İnit' | Stop-Process",
                Rule::StopUnknown,
            ),
        ],
    );
}

/// The forms a `-match` pattern is stopped through, one line each.
fn match_lines(pattern: &str) -> Vec<String> {
    vec![
        format!("Get-Process | Where-Object {{ $_.Name -match '{pattern}' }} | Stop-Process"),
        format!("Get-Process | Where-Object Name -match '{pattern}' | Stop-Process"),
        format!("Get-Process | ? {{ $_.ProcessName -match '{pattern}' }} | kill"),
        format!("Get-Process | Where-Object {{ $_.Name -match '{pattern}' }} | % Kill"),
        format!(
            "Get-Process | Where-Object {{ $_.Name -match '{pattern}' }} | ForEach-Object {{ $_.Kill() }}"
        ),
    ]
}

/// Every form of each pattern breaks `rule`.
fn all_risky(patterns: &[&str], rule: Rule) {
    let lines: Vec<String> = patterns.iter().flat_map(|p| match_lines(p)).collect();
    let risky: Vec<(&str, Rule)> = lines.iter().map(|line| (line.as_str(), rule)).collect();
    check(Shell::PowerShell, &windows(), &[], &risky);
}

#[test]
fn every_form_of_a_dotnet_match_pattern_is_judged_alike() {
    all_risky(
        &[
            // A process name never holds a folder, so a `/` in a .NET
            // expression ends nothing; the quantifier after it still applies
            // to what it follows.
            "/?explorer",
            "/*explorer",
            "exp/?lorer",
            "svc/*host",
            "/{0}lsass",
            "sm/*ss",
            "smss/{0,}",
            // .NET accepts `^*x` and `$?x`: the anchor may be absent, so they
            // match like `x`.
            "^*explorer",
            "^?explorer",
            "^+explorer",
            "^{0,1}svchost",
            "${0}explorer",
            "$?explorer",
            "explorer$*",
            "lsass$?",
        ],
        Rule::StopSystem,
    );
    // `[.`, `[=` and `[:` that does not close with `word:]` are a plain `[`
    // to .NET, which closes the set at the next `]`; `[a-z-[0]]` is a set
    // minus another. The POSIX reading skips or splits them differently, so
    // the guard cannot say which processes they pick.
    all_risky(
        &[
            "zz[[.]|.|.]]",
            "zz[[=]|.|=]]",
            "zz[[:]|.|:]]",
            "q[[:]|^|:]]",
            "e[a-z-[0]]",
            "s[a-z-[0-9]]",
            "ex[a-z-[q]]+",
            "sm[a-z-[x]]s",
            "w[a-z-[x]]nlogon",
            "w[^0-9-[x]]nlogon",
        ],
        Rule::StopUnknown,
    );
}

/// An id, a name, a listing, an object or a filter the guard cannot read is
/// `stop_unknown` and never `stop_system`; a certain stop is `stop_system`
/// and never `stop_unknown`.
#[test]
fn a_stop_the_guard_cannot_read_is_stop_unknown_and_a_certain_one_stop_system() {
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
    only(
        Shell::Cmd,
        &windows(),
        Rule::StopUnknown,
        Rule::StopSystem,
        &["tskill %n%", "tskill %id% /a", "taskkill /PID %p%"],
    );
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
fn the_rules_give_a_reason_a_prompt_can_show() {
    for (line, rule, reason_text) in [
        (
            "Stop-Process -InputObject (Get-Process)",
            Rule::StopSystem,
            "stops every process",
        ),
        (
            "Get-Process | % { Stop-Process -Id $_.Id }",
            Rule::StopSystem,
            "stops every process",
        ),
        (
            "Stop-Process -Id (Get-Process | Where-Object CPU -gt 1).Id",
            Rule::StopUnknown,
            "stops processes picked by a filter only known when it runs",
        ),
        (
            "Get-Process | Where-Object { $_.CPU -gt 100 } | Stop-Process",
            Rule::StopUnknown,
            "stops processes picked by a filter only known when it runs",
        ),
        (
            "Get-Process | Select-Object -First 1 | Stop-Process",
            Rule::StopUnknown,
            "stops processes picked by a filter only known when it runs",
        ),
        (
            "Get-Process | ForEach-Object { $_ } | Stop-Process",
            Rule::StopUnknown,
            "stops processes only known when it runs",
        ),
        (
            "Get-Process | Where-Object { $_.Name -eq 'explorer' } | Stop-Process",
            Rule::StopSystem,
            "stops a process the system needs",
        ),
        (
            "Get-Process | Stop-Process",
            Rule::StopSystem,
            "stops every process",
        ),
        (
            "taskkill /F /FI \"PID gt 0\"",
            Rule::StopSystem,
            "stops every process a filter picks",
        ),
    ] {
        assert_eq!(
            reason(line, Shell::PowerShell, &windows(), rule).as_deref(),
            Some(reason_text),
            "{line}"
        );
    }
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn the_process_rules_read_long_patterns_quickly() {
    let windows = windows();
    let slow = Duration::from_millis(500);
    let lines = [
        (
            Shell::PowerShell,
            format!("Stop-Process -Name '{}zz'", "*".repeat(26)),
        ),
        (
            Shell::PowerShell,
            format!("Stop-Process -Name '{}zz'", "*".repeat(60_000)),
        ),
        (Shell::Cmd, format!("taskkill /IM {}q", "*".repeat(30))),
        (Shell::Cmd, format!("taskkill /IM {}q", "*?".repeat(30_000))),
        (
            Shell::PowerShell,
            format!("Stop-Process -Name '{}'", "[".repeat(60_000)),
        ),
        (
            Shell::PowerShell,
            format!("Stop-Process -Name '{}'", "[a]".repeat(20_000)),
        ),
    ];
    // Long pipelines: most of the time is the parser's, not the rules', so
    // the limit is loose, as for the deep functions of the fork-bomb test.
    let pipelines = [
        format!("gps{}", "|kill".repeat(12_000)),
        format!("Get-Process{}", " | Stop-Process".repeat(4_000)),
    ];
    // Listings written inside the arguments of a `Stop-Process`, nested: each
    // is read once, and nothing below another command is read again.
    let listings = [
        listing_chain(50),
        listing_chain(300),
        listing_chain(1_600),
        format!(
            "Stop-Process -InputObject {}x{}",
            "(Get-Process ".repeat(2_000),
            ")".repeat(2_000)
        ),
        format!(
            "Stop-Process -InputObject {}x{}",
            "(Get-Process | ".repeat(1_600),
            ")".repeat(1_600)
        ),
    ];
    let limits = lines
        .iter()
        .map(|(shell, line)| (*shell, line, slow))
        .chain(
            pipelines
                .iter()
                .chain(&listings)
                .map(|line| (Shell::PowerShell, line, slow * 8)),
        );
    for (shell, line, limit) in limits {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let took = took(line, shell, &windows);
        assert!(took < limit, "{shell:?} {} bytes took {took:?}", line.len());
    }
}
