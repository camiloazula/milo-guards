//! A process can be stopped through a listing, an id, or a method on an
//! object, and each of them was safe whatever it stopped. A process is stopped
//! safely only when the guard reads which one for sure: a name that is not the
//! system's, a `Get-Process` listing of those, or an id written out in digits.
//! Anything else may be any process and is `stop_system`.

mod common;

use common::{check, posix, windows};
use milo_guards_shell::{Rule, Shell};

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
        ],
    );
}

#[test]
fn wmi_stops_processes_through_a_method() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-CimInstance Win32_Process",
            "Get-WmiObject Win32_Process",
            "Get-CimInstance Win32_Process | Select-Object Name, ProcessId",
        ],
        &[
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

#[test]
fn an_id_written_out_in_digits_is_a_process_the_agent_picked() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Stop-Process -Id 1234",
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
        &[],
    );
}

#[test]
fn an_id_of_0_or_1_is_not_a_process_the_agent_picked() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
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
        ],
    );
}

#[test]
fn an_id_only_known_when_it_runs_may_be_any_process() {
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            // A variable, a file's text and another cmdlet's listing.
            ("Stop-Process -Id $id", Rule::StopUnknown),
            ("Stop-Process $id", Rule::StopUnknown),
            ("Stop-Process -Id $env:APP_PID", Rule::StopUnknown),
            ("Stop-Process -InputObject $p", Rule::StopUnknown),
            ("Stop-Process -Id 1234,$id", Rule::StopUnknown),
            (
                "Stop-Process -Id (Get-Content app.pid)",
                Rule::StopUnknown,
            ),
            ("Stop-Process -Id $(Get-Content app.pid)", Rule::StopUnknown),
            (
                "Stop-Process -Id (Get-NetTCPConnection -LocalPort 3000).OwningProcess",
                Rule::StopUnknown,
            ),
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
            ("$procs | % { Stop-Process -Id $_.Id }", Rule::StopUnknown),
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
            (
                "Get-Process -InputObject $x | Stop-Process",
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

#[test]
fn a_second_part_beside_a_listing_is_not_the_listing() {
    // The listing says nothing of the id or the object beside it.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Stop-Process -Id (Get-Process node).Id",
            "Stop-Process -Id ((Get-Process node).Id)",
            "Stop-Process -Id (Get-Process node).Id, 4242",
            "Stop-Process -InputObject (Get-Process node), (Get-Process vite)",
        ],
        &[
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
        ],
    );
}

#[test]
fn taskkill_judges_the_id_it_is_given() {
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
            ],
        );
    }
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
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
        ],
    );
    // A `for /f` loop over a listing is a line the grammar does not read.
    check(
        Shell::Cmd,
        &windows(),
        &[],
        &[
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
            ],
        );
    }
}

#[test]
fn tskill_judges_the_name_or_id_it_is_given_like_taskkill() {
    for shell in [Shell::Cmd, Shell::PowerShell] {
        check(
            shell,
            &windows(),
            &[
                "tskill node",
                "tskill node /a",
                "tskill node /v",
                "tskill 1234",
                "tskill 4242 /a /v",
                "tskill 1234 /server:build",
                "tskill.exe node",
                "tskill",
            ],
            &[
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
            ],
        );
    }
    check(
        Shell::Cmd,
        &windows(),
        &["tskill $n"],
        &[
            ("tskill %n%", Rule::StopUnknown),
            ("tskill %id% /a", Rule::StopUnknown),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &["tskill $pid"],
        &[
            ("tskill $n", Rule::StopUnknown),
            ("tskill $n /a", Rule::StopUnknown),
            ("tskill $id", Rule::StopUnknown),
            ("tskill \"$n\"", Rule::StopUnknown),
            ("tskill (Get-Content app.pid)", Rule::StopUnknown),
            ("tskill ex$n", Rule::StopUnknown),
        ],
    );
}

#[test]
fn taskkill_reads_a_filter_on_the_pid_like_pid() {
    for shell in [Shell::Cmd, Shell::PowerShell] {
        check(
            shell,
            &windows(),
            &[
                "taskkill /F /FI \"PID eq 1234\"",
                "taskkill /FI \"PID eq 4242\" /F /T",
                "taskkill /FI \"pid EQ 1234\"",
                "taskkill /FI \"PID eq 1234\" /FI \"USERNAME eq me\"",
                "taskkill /FI \"PID eq 1234\" /FI \"MEMUSAGE gt 1\"",
            ],
            &[
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
        Shell::Cmd,
        &windows(),
        &[],
        &[("taskkill /F /FI \"PID eq %p%\"", Rule::StopUnknown)],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[("taskkill /F /FI \"PID eq $id\"", Rule::StopUnknown)],
    );
}

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
        ],
    );
}

#[test]
fn a_match_pattern_is_a_dotnet_expression_read_only_in_the_posix_subset() {
    // `-match` takes a .NET expression: a lookaround, an inline option or
    // comment, an escape that spells a character (`\x6f`, `\157`, `\cO`), a
    // Unicode class (`\p{L}`) and a named backreference are not read, so the
    // filter is one only known when it runs. (`\uXXXX` goes the same way, by
    // the same code path.)
    check(
        Shell::PowerShell,
        &windows(),
        &[
            r"Get-Process | Where-Object { $_.Name -match 'node\d*' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'node\.exe' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match '^node\b' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match '^vite\w*$' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'node\\n' } | Stop-Process",
        ],
        &[
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
        ],
    );
}

#[test]
fn a_match_pattern_with_a_backslash_in_a_set_or_a_non_ascii_letter_is_not_read() {
    // .NET reads a backslash inside `[...]` as an escape, so `[\]o]` is the
    // set `]` and `o`; the POSIX reading closes the set at the first `]`.
    // .NET also ignores case by the current culture, so `İ` (U+0130) and `ſ`
    // (U+017F) can stand for `i` and `s`; the guard folds ASCII only.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            r"Get-Process | Where-Object { $_.Name -match 'node[0-9]+' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match '^[nN]ode$' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'no[d]e' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'no[^x]e\.exe' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'node\[a' } | Stop-Process",
        ],
        &[
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

/// Every form of each pattern is `stop_system`.
fn all_stop_system(patterns: &[&str]) {
    all_risky(patterns, Rule::StopSystem);
}

/// Every form of each pattern is `stop_unknown`: the guard cannot read the
/// pattern, so it cannot say which processes it picks.
fn all_stop_unknown(patterns: &[&str]) {
    all_risky(patterns, Rule::StopUnknown);
}

fn all_risky(patterns: &[&str], rule: Rule) {
    let lines: Vec<String> = patterns.iter().flat_map(|p| match_lines(p)).collect();
    let risky: Vec<(&str, Rule)> = lines.iter().map(|line| (line.as_str(), rule)).collect();
    check(Shell::PowerShell, &windows(), &[], &risky);
}

#[test]
fn a_dotnet_match_pattern_reads_a_slash_as_a_plain_character() {
    // A process name never holds a folder, so a `/` in a .NET expression ends
    // nothing; the quantifier after it still applies to what it follows.
    all_stop_system(&[
        "/?explorer",
        "/*explorer",
        "exp/?lorer",
        "svc/*host",
        "/{0}lsass",
        "sm/*ss",
        "smss/{0,}",
    ]);
    check(
        Shell::PowerShell,
        &windows(),
        &[
            r"Get-Process | Where-Object { $_.Name -match 'a/b' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'node/?x' } | Stop-Process",
        ],
        &[(
            r"Get-Process | Where-Object { $_.Name -match @('/?explorer') } | Stop-Process",
            Rule::StopSystem,
        )],
    );
}

#[test]
fn a_dotnet_match_pattern_takes_a_quantifier_after_an_anchor() {
    // .NET accepts `^*x` and `$?x`: the anchor may be absent, so they match
    // like `x`.
    all_stop_system(&[
        "^*explorer",
        "^?explorer",
        "^+explorer",
        "^{0,1}svchost",
        "${0}explorer",
        "$?explorer",
        "explorer$*",
        "lsass$?",
    ]);
    check(
        Shell::PowerShell,
        &windows(),
        &[
            r"Get-Process | Where-Object { $_.Name -match '^*node' } | Stop-Process",
            r"Get-Process | Where-Object { $_.Name -match 'node$?' } | Stop-Process",
        ],
        &[],
    );
}

#[test]
fn a_dotnet_match_pattern_with_a_bracket_in_a_set_is_not_read() {
    // `[.`, `[=` and `[:` that does not close with `word:]` are a plain `[`
    // to .NET, which closes the set at the next `]`; `[a-z-[0]]` is a set
    // minus another. The POSIX reading skips or splits them differently.
    all_stop_unknown(&[
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
    ]);
}

#[test]
fn a_posix_expression_still_reads_a_slash_as_the_end_of_a_folder() {
    // `pkill` sees a program's folder end at a `/`, and its sets are POSIX's.
    check(
        Shell::Posix,
        &posix(),
        &["pkill 'a/?node'", "pkill 'node[[:alpha:]]x'"],
        &[
            ("pkill '/sbin/[i]nit'", Rule::StopSystem),
            ("pkill '^*init'", Rule::StopSystem),
            ("pkill 'zz[[:alpha:]]|init'", Rule::StopSystem),
        ],
    );
}

#[test]
fn wmic_in_powershell_does_not_read_a_value_with_a_variable_in_it() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "wmic process where name=\"node.exe\" call terminate",
            "wmic process get name",
        ],
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
    // In cmd a `$` is a character of the name.
    check(
        Shell::Cmd,
        &windows(),
        &["wmic process where name=$n call terminate"],
        &[],
    );
}

#[test]
fn wmic_path_win32_process_is_the_process_class_the_alias_stands_for() {
    for shell in [Shell::Cmd, Shell::PowerShell] {
        check(
            shell,
            &windows(),
            &[
                "wmic path win32_process get name",
                "wmic path win32_process where name=\"node.exe\" get processid",
                "wmic path win32_process where name=\"node.exe\" call terminate",
                "wmic path Win32_Process where \"name='node.exe'\" delete",
                "wmic path win32_process where processid=1234 call terminate",
                "wmic PATH WIN32_PROCESS where name=\"node.exe\" delete",
            ],
            &[
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
}

#[test]
fn a_process_stopped_through_a_listing_or_a_substitution_in_a_shell() {
    // `kill` is judged by its ids (see `issue_135`); the lines that hand it
    // a listing, a substitution or a file are the same.
    check(
        Shell::Posix,
        &posix(),
        &[
            "pgrep node",
            "pgrep -f vite | head -1",
            "lsof -ti:3000",
            "kill 4242",
            "kill -9 4242",
            "kill %1",
            "pkill -P $$",
        ],
        &[
            ("kill $(pgrep node)", Rule::StopUnknown),
            ("kill -9 $(pgrep -f vite)", Rule::StopUnknown),
            ("kill `pgrep node`", Rule::StopUnknown),
            ("kill $(lsof -ti:3000)", Rule::StopUnknown),
            ("kill -9 $(lsof -t -i tcp:3000)", Rule::StopUnknown),
            ("kill \"$(cat app.pid)\"", Rule::StopUnknown),
            ("kill $(< app.pid)", Rule::StopUnknown),
            ("kill $(jobs -p)", Rule::StopUnknown),
            ("kill $(pidof node)", Rule::StopUnknown),
            ("kill ${pids[@]}", Rule::StopUnknown),
            ("pgrep node | xargs kill", Rule::StopUnknown),
            ("pgrep node | xargs -r kill -9", Rule::StopUnknown),
            ("pgrep node | xargs -I{} kill {}", Rule::StopUnknown),
            ("lsof -t -i :3000 | xargs kill", Rule::StopUnknown),
            (
                "ps aux | grep node | awk '{print $2}' | xargs kill",
                Rule::StopUnknown,
            ),
            ("cat pids.txt | xargs kill", Rule::StopUnknown),
            ("xargs -a pids.txt kill", Rule::StopUnknown),
            ("xargs kill < pids.txt", Rule::StopUnknown),
            ("jobs -p | xargs kill", Rule::StopUnknown),
            (
                "for p in $(pgrep node); do kill $p; done",
                Rule::StopUnknown,
            ),
            (
                "pgrep node | while read p; do kill $p; done",
                Rule::StopUnknown,
            ),
            (
                "while read p; do kill $p; done < pids.txt",
                Rule::StopUnknown,
            ),
            ("xargs pkill", Rule::StopUnknown),
        ],
    );
}
