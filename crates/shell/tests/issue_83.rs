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
                Rule::StopSystem,
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
                Rule::StopSystem,
            ),
            // Not the process itself: its parent, or an item of a list.
            ("(Get-Process node).Parent.Kill()", Rule::StopSystem),
            (
                "Get-Process node | % { $_.Parent.Kill() }",
                Rule::StopSystem,
            ),
            ("(Get-Process node)[0].Kill()", Rule::StopSystem),
            ("((Get-Process node), $x).Kill()", Rule::StopSystem),
            // An object only known when it runs.
            ("$p.Kill()", Rule::StopSystem),
            ("$proc.Kill($true)", Rule::StopSystem),
            ("$p = Get-Process; $p.Kill()", Rule::StopSystem),
            ("$procs | % { $_.Kill() }", Rule::StopSystem),
            ("$procs | % Kill", Rule::StopSystem),
            ("$procs.ForEach({ $_.Kill() })", Rule::StopSystem),
            ("% { $_.Kill() }", Rule::StopSystem),
            (
                "Get-Content pids.txt | % { (Get-Process -Id $_).Kill() }",
                Rule::StopSystem,
            ),
            // .NET's lists, and an id that is not written out in digits or
            // is the group's or the system's own.
            (
                "[System.Diagnostics.Process]::GetProcesses() | % { $_.Kill() }",
                Rule::StopSystem,
            ),
            (
                "[System.Diagnostics.Process]::GetProcessesByName('explorer').Kill()",
                Rule::StopSystem,
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
                Rule::StopSystem,
            ),
            (
                "[System.Diagnostics.Process]::GetProcessById(1234 + 0).Kill()",
                Rule::StopSystem,
            ),
            ("(Get-Process -Id 0).Kill()", Rule::StopSystem),
            ("(Get-Process -Id $id).Kill()", Rule::StopSystem),
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
                Rule::StopSystem,
            ),
            (
                "Get-CimInstance Win32_Process -Filter \"name='node.exe'\" | Invoke-CimMethod -MethodName Terminate",
                Rule::StopSystem,
            ),
            (
                "Invoke-CimMethod -InputObject $p -MethodName terminate",
                Rule::StopSystem,
            ),
            (
                "Get-WmiObject Win32_Process | Invoke-WmiMethod -Name Terminate",
                Rule::StopSystem,
            ),
            (
                "Get-CimInstance Win32_Process | icim -MethodName Terminate",
                Rule::StopSystem,
            ),
            (
                "Get-WmiObject Win32_Process | iwmi -Name Terminate",
                Rule::StopSystem,
            ),
            (
                "Get-WmiObject Win32_Process | % { $_.Terminate() }",
                Rule::StopSystem,
            ),
            (
                "(Get-WmiObject Win32_Process -Filter \"name='explorer.exe'\").Terminate()",
                Rule::StopSystem,
            ),
            (
                "(Get-CimInstance Win32_Process -Filter \"name='node.exe'\").Terminate()",
                Rule::StopSystem,
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
            ("Stop-Process -Id $id", Rule::StopSystem),
            ("Stop-Process $id", Rule::StopSystem),
            ("Stop-Process -Id $env:APP_PID", Rule::StopSystem),
            ("Stop-Process -InputObject $p", Rule::StopSystem),
            ("Stop-Process -Id 1234,$id", Rule::StopSystem),
            (
                "Stop-Process -Id (Get-Content app.pid)",
                Rule::StopSystem,
            ),
            ("Stop-Process -Id $(Get-Content app.pid)", Rule::StopSystem),
            (
                "Stop-Process -Id (Get-NetTCPConnection -LocalPort 3000).OwningProcess",
                Rule::StopSystem,
            ),
            (
                "Stop-Process -Id (Get-NetTCPConnection -LocalPort 3000 -State Listen).OwningProcess -Force",
                Rule::StopSystem,
            ),
            ("Stop-Process -Id (netstat -ano)", Rule::StopSystem),
            ("kill $id", Rule::StopSystem),
            ("kill (Get-Content app.pid)", Rule::StopSystem),
            // Not an id.
            ("Stop-Process -Id ($x + 1)", Rule::StopSystem),
            ("Stop-Process -Id 0x10", Rule::StopSystem),
            ("Stop-Process -Id -1", Rule::StopSystem),
            ("Stop-Process -Id 1.5", Rule::StopSystem),
            ("Stop-Process -Id ' 1234'", Rule::StopSystem),
            ("Stop-Process -Id 99999999999999999999", Rule::StopSystem),
            ("Stop-Process -Id '1234,5678'", Rule::StopSystem),
            ("Stop-Process -Id $null", Rule::StopSystem),
            // The item of a block, when no `Get-Process` feeds it.
            ("$procs | % { Stop-Process -Id $_.Id }", Rule::StopSystem),
            ("$procs | % { Stop-Process $_ }", Rule::StopSystem),
            (
                "Get-Content app.pid | % { Stop-Process -Id $_ }",
                Rule::StopSystem,
            ),
            ("1..3 | % { Stop-Process -Id $_ }", Rule::StopSystem),
            ("Get-Content app.pid | Stop-Process", Rule::StopSystem),
            (
                "Get-NetTCPConnection -LocalPort 3000 | Stop-Process",
                Rule::StopSystem,
            ),
            ("% { Stop-Process -Id $_ }", Rule::StopSystem),
            // A listing by id takes the same ids.
            ("Get-Process -Id $id | Stop-Process", Rule::StopSystem),
            (
                "Get-Process -Id (Get-Content app.pid) | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process -InputObject $x | Stop-Process",
                Rule::StopSystem,
            ),
            ("Get-Process -Id $id | % { $_.Kill() }", Rule::StopSystem),
            (
                "Stop-Process -Id (Get-Process -Id $id).Id",
                Rule::StopSystem,
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
                Rule::StopSystem,
            ),
            (
                "Stop-Process -Id ($x, (Get-Process node).Id)",
                Rule::StopSystem,
            ),
            (
                "Stop-Process -Id $((Get-Process node).Id; $x)",
                Rule::StopSystem,
            ),
            (
                "Stop-Process -Id (Get-Process node).Id, $x",
                Rule::StopSystem,
            ),
            (
                "Stop-Process -InputObject ((Get-Process node), $x)",
                Rule::StopSystem,
            ),
            (
                "Stop-Process -InputObject (Get-Process node), $x",
                Rule::StopSystem,
            ),
            (
                "Stop-Process -Id ((Get-Process node).Id + 1)",
                Rule::StopSystem,
            ),
            (
                "Stop-Process -Id (Get-Process node).Id, (Get-Content app.pid)",
                Rule::StopSystem,
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
                ("taskkill /PID abc", Rule::StopSystem),
                ("taskkill /PID -1", Rule::StopSystem),
                ("taskkill /PID 12.5", Rule::StopSystem),
                ("taskkill /F /PID %pid%", Rule::StopSystem),
                ("taskkill /F /PID $id", Rule::StopSystem),
            ],
        );
    }
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[
            ("taskkill /F /PID (Get-Content app.pid)", Rule::StopSystem),
            ("taskkill /F /PID (Get-Process).Id", Rule::StopSystem),
            (
                "Get-Process node | ForEach-Object { taskkill /F /PID $_.Id }",
                Rule::StopSystem,
            ),
            (
                "Get-NetTCPConnection -LocalPort 3000 | % { taskkill /F /PID $_.OwningProcess }",
                Rule::StopSystem,
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
                    Rule::StopSystem,
                ),
                (
                    "wmic process where \"name='node.exe' or name='explorer.exe'\" call terminate",
                    Rule::StopSystem,
                ),
                (
                    "wmic process where name!=\"node.exe\" call terminate",
                    Rule::StopSystem,
                ),
                (
                    "wmic process where \"name='*'\" call terminate",
                    Rule::StopSystem,
                ),
                (
                    "wmic process where parentprocessid=1234 call terminate",
                    Rule::StopSystem,
                ),
                (
                    "wmic process where name=%NAME% call terminate",
                    Rule::StopSystem,
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
            ("tskill %n%", Rule::StopSystem),
            ("tskill %id% /a", Rule::StopSystem),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &["tskill $pid"],
        &[
            ("tskill $n", Rule::StopSystem),
            ("tskill $n /a", Rule::StopSystem),
            ("tskill $id", Rule::StopSystem),
            ("tskill \"$n\"", Rule::StopSystem),
            ("tskill (Get-Content app.pid)", Rule::StopSystem),
            ("tskill ex$n", Rule::StopSystem),
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
                ("taskkill /F /FI \"PID eq abc\"", Rule::StopSystem),
                ("taskkill /F /FI \"PID eq 1234 or 0\"", Rule::StopSystem),
                ("taskkill /F /FI \"PID eq\"", Rule::StopSystem),
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
        &[("taskkill /F /FI \"PID eq %p%\"", Rule::StopSystem)],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[("taskkill /F /FI \"PID eq $id\"", Rule::StopSystem)],
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
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.Name -match \"$dir\" } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.Name -notmatch 'node' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                "Get-Process | Where-Object { $_.CPU -match 'node' } | Stop-Process",
                Rule::StopSystem,
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
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '^(?!node).*' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '^(?!node$).+' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object Name -match '^(?!(node|vite)$)' | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | ? { $_.Name -match '(?!x)' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where { $_.Name -match '(?!x)' } | kill",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '(?=e)' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '(?<!x)e' } | Stop-Process",
                Rule::StopSystem,
            ),
            // Inline options, comments and conditionals.
            (
                r"Get-Process | Where-Object { $_.Name -match '(?x) e x p l o r e r' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '(?x)expl orer' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '(?i:EXPLORER)' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '(?#node)' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'node(?(x)|)' } | Stop-Process",
                Rule::StopSystem,
            ),
            // Escapes that spell out a character.
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl\x6frer' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'ex\x70lorer' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'lsas\x73' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'explor\x65r' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl\157rer' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl\0157rer' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match 'expl\cOrer' } | Stop-Process",
                Rule::StopSystem,
            ),
            // Unicode classes.
            (
                r"Get-Process | Where-Object { $_.Name -match '\p{L}' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '\p{L}+' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '\P{N}' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object -Property Name -Match -Value '\p{L}' | Stop-Process",
                Rule::StopSystem,
            ),
            // Named backreferences.
            (
                r"Get-Process | Where-Object { $_.Name -match '(?<n>e)xplor\k<n>r' } | Stop-Process",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '(?<n>e)xplor\k{n}r' } | Stop-Process",
                Rule::StopSystem,
            ),
            // The same filters in front of a method that stops them.
            (
                r"Get-Process | Where-Object { $_.Name -match '^(?!node)' } | % Kill",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '^(?!node)' } | % { $_.Kill() }",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -match '^(?!node)' } | ForEach-Object { $_.Kill() }",
                Rule::StopSystem,
            ),
            (
                r"Get-Process | Where-Object { $_.Name -imatch 'expl\x6frer' } | % Kill",
                Rule::StopSystem,
            ),
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
                Rule::StopSystem,
            ),
            ("wmic process where name=$n delete", Rule::StopSystem),
            (
                "wmic process where name=\"$n\" call terminate",
                Rule::StopSystem,
            ),
            (
                "wmic process where name=$env:P call terminate",
                Rule::StopSystem,
            ),
            (
                "wmic process where processid=$id call terminate",
                Rule::StopSystem,
            ),
            (
                "wmic process where name=$($n) call terminate",
                Rule::StopSystem,
            ),
            (
                "wmic path win32_process where name=$n call terminate",
                Rule::StopSystem,
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
                    Rule::StopSystem,
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
            ("kill $(pgrep node)", Rule::StopSystem),
            ("kill -9 $(pgrep -f vite)", Rule::StopSystem),
            ("kill `pgrep node`", Rule::StopSystem),
            ("kill $(lsof -ti:3000)", Rule::StopSystem),
            ("kill -9 $(lsof -t -i tcp:3000)", Rule::StopSystem),
            ("kill \"$(cat app.pid)\"", Rule::StopSystem),
            ("kill $(< app.pid)", Rule::StopSystem),
            ("kill $(jobs -p)", Rule::StopSystem),
            ("kill $(pidof node)", Rule::StopSystem),
            ("kill ${pids[@]}", Rule::StopSystem),
            ("pgrep node | xargs kill", Rule::StopSystem),
            ("pgrep node | xargs -r kill -9", Rule::StopSystem),
            ("pgrep node | xargs -I{} kill {}", Rule::StopSystem),
            ("lsof -t -i :3000 | xargs kill", Rule::StopSystem),
            (
                "ps aux | grep node | awk '{print $2}' | xargs kill",
                Rule::StopSystem,
            ),
            ("cat pids.txt | xargs kill", Rule::StopSystem),
            ("xargs -a pids.txt kill", Rule::StopSystem),
            ("xargs kill < pids.txt", Rule::StopSystem),
            ("jobs -p | xargs kill", Rule::StopSystem),
            ("for p in $(pgrep node); do kill $p; done", Rule::StopSystem),
            (
                "pgrep node | while read p; do kill $p; done",
                Rule::StopSystem,
            ),
            (
                "while read p; do kill $p; done < pids.txt",
                Rule::StopSystem,
            ),
            ("xargs pkill", Rule::StopSystem),
        ],
    );
}
