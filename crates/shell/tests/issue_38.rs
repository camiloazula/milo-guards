//! PowerShell code known only when it runs, given to a cmdlet as a script
//! block or built from text: `Invoke-Command $b`, `[scriptblock]::Create(…)`,
//! `InvokeScript(…)`. A block written out is read where it stands.

mod common;

use common::{check, rules, windows};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_block_written_out_stays_safe() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Invoke-Command { Get-ChildItem }",
            "Invoke-Command -ScriptBlock { Get-ChildItem }",
            "Invoke-Command -ScriptBlock:{ Get-ChildItem }",
            "Invoke-Command -Script { Get-ChildItem }",
            "icm { Get-ChildItem }",
            "Invoke-Command -ComputerName srv -ScriptBlock { Get-Date }",
            "Invoke-Command -Session $s { Get-Date }",
            "Invoke-Command -Session $s -ScriptBlock { Get-Date } -ArgumentList $x",
            "Invoke-Command localhost { Get-Date }",
            "Invoke-Command -FilePath .\\check.ps1 -ComputerName srv",
            "1..3 | ForEach-Object { $_ * 2 }",
            "1..3 | % { $_ * 2 }",
            "Get-ChildItem | ForEach-Object Name",
            "Get-ChildItem | % -MemberName Name",
            "1..3 | ForEach-Object -Begin { $s = 0 } -Process { $s += $_ } -End { $s }",
            "1..3 | ForEach-Object { 'begin' } { $_ } { 'end' }",
            "1..3 | ForEach-Object -Parallel { $_ } -ThrottleLimit $n",
            "Start-Job { cargo build }",
            "Start-Job -Name build -ScriptBlock { cargo build }",
            "Start-Job -InitializationScript { $x = 1 } -ScriptBlock { cargo build }",
            "Start-ThreadJob -ScriptBlock { cargo build }",
            "Register-ScheduledJob -Name nightly -ScriptBlock { cargo build }",
            "Set-PSBreakpoint -Script build.ps1 -Line 3 -Action { break }",
            "Set-PSBreakpoint -Script $script -Line 3",
            "New-Module -ScriptBlock { function f { 1 } }",
            "Measure-Command { cargo build }",
            "$ExecutionContext.InvokeCommand.CommandNotFoundAction = { param($name) }",
            "$ExecutionContext.InvokeCommand.GetCommand('git', 'Application')",
            "$b = { Get-ChildItem }",
            ".\\build.ps1 -Action Build",
            "Get-Process -Name code",
        ],
        &[],
    );
}

#[test]
fn a_block_known_only_when_it_runs_is_unknown() {
    let line = |text: &str| (text.to_string(), Rule::Unknown);
    let risky: Vec<(String, Rule)> = [
        "Invoke-Command $b",
        "Invoke-Command -ScriptBlock $b",
        "Start-Job $b",
        "Start-ThreadJob -ScriptBlock $b",
        "Set-PSBreakpoint -Action $b",
        "Register-ScheduledJob -ScriptBlock $b",
        "1 | ForEach-Object $b",
        "$ExecutionContext.InvokeCommand.InvokeScript('Remove-Item -Recurse -Force ~')",
        "$ExecutionContext.InvokeCommand.CommandNotFoundAction = $b",
        "$b=[scriptblock]::Create('Remove-Item -Recurse -Force ~'); Invoke-Command $b",
        // The parameters the issue names, each by name and by prefix.
        "Invoke-Command -ScriptBlock:$b",
        "Invoke-Command -Script $b",
        "Invoke-Command -ComputerName srv -ScriptBlock $b",
        "Invoke-Command -Session $s $b",
        "Invoke-Command -ArgumentList { 1 } $b",
        "Invoke-Command -ScriptBlock (Get-Block)",
        "Invoke-Command ({ Get-ChildItem })",
        "icm $b",
        "sajb $b",
        "sbp -Action $b",
        "Start-Job -Name build $b",
        "Start-Job -InitializationScript $i { 1 }",
        "Start-Job -ScriptBlock ([scriptblock]::Create($x))",
        "Start-ThreadJob -InitializationScript $i -ScriptBlock { 1 }",
        "Register-ScheduledJob -Name nightly -InitializationScript $i -ScriptBlock { 1 }",
        "Set-PSBreakpoint -Script build.ps1 -Line 3 -Action $b",
        "Set-PSBreakpoint -Script build.ps1 -Line 3 -Action 'break'",
        "1 | % $b",
        "1 | ForEach-Object -Process $b",
        "1 | ForEach-Object -Begin $b -Process { $_ }",
        "1 | ForEach-Object -Begin { 1 } -Process { $_ } -End $b",
        "1 | ForEach-Object -Parallel $b",
        "1 | ForEach-Object { 'begin' } $b",
        "1 | ForEach-Object -Pro $b",
        // Cmdlets that run a block the same way.
        "New-Module -ScriptBlock $b",
        "Measure-Command $b",
        "Measure-Command -Expression $b",
        // A hook the host runs for every command.
        "$ExecutionContext.InvokeCommand.PreCommandLookupAction = $b",
        "$ExecutionContext.InvokeCommand.PostCommandLookupAction += $b",
        "$ExecutionContext.InvokeCommand.CommandNotFoundAction = (Get-Block)",
        // Code built from text.
        "[scriptblock]::Create($code)",
        // Once a safe row in `windows.rs`: building a block is running code the
        // guard does not read, whatever hands it on.
        "[ScriptBlock]::Create($safe)",
        "[ScriptBlock]::Create('Get-ChildItem')",
        "[System.Management.Automation.ScriptBlock]::Create($code)",
        "$ExecutionContext.InvokeCommand.NewScriptBlock($code)",
        "$ExecutionContext.InvokeCommand.InvokeScript($code)",
        "$ExecutionContext.InvokeCommand.InvokeScript('Get-ChildItem')",
        "$ExecutionContext.SessionState.InvokeCommand.InvokeScript($code, $arg)",
    ]
    .into_iter()
    .map(line)
    .collect();
    let rows: Vec<(&str, Rule)> = risky
        .iter()
        .map(|(text, rule)| (text.as_str(), *rule))
        .collect();
    check(Shell::PowerShell, &windows(), &[], &rows);
}

#[test]
fn text_given_to_build_code_is_read() {
    let paths = windows();
    for line in [
        "[scriptblock]::Create('Remove-Item -Recurse -Force ~')",
        "$ExecutionContext.InvokeCommand.NewScriptBlock('Remove-Item -Recurse -Force ~')",
        "$ExecutionContext.InvokeCommand.InvokeScript('Remove-Item -Recurse -Force ~')",
        "$ExecutionContext.InvokeCommand.InvokeScript(\"Remove-Item -Recurse -Force $HOME\")",
        "$b=[scriptblock]::Create('Remove-Item -Recurse -Force ~'); Invoke-Command $b",
    ] {
        let found = rules(line, Shell::PowerShell, &paths);
        assert!(found.contains(&Rule::Delete), "{line}: {found:?}");
        assert!(found.contains(&Rule::Unknown), "{line}: {found:?}");
    }
}
