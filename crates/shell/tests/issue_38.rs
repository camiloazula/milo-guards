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

#[test]
fn a_list_stays_with_the_parameter_it_follows() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Start-Job { param($a,$b) $a } -ArgumentList $x, $y",
            "Start-Job -ScriptBlock { param($a,$b) $a } -ArgumentList $x, $y",
            "Start-Job -ArgumentList $x, $y -ScriptBlock { param($a,$b) $a }",
            "Invoke-Command { param($a,$b) $a } -ArgumentList $x, $y",
            "Invoke-Command -ComputerName $a, $b { Get-Date }",
            "1..3 | ForEach-Object -Process { $_ } -ArgumentList $a, $b",
            "1..3 | ForEach-Object -Begin { 1 } -Process { $_ } -ArgumentList $a, $b -End { 2 }",
            "1..3 | ForEach-Object -Process { 1 }, { 2 }",
        ],
        &[],
    );
}

#[test]
fn start_job_takes_a_second_block_by_position() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Start-Job { cargo build } { $x = 1 }",
            "Start-Job -ScriptBlock { cargo build } { $x = 1 }",
            "Start-Job -Command { cargo build }",
            "Start-Job -Command { cargo build } -InitializationScript { $x = 1 }",
            "Start-Job { cargo build } -Name build",
            "Start-Job -Name build { cargo build }",
            "Invoke-Command -Command { Get-Date }",
        ],
        &[],
    );
    let risky = [
        "Start-Job { cargo build } $i",
        "Start-Job -ScriptBlock { cargo build } $i",
        "Start-Job -Command { 1 } $i",
        "Start-Job -Script { 1 } $i",
        "Start-Job -ScriptBlock { 1 } (Get-Block)",
        "Start-Job -ScriptBlock { 1 } 'x'",
        "Start-Job $b { 1 }",
        "Start-Job -Command $b",
        "sajb { 1 } $i",
        "Invoke-Command -Command $b",
        "icm -Command $b",
        // A comma list after a block parameter is all blocks.
        "1..3 | ForEach-Object -Process { 1 }, $b",
    ]
    .map(|line| (line, Rule::Unknown));
    check(Shell::PowerShell, &windows(), &[], &risky);
}

#[test]
fn a_splat_on_a_cmdlet_that_runs_a_block_is_unknown() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            // One block is all these take: a splat beside one adds none.
            "Invoke-Command { Get-Date } @p",
            "Invoke-Command -ComputerName srv -ScriptBlock { Get-Date } @p",
            "New-Module { function f { 1 } } @p",
            "Measure-Command { cargo build } @p",
            "Set-PSBreakpoint -Script build.ps1 -Line 3 -Action { break } @p",
            // A splat on a cmdlet that runs no block of its own.
            "Get-ChildItem @p",
            "Get-Process @p",
        ],
        &[],
    );
    let risky = [
        "Set-PSBreakpoint @p",
        "Set-PSBreakpoint -Command Get-Date @p",
        "Set-PSBreakpoint -Script build.ps1 -Line 3 @p",
        "sbp @p",
        "Start-Job { 1 } @p",
        "Start-Job -ScriptBlock { 1 } @p",
        "Start-Job @p",
        "Start-ThreadJob { 1 } @p",
        "Start-ThreadJob -ScriptBlock { 1 } @p",
        "Register-ScheduledJob -Name nightly -ScriptBlock { 1 } @p",
        "Invoke-Command @p",
        "Invoke-Command -ComputerName srv @p",
        "New-Module @p",
        "Measure-Command @p",
        "1..3 | ForEach-Object { $_ } @p",
        "1..3 | ForEach-Object @p",
        // The event cmdlets keep their own reading of a splat and of a
        // block that is not written out.
        "Register-EngineEvent PowerShell.Exiting -Action $b",
        "Register-EngineEvent @p",
    ]
    .map(|line| (line, Rule::Unknown));
    check(Shell::PowerShell, &windows(), &[], &risky);
}

#[test]
fn every_hook_on_invoke_command_is_read_set_or_called() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "$ExecutionContext.InvokeCommand.LocationChangedAction = { param($s, $e) }",
            "$ExecutionContext.InvokeCommand.set_CommandNotFoundAction({ param($n) })",
            "$ExecutionContext.InvokeCommand.set_PreCommandLookupAction({ param($n) })",
            "$ExecutionContext.InvokeCommand.set_PostCommandLookupAction({ param($n) })",
            "$ExecutionContext.InvokeCommand.set_LocationChangedAction({ param($s, $e) })",
            "$ExecutionContext.InvokeCommand.set_Other($b)",
            "$ExecutionContext.InvokeCommand.Other = $b",
        ],
        &[],
    );
    let risky = [
        "$ExecutionContext.InvokeCommand.LocationChangedAction = $b",
        "$ExecutionContext.InvokeCommand.LocationChangedAction += $b",
        "$ExecutionContext.InvokeCommand.LocationChangedAction = (Get-Block)",
        "$ExecutionContext.InvokeCommand.'LocationChangedAction' = $b",
        "$ExecutionContext.InvokeCommand.set_CommandNotFoundAction($b)",
        "$ExecutionContext.InvokeCommand.set_PreCommandLookupAction($b)",
        "$ExecutionContext.InvokeCommand.set_PostCommandLookupAction($b)",
        "$ExecutionContext.InvokeCommand.set_LocationChangedAction($b)",
        "$ExecutionContext.InvokeCommand.set_LocationChangedAction((Get-Block))",
        "$ExecutionContext.InvokeCommand.set_CommandNotFoundAction()",
        "$ExecutionContext.InvokeCommand.set_CommandNotFoundAction('x')",
    ]
    .map(|line| (line, Rule::Unknown));
    check(Shell::PowerShell, &windows(), &[], &risky);
}
