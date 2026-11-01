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

#[test]
fn a_named_initialization_script_leaves_the_positional_block_to_be_read() {
    let risky = [
        "Start-ThreadJob -InitializationScript { Import-Module x } $b",
        "Start-ThreadJob -Init { 1 } (Get-Block)",
        "Register-ScheduledJob -InitializationScript { 1 } nightly $b",
        "Register-ScheduledJob -Name nightly -InitializationScript { 1 } $b",
        "Register-ScheduledJob nightly $b",
        "Start-ThreadJob $b",
    ]
    .map(|line| (line, Rule::Unknown));
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Start-ThreadJob -InitializationScript { 1 } { cargo build }",
            "Start-ThreadJob -InitializationScript { 1 } -ScriptBlock { cargo build }",
            "Start-ThreadJob { cargo build } -Name build",
            "Register-ScheduledJob nightly { cargo build }",
            "Register-ScheduledJob -InitializationScript { 1 } nightly { cargo build }",
            "Register-ScheduledJob -Name nightly -InitializationScript { 1 } { cargo build }",
            "Register-ScheduledJob -Name nightly -InitializationScript { 1 } -ScriptBlock { cargo build }",
        ],
        &risky,
    );
}

#[test]
fn a_method_name_in_quotes_is_the_method() {
    let paths = windows();
    let risky = [
        "$ExecutionContext.InvokeCommand.'InvokeScript'('Remove-Item -Recurse -Force ~')",
        "$ExecutionContext.InvokeCommand.\"InvokeScript\"('Remove-Item -Recurse -Force ~')",
        "$ExecutionContext.InvokeCommand.\"NewScriptBlock\"($code)",
        "[scriptblock]::'Create'('Remove-Item -Recurse -Force ~')",
        "[scriptblock]::\"Create\"($code)",
        "$ExecutionContext.InvokeCommand.'set_CommandNotFoundAction'($b)",
        "$ExecutionContext.InvokeCommand.'ExpandString'($s)",
        "$b.'Invoke'()",
    ]
    .map(|line| (line, Rule::Unknown));
    check(
        Shell::PowerShell,
        &paths,
        &[],
        &[
            risky.as_slice(),
            &[("(Get-Item ~).'Delete'()", Rule::Delete)],
        ]
        .concat(),
    );
    for line in [
        "$ExecutionContext.InvokeCommand.'InvokeScript'('Remove-Item -Recurse -Force ~')",
        "[scriptblock]::'Create'('Remove-Item -Recurse -Force ~')",
    ] {
        let found = rules(line, Shell::PowerShell, &paths);
        assert!(found.contains(&Rule::Delete), "{line}: {found:?}");
    }
}

#[test]
fn expand_string_runs_the_subexpressions_in_its_text() {
    let paths = windows();
    for line in [
        "$ExecutionContext.InvokeCommand.ExpandString('$(Remove-Item -Recurse -Force ~)')",
        "$ExecutionContext.SessionState.InvokeCommand.ExpandString('a $(Remove-Item -Recurse -Force ~)')",
    ] {
        let found = rules(line, Shell::PowerShell, &paths);
        assert!(found.contains(&Rule::Delete), "{line}: {found:?}");
        assert!(found.contains(&Rule::Unknown), "{line}: {found:?}");
    }
    let risky = [
        "$ExecutionContext.InvokeCommand.ExpandString($s)",
        "$ExecutionContext.InvokeCommand.ExpandString('plain text')",
    ]
    .map(|line| (line, Rule::Unknown));
    check(Shell::PowerShell, &paths, &[], &risky);
}

#[test]
fn a_member_name_that_runs_code_or_deletes_is_the_method_called() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Get-ChildItem | ForEach-Object Name",
            "Get-ChildItem | % FullName",
            "Get-ChildItem | % -MemberName Length",
            "'a' | % ToUpper",
            "'a' | % -MemberName Replace -ArgumentList 'a', 'b'",
        ],
        &[
            ("$b | ForEach-Object Invoke", Rule::Unknown),
            ("$b | % -MemberName Invoke", Rule::Unknown),
            ("$b | % -MemberName:Invoke", Rule::Unknown),
            ("$b | ForEach-Object InvokeReturnAsIs", Rule::Unknown),
            ("$b | % InvokeWithContext", Rule::Unknown),
            ("$b | % 'Invoke'", Rule::Unknown),
            ("$b | % -Mem Invoke", Rule::Unknown),
            ("$b | % -MemberName $m", Rule::Unknown),
            ("Get-ChildItem | % Delete", Rule::Delete),
            (
                "Get-ChildItem | % -MemberName MoveTo -ArgumentList x",
                Rule::Delete,
            ),
            ("Get-Item HKCU:\\x | % DeleteSubKeyTree", Rule::Delete),
        ],
    );
}

#[test]
fn common_parameters_and_args_take_their_value() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Start-Job { npm test } -ErrorAction Stop",
            "Start-Job { npm test } -EA Stop",
            "Start-Job -ScriptBlock { npm test } -OutVariable j",
            "Start-Job -ScriptBlock { npm test } -OV j",
            "Start-Job -ErrorAction:Stop -ScriptBlock { npm test }",
            "Start-Job { param($a) $a } -Args $x",
            "Start-Job { npm test } -ErrorVariable e -WarningAction Ignore -WarningVariable w",
            "Start-Job { npm test } -InformationAction Ignore -InformationVariable i -ProgressAction SilentlyContinue",
            "Start-Job { npm test } -OutBuffer 2 -PipelineVariable p",
            "Start-ThreadJob { npm test } -ErrorAction Stop",
            "Start-ThreadJob -ScriptBlock { npm test } -EV e",
            "Register-ScheduledJob -Name nightly -ScriptBlock { npm test } -ErrorAction Stop",
            "Register-ScheduledJob nightly { npm test } -WA Ignore",
            "Invoke-Command { Get-Date } -ErrorAction Stop",
            "Invoke-Command -ErrorAction Stop { Get-Date }",
            "Invoke-Command { param($a) $a } -Args $x",
            "New-Module { function f { 1 } } -ErrorAction Stop",
            "Measure-Command { cargo build } -ErrorAction Stop",
            "1..3 | ForEach-Object { $_ } -Args $x",
            "1..3 | ForEach-Object { $_ } -ErrorAction Stop",
            "1..3 | ForEach-Object { $_ } -Confirm:$false",
            "1..3 | ForEach-Object -Confirm:$false { $_ }",
            "Start-Job { npm test } -Confirm:$false",
            "Start-Job -Confirm:$false { npm test }",
            "Invoke-Command { Get-Date } -Whatever:$x",
            "Set-PSBreakpoint -Script build.ps1 -Line 3 -Action { break } -ErrorAction Stop",
        ],
        &[
            // The value after a parameter is not hidden by what it follows.
            ("Start-Job { npm test } -ErrorAction Stop $i", Rule::Unknown),
            ("Start-Job -ErrorAction:Stop $b", Rule::Unknown),
            ("Start-ThreadJob -ErrorAction Stop $b", Rule::Unknown),
            ("1..3 | ForEach-Object -Confirm:$false $b", Rule::Unknown),
        ],
    );
}

#[test]
fn remaining_scripts_is_a_block_parameter() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "1 | ForEach-Object -Process { 1 } -RemainingScripts { 2 }",
            "1 | ForEach-Object -Process { 1 } -RemainingScripts { 2 }, { 3 }",
        ],
        &[
            (
                "1 | ForEach-Object -Process { 1 } -RemainingScripts $b",
                Rule::Unknown,
            ),
            (
                "1 | ForEach-Object -Process { 1 } -RemainingScripts:$b",
                Rule::Unknown,
            ),
            ("1 | ForEach-Object -Process { 1 } -Rem:$b", Rule::Unknown),
            (
                "1 | ForEach-Object -Process { 1 } -Remaining:$b",
                Rule::Unknown,
            ),
            (
                "1 | ForEach-Object -Process { 1 } -RemainingScripts:$b, $c",
                Rule::Unknown,
            ),
            (
                "1 | ForEach-Object -Process { 1 } -RemainingScripts { 2 }, $c",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn a_member_name_that_builds_code_or_sets_a_hook_is_judged() {
    let paths = windows();
    check(
        Shell::PowerShell,
        &paths,
        &[
            "$ExecutionContext.InvokeCommand | % -MemberName CommandNotFoundAction",
            "$ExecutionContext.InvokeCommand | % CommandNotFoundAction",
            "$ExecutionContext.InvokeCommand | % -MemberName CommandNotFoundAction -ArgumentList { 1 }",
            "$ExecutionContext.InvokeCommand | % -MemberName set_CommandNotFoundAction -ArgumentList { 1 }",
            "$ExecutionContext.InvokeCommand | % set_CommandNotFoundAction { 1 }",
        ],
        &[
            ("$ExecutionContext.InvokeCommand | % InvokeScript $s", Rule::Unknown),
            ("$ExecutionContext.InvokeCommand | % NewScriptBlock $s", Rule::Unknown),
            ("$ExecutionContext.InvokeCommand | % ExpandString $s", Rule::Unknown),
            ("$ExecutionContext.InvokeCommand | % 'InvokeScript' 'Get-Date'", Rule::Unknown),
            (
                "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript -ArgumentList $s",
                Rule::Unknown,
            ),
            ("$ExecutionContext.InvokeCommand | % set_CommandNotFoundAction $b", Rule::Unknown),
            ("$ExecutionContext.InvokeCommand | % set_CommandNotFoundAction", Rule::Unknown),
            ("$ExecutionContext.InvokeCommand | % set_LocationChangedAction $b", Rule::Unknown),
            (
                "$ExecutionContext.InvokeCommand | % -MemberName set_CommandNotFoundAction -ArgumentList $b",
                Rule::Unknown,
            ),
            (
                "$ExecutionContext.InvokeCommand | % -MemberName CommandNotFoundAction -ArgumentList $b",
                Rule::Unknown,
            ),
            ("$ExecutionContext.InvokeCommand | % CommandNotFoundAction $b", Rule::Unknown),
            (
                "$ExecutionContext.InvokeCommand | % -MemberName PreCommandLookupAction -Args $b",
                Rule::Unknown,
            ),
        ],
    );
    // The text given as the code is read, whichever way it is written out.
    for line in [
        "$ExecutionContext.InvokeCommand | % InvokeScript 'Remove-Item -Recurse -Force ~'",
        "$ExecutionContext.InvokeCommand | % -MemberName InvokeScript -ArgumentList 'Remove-Item -Recurse -Force ~'",
        "$ExecutionContext.InvokeCommand | % -MemberName:InvokeScript -ArgumentList:'Remove-Item -Recurse -Force ~'",
        "$ExecutionContext.InvokeCommand | % ExpandString '$(Remove-Item -Recurse -Force ~)'",
        "$ExecutionContext.InvokeCommand | % NewScriptBlock 'Remove-Item -Recurse -Force ~'",
    ] {
        let found = rules(line, Shell::PowerShell, &paths);
        assert!(found.contains(&Rule::Delete), "{line}: {found:?}");
        assert!(found.contains(&Rule::Unknown), "{line}: {found:?}");
    }
}

#[test]
fn what_follows_a_member_name_is_its_arguments() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "$list | % Add $item",
            "$s | % Substring 1 $n",
            "1 | ForEach-Object -MemberName Name $b",
            "$s | % -MemberName Substring -ArgumentList $a, $b",
            "$s | % 'Substring' $a $b",
        ],
        &[
            ("1 | ForEach-Object $b", Rule::Unknown),
            ("1 | ForEach-Object { 1 } $b", Rule::Unknown),
            ("1 | % { 1 } , $b", Rule::Unknown),
            ("1 | % $b Name", Rule::Unknown),
            ("$list | % Delete $item", Rule::Delete),
            ("1 | % Add -Process $b", Rule::Unknown),
        ],
    );
}

#[test]
fn where_object_runs_its_filter_script() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "1 | Where-Object { $_ -gt 1 }",
            "1 | ? { $_ -gt 1 }",
            "1 | where { $_ -gt 1 }",
            "Get-ChildItem | Where-Object -FilterScript { $_.Length -gt 1 }",
            "Get-ChildItem | ? -FilterScript:{ $_.Length -gt 1 }",
            "Get-ChildItem | ? -Filter { $_.Length -gt 1 }",
            // A word first is the property of the comparison form.
            "Get-ChildItem | ? Name -like '*.rs'",
            "Get-ChildItem | Where-Object Name -eq 'a.rs'",
            "Get-ChildItem | where Length -gt 100",
            "Get-ChildItem | ? 'Name' -like '*.rs'",
            "Get-ChildItem | ? -Property Name -Value x -EQ",
            "Get-ChildItem | ? -Property Name -Value $v -Like",
            "Get-ChildItem | ? -Property $p -Value $v -EQ",
            "Get-ChildItem | ? Name -in $names",
            "Get-ChildItem | ? -InputObject $x { 1 }",
            "Get-ChildItem | ? Name -ne $x -ErrorAction Stop",
            "Get-ChildItem | ? -FilterScript { 1 } @p",
        ],
        &[
            ("1 | Where-Object $b", Rule::Unknown),
            ("1 | ? $b", Rule::Unknown),
            ("1 | where $b", Rule::Unknown),
            (
                "Get-ChildItem | Where-Object -FilterScript $b",
                Rule::Unknown,
            ),
            ("Get-ChildItem | ? -Filter $b", Rule::Unknown),
            ("Get-ChildItem | ? -FilterScript:$b", Rule::Unknown),
            ("Get-ChildItem | ? -FilterScript (Get-Block)", Rule::Unknown),
            ("Get-ChildItem | ? (Get-Block)", Rule::Unknown),
            ("Get-ChildItem | ? $prop -eq 1", Rule::Unknown),
            ("Get-ChildItem | ? @p", Rule::Unknown),
            (
                "$t=[scriptblock]; $b=$t::Create('Remove-Item -Recurse -Force ~'); 1 | ? $b",
                Rule::Unknown,
            ),
            (
                "$b=[scriptblock]::Create('Remove-Item -Recurse -Force ~'); 1 | Where-Object $b",
                Rule::Unknown,
            ),
        ],
    );
}

/// Inside a provider a bare `NUL` or `CON` is an item there, not the device,
/// so the item cmdlets judge it as the provider's item.
#[test]
fn an_item_named_like_a_device_in_a_provider_is_an_item() {
    check(
        Shell::PowerShell,
        &windows(),
        &["cd C:\\x; Set-Content NUL x", "python x.py > $null"],
        &[
            (
                "cd HKLM:\\SOFTWARE\\Foo; Clear-Item NUL",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Clear-Item CON",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Set-Item NUL -Value 1",
                Rule::SystemSettings,
            ),
            ("cd HKLM:\\SOFTWARE\\Foo; si NUL 1", Rule::SystemSettings),
            ("cd HKLM:\\SOFTWARE\\Foo; cli NUL", Rule::SystemSettings),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Clear-Item -Path NUL",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Clear-Item -LiteralPath NUL",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Get-Item NUL | Clear-Item",
                Rule::SystemSettings,
            ),
            ("cd HKCU:\\Software; Clear-Item NUL", Rule::SystemSettings),
            (
                "cd Registry::HKEY_LOCAL_MACHINE\\SOFTWARE; Clear-Item NUL",
                Rule::SystemSettings,
            ),
            ("cd $key; Clear-Item NUL", Rule::Overwrite),
            ("cd Env:; Set-Item NUL -Value x", Rule::Overwrite),
            ("cd Variable:; Set-Item NUL -Value x", Rule::Overwrite),
            ("cd 1:; Set-Item NUL -Value 1", Rule::Overwrite),
            (
                "cd Function:; Set-Item NUL -Value 'Remove-Item ~ -Recurse'; NUL",
                Rule::Overwrite,
            ),
            (
                "cd Alias:; Set-Item NUL -Value Remove-Item",
                Rule::Overwrite,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Move-ItemProperty NUL CON -Name x",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Copy-ItemProperty NUL CON -Name x",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Move-ItemProperty -Path NUL -Destination CON -Name x",
                Rule::SystemSettings,
            ),
            (
                "cd HKLM:\\SOFTWARE\\Foo; Copy-ItemProperty -Path NUL -Destination CON -Name x",
                Rule::SystemSettings,
            ),
            (
                "cd $key; Move-ItemProperty NUL CON -Name x",
                Rule::Overwrite,
            ),
        ],
    );
}

#[test]
fn trace_command_runs_its_expression() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Trace-Command -Name ParameterBinding -Expression { Get-Date }",
            "Trace-Command -Name ParameterBinding -Expression:{ Get-Date }",
            "Trace-Command ParameterBinding { Get-Date }",
            "Trace-Command -Name ParameterBinding { Get-Date }",
            "Trace-Command $name { Get-Date }",
            "Trace-Command -Name ParameterBinding -Expression { Get-Date } -PSHost",
            "Trace-Command -Name ParameterBinding -Expression { Get-Date } -FilePath trace.log",
            "Trace-Command -Name $n -Expression { Get-Date } -Option All",
        ],
        &[
            (
                "Trace-Command -Name ParameterBinding -Expression $b",
                Rule::Unknown,
            ),
            ("Trace-Command -Name ParameterBinding -Exp $b", Rule::Unknown),
            ("Trace-Command ParameterBinding $b", Rule::Unknown),
            ("Trace-Command -Name ParameterBinding $b", Rule::Unknown),
            ("Trace-Command ParameterBinding Get-Date", Rule::Unknown),
            (
                "Trace-Command -Name ParameterBinding -Command Get-Date",
                Rule::Unknown,
            ),
            (
                "Trace-Command -Name ParameterBinding -Expression { 1 } @p",
                Rule::Unknown,
            ),
            (
                "$b=[scriptblock]::Create('Remove-Item -Recurse -Force ~'); Trace-Command ParameterBinding $b",
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn a_method_called_by_a_name_known_only_when_it_runs_is_unknown() {
    let paths = windows();
    let risky = [
        "$m='InvokeScript'; $ExecutionContext.InvokeCommand.$m('Remove-Item -Recurse -Force ~')",
        "$ExecutionContext.InvokeCommand.($m)('Remove-Item -Recurse -Force ~')",
        "$ExecutionContext.InvokeCommand.\"$m\"('x')",
        "$ExecutionContext.InvokeCommand.\"Invoke$('Script')\"('Remove-Item -Recurse -Force ~')",
        "$ExecutionContext.InvokeCommand.\"Invoke$($m)\"('x')",
        "$m=\"Delete\"; (Get-Item ~).$m()",
        "$m='Delete'; (Get-Item ~).$m()",
        "$m='Delete'; [IO.Directory]::$m('C:\\x', $true)",
        "$t::$m('x')",
        "$list.$m(1)",
        "$list.(Get-Name)(1)",
        "$list.{ Add }(1)",
        "$list.[string]$m(1)",
    ]
    .map(|line| (line, Rule::Unknown));
    check(Shell::PowerShell, &paths, &[], &risky);
    // A name written out stays the method it names: constant strings, with
    // or without quotes, and the escape in a double-quoted one.
    check(
        Shell::PowerShell,
        &paths,
        &[
            "$list.Add(1)",
            "$list.'Add'(1)",
            "$list.\"Add\"(1)",
            "$s.Substring(1)",
            "$s.\"Substring\"(1)",
            "[Math]::Max(1, 2)",
            "[Math]::\"Max\"(1, 2)",
            // A property read has no argument list: a name only known when
            // it runs is a column, not a call.
            "$row.$col",
            "$row.$col.Name",
            "$row.\"$col\"",
            "$row.($col)",
            "$row.$col = 1",
            "Write-Output $row.$col",
        ],
        &[
            ("$e.InvokeCommand.InvokeScript('x')", Rule::Unknown),
            ("$e.InvokeCommand.'InvokeScript'('x')", Rule::Unknown),
            ("$e.InvokeCommand.\"InvokeScript\"('x')", Rule::Unknown),
            ("$e.InvokeCommand.\"Invoke`Script\"('x')", Rule::Unknown),
            ("(Get-Item ~).\"Delete\"()", Rule::Delete),
            ("(Get-Item ~).\"Del`ete\"()", Rule::Delete),
        ],
    );
}
