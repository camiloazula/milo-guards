//! A device spelling is the same in any folder, so a redirect to it after a
//! `cd` to a place the guard cannot read is not a write to an unknown file.

mod common;

use common::{check, windows};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_null_device_after_an_unreadable_cd_is_safe() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "cd $dir; python x.py > $null",
            "cd $dir; python x.py > NUL",
            "cd $dir; python x.py > NUL:",
            "cd $dir; python x.py 2> $null",
            "cd $dir; python x.py *> nul",
            "cd $dir; python x.py | Out-File $null",
            "cd $dir; python x.py | Out-File -FilePath NUL",
            "Set-Location $dir; python x.py > $null",
            "cd $dir; python x.py > CON",
        ],
        &[
            // Only a device is the same in any folder.
            ("cd $dir; python x.py > out.txt", Rule::Overwrite),
            ("cd $dir; python x.py > nulx", Rule::Overwrite),
            ("cd $dir; python x.py > .\\NUL", Rule::Overwrite),
            ("cd $dir; python x.py > sub\\NUL", Rule::Overwrite),
            ("cd $dir; python x.py > $null.txt", Rule::Overwrite),
            ("cd $dir; python x.py > $out", Rule::Overwrite),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            "cd %X% & bash x.sh > nul",
            "cd %X% & bash x.sh > NUL",
            "cd %X% & bash x.sh 2> nul",
            "cd %X% & bash x.sh >nul 2>&1",
            "cd %X% & bash x.sh > nul:",
            "cd %X% & bash x.sh > con",
        ],
        &[
            ("cd %X% & bash x.sh > out.txt", Rule::Overwrite),
            ("cd %X% & bash x.sh > sub\\nul", Rule::Overwrite),
            ("cd %X% & bash x.sh > nulx", Rule::Overwrite),
        ],
    );
}

#[test]
fn a_null_device_after_a_readable_cd_is_not_a_file_there() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "cd C:\\other; python x.py > $null",
            "cd C:\\other; python x.py > NUL",
        ],
        &[("cd C:\\other; python x.py > out.txt", Rule::Overwrite)],
    );
    check(
        Shell::Cmd,
        &windows(),
        &["cd /d C:\\other & bash x.sh > nul"],
        &[("cd /d C:\\other & bash x.sh > out.txt", Rule::Overwrite)],
    );
}

#[test]
fn a_posix_device_after_an_unreadable_cd_is_safe() {
    check(
        Shell::Posix,
        &common::posix(),
        &[
            "cd $dir && python x.py > /dev/null",
            "cd $dir && python x.py 2> /dev/null",
            "cd $dir && python x.py &> /dev/null",
        ],
        &[
            ("cd $dir && python x.py > out.txt", Rule::Overwrite),
            ("cd $dir && python x.py > dev/null", Rule::Overwrite),
        ],
    );
}
