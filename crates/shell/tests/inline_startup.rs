//! A `BASH_ENV` file a line writes runs in the shell that inline code starts:
//! the two readings (inline code, and files a shell runs first) hold together.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_shell_the_inline_code_starts_runs_the_startup_file() {
    check(
        Shell::Posix,
        &posix(),
        &[
        ],
        &[
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh python3 -c 'import os; os.system(\"bash -c true\")'",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; BASH_ENV=e.sh node -e 'require(\"child_process\").execSync(\"bash -c true\")'",
                Rule::Unknown,
            ),
            (
                "echo 'rm -rf ~' > e.sh; export BASH_ENV=e.sh; python3 -c 'import os; os.system(\"bash -c true\")'",
                Rule::Unknown,
            ),
            // Not read whole by the strict gate: unknown.
            ("BASH_ENV=e.sh python3 -c 'print(1)'", Rule::Unknown),
            ("echo hi > e.sh; python3 -c 'import os; os.system(\"bash -c true\")'", Rule::Unknown),
        ],
    );
}
