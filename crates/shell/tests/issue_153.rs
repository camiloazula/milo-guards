//! A redirect on a group, a branch or a loop writes its file before the body
//! runs, from the folder the line is in then. A `cd` in the body that may not
//! have run (in a branch, after `&&` or `||`, in a loop body) leaves the line
//! in a folder that is not certain, so a later run of the file the redirect
//! wrote may be from the folder the file is in. `{ cd sub; echo x; } > x.sh;
//! bash x.sh` runs `sub/x.sh`, which is not written; `if false; then cd sub;
//! else echo x; fi > x.sh; bash x.sh` may run the `x.sh` it wrote.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_cd_that_may_not_have_run_in_a_redirected_body_leaves_the_folder_unsure() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A `cd` that surely ran: the file is written where the group
            // starts, and run from the folder it went to.
            "{ cd sub; echo x; } > x.sh; bash x.sh",
            "{ cd sub; echo x; } >> x.sh; bash x.sh",
            "{ cd sub && echo x; } > x.sh; bash x.sh",
            "if true; then cd sub; fi > x.sh; bash x.sh",
            "if :; then cd sub; fi > x.sh; bash x.sh",
            // A body that does not move the line.
            "{ echo x; } > x.sh; cat x.sh",
            "if test -d sub; then echo x; fi > x.sh; cat x.sh",
            "for i in a b; do echo x; done > x.sh; cat x.sh",
            // The file is not run.
            "if false; then cd sub; else echo x; fi > x.sh; cat x.sh",
            "{ echo x; false && cd sub; } > x.sh; cat x.sh",
            // Written and run somewhere else.
            "if false; then cd sub; else echo x; fi > x.sh; bash y.sh",
            "if false; then cd sub; else echo x; fi > x.sh; bash sub/y.sh",
            // The run is after a `cd` that surely ran, from a folder the
            // file was not written in.
            "{ echo x; false && cd sub; } > x.sh; cd other; bash x.sh",
        ],
        &[
            // The lines of the issue.
            (
                "if false; then cd sub; else echo x; fi > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "if test -d sub; then cd sub; else echo x; fi > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "case y in x) cd sub;; *) echo x;; esac > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "{ echo x; false && cd sub; } > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "{ echo x; [ -d sub ] && cd sub; } > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "{ echo x; cd sub || true; } > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "for i in $list; do cd sub; echo x; done > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "while read l; do echo x; cd sub; done < in.txt > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            // The same at the top level, as before.
            (
                "if false; then cd sub; fi; echo x > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            // Every way the file is written and run.
            ("if false; then cd sub; fi > x.sh; bash x.sh", Rule::Unknown),
            (
                "if false; then cd sub; else echo x; fi >> x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "if false; then cd sub; else echo x; fi > x.sh; ./x.sh",
                Rule::Unknown,
            ),
            (
                "if false; then cd sub; else echo x; fi > x.sh; sh ./x.sh",
                Rule::Unknown,
            ),
            (
                "if false; then cd sub; else echo x; fi > x.sh; source x.sh",
                Rule::Unknown,
            ),
            (
                "if false; then cd sub; else echo x; fi > x.sh; . ./x.sh",
                Rule::Unknown,
            ),
            // Every kind of body.
            (
                "if false; then echo x; else cd sub; fi > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "if a; then echo x; elif b; then cd sub; fi > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "case y in x) echo x;; *) cd sub;; esac > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "{ echo x; test -d sub && cd sub; } > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "{ echo x; cd sub || cd other; } > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "{ { echo x; false && cd sub; }; } > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "{ echo x; if false; then cd sub; fi; } > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "{ echo x; false && cd sub; echo y; } > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "until false; do echo x; cd sub; done > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "while false; do cd sub; done > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "for ((i = 0; i < 3; i++)); do echo x; cd sub; done > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            // More than one redirect, and a here-document.
            (
                "if false; then cd sub; else echo x; fi 2> err > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "if false; then cd sub; else echo x; fi > x.sh 2> err; bash x.sh",
                Rule::Unknown,
            ),
            (
                "{ echo x; false && cd sub; } <<EOF > x.sh\nin\nEOF\nbash x.sh",
                Rule::Unknown,
            ),
            // After a list, a branch or a loop earlier on the line.
            (
                "ls; { echo x; false && cd sub; } > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "ls && { echo x; false && cd sub; } > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "if a; then cd up; fi; { echo x; false && cd sub; } > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            // In a body that is itself redirected, or in a function.
            (
                "f() { { echo x; false && cd sub; } > x.sh; bash x.sh; }; f",
                Rule::Unknown,
            ),
            (
                "{ { echo x; false && cd sub; } > x.sh; bash x.sh; }",
                Rule::Unknown,
            ),
            // A write to a path with a folder in it.
            (
                "if false; then cd sub; else echo x; fi > sub/x.sh; bash sub/x.sh",
                Rule::Unknown,
            ),
            // Only a condition that is `true` or `:` alone surely takes the
            // branch.
            (
                "if true; then cd sub; else echo x; fi > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "if true && false; then cd sub; fi > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "if true; then echo x; elif a; then cd sub; fi > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            (
                "true() { false; }; if true; then cd sub; fi > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            // From `sub`, `../x.sh` is the file written where the line began.
            (
                "if false; then cd sub; else echo x; fi > x.sh; bash ../x.sh",
                Rule::Unknown,
            ),
            // The second `cd` runs only when the first did.
            (
                "{ cd sub && cd sub2; echo x; } > x.sh; bash x.sh",
                Rule::Unknown,
            ),
            // A subshell gives the line back, so the file is run where it is
            // written (as before).
            ("(cd sub; echo x) > x.sh; bash x.sh", Rule::Unknown),
        ],
    );
}

#[test]
fn a_cd_that_surely_ran_keeps_its_verdict() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "{ cd sub; echo x; } > x.sh; bash x.sh",
            "{ cd sub; cd sub2; echo x; } > x.sh; bash x.sh",
            "if true; then cd sub; fi > x.sh; bash x.sh",
            "ls; { cd sub; echo x; } > x.sh; bash x.sh",
        ],
        &[
            // The group starts in the folder the line was in, so the file
            // it writes is the one that is run after a `cd` back.
            (
                "{ cd sub; echo x; } > x.sh; cd ..; bash x.sh",
                Rule::Unknown,
            ),
        ],
    );
}
