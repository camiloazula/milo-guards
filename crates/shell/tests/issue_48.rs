//! The shell runs a backtick substitution in the body of an unquoted
//! here-document, as it does a `$(...)`. The grammar reads the `$(...)` there
//! but not the backticks, so what ran in them was judged as plain text. It is
//! read as the code it is, and a substitution that cannot be read makes the
//! line `Unreadable`.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_backtick_substitution_in_an_unquoted_here_document_is_read_as_code() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("cat <<EOF\n`rm -rf /home/me`\nEOF", Rule::Delete),
            ("cat <<EOF\nline `rm -rf /home/me` end\nEOF", Rule::Delete),
            ("cat <<-EOF\n\t`rm -rf /home/me`\n\tEOF", Rule::Delete),
            ("cat <<EOF | cat\n`rm -rf /home/me`\nEOF", Rule::Delete),
            ("cat <<EOF\n`sudo ls`\nEOF", Rule::Elevated),
            ("cat <<EOF\n`cat ~/.ssh/id_rsa`\nEOF", Rule::ReadSecret),
            // A reader of its input: the backticks run before it reads.
            (
                "python3 - <<PY\nprint(1)\n`rm -rf /home/me`\nPY",
                Rule::Delete,
            ),
            ("bash <<EOF\necho a\n`rm -rf /home/me`\nEOF", Rule::Delete),
            // A second here-document on the line, or one after a command.
            ("cat <<A <<B\nx\nA\n`rm -rf /home/me`\nB", Rule::Delete),
            ("true && cat <<EOF\n`rm -rf /home/me`\nEOF", Rule::Delete),
        ],
    );
}

#[test]
fn the_text_around_a_backtick_substitution_does_not_hide_it() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // An escaped backtick is text; the next one is code.
            ("cat <<EOF\n\\`x\\` `rm -rf /home/me`\nEOF", Rule::Delete),
            // Two backslashes are a backslash, so the backtick is code.
            ("cat <<EOF\n\\\\`rm -rf /home/me`\nEOF", Rule::Delete),
            // A backslash-newline is joined before the code is read.
            ("cat <<EOF\n`r\\\nm -rf /home/me`\nEOF", Rule::Delete),
            // The code takes `\``, `\\` and `\$` down one level.
            ("cat <<EOF\n`echo \\`rm -rf /home/me\\``\nEOF", Rule::Delete),
            ("cat <<EOF\n`rm -rf \\$HOME`\nEOF", Rule::Delete),
            // Code that goes over several lines, with tabs in a `<<-` body.
            (
                "cat <<-EOF\n\t`echo a\n\t&& rm -rf /home/me`\n\tEOF",
                Rule::Delete,
            ),
            // A backtick inside a `$(...)` is the grammar's own.
            ("cat <<EOF\n$(echo `rm -rf /home/me`)\nEOF", Rule::Delete),
            // In a message handed to a command.
            (
                "git commit -m \"$(cat <<EOF\nfix `rm -rf /home/me`\nEOF\n)\"",
                Rule::Delete,
            ),
            // A here-document in a substitution in a substitution.
            (
                "echo \"$(cat <<EOF\n`rm -rf /home/me`\nEOF\n)\"",
                Rule::Delete,
            ),
            // A here-document in the code is read in turn.
            (
                "cat <<EOF\n`cat <<X\nhi\nX\nrm -rf /home/me`\nEOF",
                Rule::Delete,
            ),
            // A quote in the code does not end it: the first backtick does.
            (
                "cat <<EOF\n`echo '` ; rm -rf /home/me ; echo '`\nEOF",
                Rule::Unreadable,
            ),
        ],
    );
}

#[test]
fn a_backtick_substitution_that_cannot_be_read_makes_the_line_unreadable() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // A backtick that never closes.
            ("cat <<EOF\n`rm -rf /home/me\nEOF", Rule::Unreadable),
            ("cat <<EOF\n`ls` `rm -rf /home/me\nEOF", Rule::Unreadable),
            ("cat <<EOF\nx \\``rm -rf /home/me\nEOF", Rule::Unreadable),
            // An escaped backtick, then one that never closes.
            ("cat <<EOF\n\\`rm -rf /home/me`\nEOF", Rule::Unreadable),
            // Code a shell refuses.
            ("cat <<EOF\n`echo 'a`\nEOF", Rule::Unreadable),
            ("cat <<EOF\n`if then fi`\nEOF", Rule::Unreadable),
            // A backtick the grammar read inside a `${...}`.
            ("cat <<EOF\n${x:-`rm -rf /home/me`}\nEOF", Rule::Unreadable),
            // A here-document in a backtick substitution: the outer one
            // takes a backslash off first, so the body is not what it shows.
            (
                "echo \"`cat <<EOF\n\\`rm -rf /home/me\\`\nEOF\n`\"",
                Rule::Unreadable,
            ),
            ("echo `cat <<EOF\n\\`ls\\`\nEOF\n`", Rule::Unreadable),
        ],
    );
}

#[test]
fn a_here_document_that_runs_nothing_reads_as_before() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "cat <<EOF\n`ls`\nEOF",
            "cat <<EOF\nlist: `echo hi` done\nEOF",
            "cat <<EOF\n``\nEOF",
            "cat <<EOF\n`echo é`\nEOF",
            "cat <<-EOF\n\t`ls`\n\tEOF",
            "git commit -m \"$(cat <<EOF\nfix `ls`\nEOF\n)\"",
            // A quoted delimiter feeds the body as it is.
            "cat <<'EOF'\n`rm -rf /home/me`\nEOF",
            "cat <<\\EOF\n`rm -rf /home/me`\nEOF",
            "cat <<\"EOF\"\n`rm -rf /home/me`\nEOF",
            "cat <<-'EOF'\n\t`rm -rf /home/me`\n\tEOF",
            "git commit -m \"$(cat <<'EOF'\nfix `rm -rf /home/me`\nEOF\n)\"",
            // An escaped backtick is text.
            "cat <<EOF\n\\`rm -rf /home/me\\`\nEOF",
            // A here-string is not a here-document.
            "cat <<< 'x `rm -rf /home/me`'",
            // No backtick at all.
            "cat <<EOF\nrm -rf /home/me\nEOF",
        ],
        &[],
    );
}

#[test]
fn a_backtick_in_the_text_after_an_expansion_is_read_as_code_not_as_a_part() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "cat > version.txt <<EOF\nversion=$VERSION\nbuilt=`date`\nEOF",
            "cat <<EOF\nHello $USER, today is `date +%A`.\nEOF",
            "cat <<EOF\n`echo $HOME`\nEOF",
            "cat <<EOF\n$(pwd) `ls`\nEOF",
            "git commit -m \"$(cat <<EOF\nRelease $VERSION\n\nAdds \\`--flag\\` to the parser.\nEOF\n)\"",
            "gh pr create --title x --body \"$(cat <<EOF\nCloses #$ISSUE\n\nUse \\`foo\\` here.\nEOF\n)\"",
            "cat <<EOF\nPath: ${PWD}\nRun `make` next.\nEOF",
            "cat <<EOF\nTotal: $((1+2)) files, see `ls`\nEOF",
            // An escaped backtick after an expansion is text.
            "cat <<EOF\n$(pwd) \\`x\\`\nEOF",
        ],
        &[
            ("cat <<EOF\n$USER `rm -rf /home/me`\nEOF", Rule::Delete),
            ("cat <<EOF\n${PWD} `rm -rf /home/me`\nEOF", Rule::Delete),
            ("cat <<EOF\n$(pwd) `rm -rf /home/me` $USER\nEOF", Rule::Delete),
        ],
    );
}
