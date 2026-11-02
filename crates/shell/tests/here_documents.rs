//! Here-documents. The shell ends one only at a line that is exactly its
//! delimiter (for `<<-`, after leading tabs); the grammar also ends it at a
//! line only near the delimiter (` PY`, `PY `, `PY #...`, `PY ;...`), and
//! then judges the rest as shell commands while the program reads it as its
//! input, so such a line is Unreadable, not guessed at, in `"$(…)"` as
//! outside it. Bash, sh and zsh join a backslash-newline in an unquoted body
//! before they look for the end line, and the shell runs the `$(…)` and
//! backtick substitutions in such a body. Text before a here-document that
//! only looks like one, or whose quotes and brackets a plain scan misreads,
//! hides nothing that follows.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn a_here_document_ends_only_at_a_line_that_is_its_delimiter() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "cat <<'EOF'\nx\nEOF",
            "cat <<EOF\nx\nEOF",
            "cat <<-EOF\n\tx\n\tEOF",
            "cat <<-EOF\n\t\tx\n\t\tEOF",
            // A line that only holds the delimiter's letters is body.
            "cat <<'EOF'\nXEOF\nEOF",
            "cat <<'EOF'\nthe EOF marker\nEOF",
            // A command after the end is read as a command.
            "cat <<'EOF'\nx\nEOF\necho done",
            // In a double-quoted substitution, ending exactly.
            "git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\"",
            "x=\"$(cat <<'EOF'\nx\nEOF\n)\"",
            "echo \"$(cat <<EOF\nx\nEOF\n)\"",
            "echo \"`cat <<'EOF'\nx\nEOF\n`\"",
            "echo \"$(cat <<-EOF\n\tx\n\tEOF\n)\"",
            "echo \"$(psql <<'EOF'\nselect 1;\nEOF\n)\" && echo done",
            // A line that holds a different word is body.
            "echo \"$(sqlite3 db <<'EOF'\nselect 1;\nPY\nEOF\n)\" \"$(echo ')')\"",
        ],
        &[
            // A leading space.
            (
                "python3 - <<'PY'\nimport shutil\nfor PY in [1]:\n PY\n shutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<PY\nimport shutil\nfor PY in [1]:\n PY\n shutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<-'PY'\nimport shutil\nfor PY in [1]:\n PY\n shutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<'PY'\nimport shutil\ntry:\n pass\nexcept NameError:\n PY\n shutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            // A trailing space, a comment, a `;`, a tab after the word.
            (
                "python3 - <<'PY'\nimport shutil\nPY \nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<'PY'\nimport shutil\nPY #x\nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<'PY'\nimport shutil\nPY ;x\nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<'PY'\nimport shutil\nPY\t\nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            // The delimiter in quotes ends the body for neither the grammar
            // nor the shell, but is refused all the same (one simple rule).
            (
                "python3 - <<'PY'\nimport shutil\n'PY'\nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            (
                "python3 - <<'PY'\nimport shutil\n\"PY\"\nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            // `<<-` strips tabs only: a space in front is near.
            (
                "python3 - <<-'PY'\nimport shutil\n\t PY\nshutil.rmtree('/home/me')\n\tPY",
                Rule::Unreadable,
            ),
            // Every reader of a here-document.
            (
                "bash <<'EOF'\necho a\n EOF\nrm -rf /home/me\nEOF",
                Rule::Unreadable,
            ),
            (
                "sh -s <<'EOF'\necho a\nEOF \nrm -rf /home/me\nEOF",
                Rule::Unreadable,
            ),
            (
                "node <<'EOF'\nlet a = 1\n EOF\nrequire('fs').rmSync('/home/me')\nEOF",
                Rule::Unreadable,
            ),
            (
                "psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF",
                Rule::Unreadable,
            ),
            // A reader that is not special still gets the same answer.
            ("cat <<'EOF'\nx\n EOF\nrm -rf /home/me\nEOF", Rule::Unreadable),
            // The commonest way an agent writes a here-document is inside
            // `"$(…)"` (`git commit -m "$(cat <<'EOF' …)"`), so the same line
            // in double quotes, or in a backtick in double quotes, is as
            // unreadable as outside them.
            (
                "echo \"$(psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            (
                "x=\"$(psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            // The end line with a trailing space or a comment.
            (
                "echo \"$(psql <<'EOF'\nselect 1;\nEOF \ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            (
                "echo \"$(psql <<'EOF'\nselect 1;\nEOF #\ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            // An unquoted delimiter, and `<<-`.
            (
                "echo \"$(psql <<EOF\nselect 1;\n EOF\ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            (
                "echo \"$(psql <<-EOF\n\tselect 1;\n EOF\n\tdrop table t;\n\tEOF\n)\"",
                Rule::Unreadable,
            ),
            // A backtick in double quotes.
            (
                "echo \"`psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n`\"",
                Rule::Unreadable,
            ),
            (
                "x=\"`psql <<'EOF'\nselect 1;\nEOF \ndrop table t;\nEOF\n`\"",
                Rule::Unreadable,
            ),
            // Other readers.
            (
                "echo \"$(mysql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            (
                "echo \"$(sqlite3 db <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            (
                "echo \"$(bash <<'EOF'\necho a\n EOF\nrm -rf /home/me\nEOF\n)\"",
                Rule::Unreadable,
            ),
            // In a substitution in a substitution, in a subshell, in a pipe,
            // with words around it.
            (
                "echo \"$(echo \"$(psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)\")\"",
                Rule::Unreadable,
            ),
            (
                "echo \"$( (psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n) )\"",
                Rule::Unreadable,
            ),
            (
                "echo \"a\" \"$(psql <<'EOF' | cat\nselect 1;\n EOF\ndrop table t;\nEOF\n)\" \"b\"",
                Rule::Unreadable,
            ),
            (
                "echo \"`echo \"$(psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)\"`\"",
                Rule::Unreadable,
            ),
            // The same line outside the quotes.
            (
                "echo $(psql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF\n)",
                Rule::Unreadable,
            ),
        ],
    );
}

/// The shell joins each backslash-newline in the body of an unquoted
/// here-document before it expands the body and before it looks for the end
/// line, so `$(r\<newline>m -rf …)` in it runs `rm`. A quoted delimiter feeds
/// the body as it is. Bash, sh and zsh join a backslash-newline before they
/// compare a body line with the delimiter; dash and ksh do not. So a line that
/// took one in and is (joined, or in any piece) the delimiter or near it ends
/// the body for some shells and not for others: Unreadable. With `<<-` the
/// tabs of the line that goes on stay in every shell, so `\tEO\<newline>\tF`
/// is no delimiter, and the body goes on to the real end line, where the
/// statements in it are read.
#[test]
fn a_backslash_newline_in_an_unquoted_here_document_body_is_joined() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A quoted delimiter: the body is text, the backslash stays.
            "cat <<'EOF'\n$(r\\\nm -rf /home/me)\nEOF",
            "echo \"$(cat <<'EOF'\n$(r\\\nm -rf /home/me)\nEOF\n)\"",
            "cat <<\\EOF\n$(r\\\nm -rf /home/me)\nEOF",
            "cat <<'EOF'\nEO\\\nF\nEOF",
            // An escaped backslash is not a continuation, and the body stays
            // text: `\\` then a newline.
            "echo \"$(cat <<EOF\nx\\\\\nEOF\n)\"",
            // Continuations that come nowhere near the delimiter.
            "cat <<EOF\nlong \\\nline\nEOF",
            "cat <<-EOF\n\tx\\\n\ty\n\tEOF",
            "git commit -m \"$(cat <<EOF\nmsg \\\nmore\nEOF\n)\"",
            // The tabs stay after a backslash-newline, so this line is not the
            // delimiter in any shell, and `rm` is body text.
            "echo \"$(cat <<-EOF\n\tx\n\tEO\\\n\tF\nr\\\nm -rf /home/me\nEOF\n)\"",
        ],
        &[
            // The top-level form.
            ("cat <<EOF\n$(r\\\nm -rf /home/me)\nEOF", Rule::Delete),
            ("cat <<-EOF\nx $(r\\\nm -rf /home/me)\n\tEOF", Rule::Delete),
            ("cat <<-EOF\n$(rm -rf /home/me)\n\tEOF", Rule::Delete),
            // The same inside a double-quoted substitution.
            (
                "echo \"$(cat <<EOF\n$(r\\\nm -rf /home/me)\nEOF\n)\"",
                Rule::Delete,
            ),
            (
                "git commit -m \"$(cat <<EOF\nmsg $(r\\\nm -rf /home/me)\nEOF\n)\"",
                Rule::Delete,
            ),
            (
                "x=\"$(cat <<EOF\n$(r\\\nm -rf /home/me)\nEOF\n)\"",
                Rule::Delete,
            ),
            // In a backtick in double quotes.
            (
                "echo \"`cat <<EOF\n$(r\\\nm -rf /home/me)\nEOF\n`\"",
                Rule::Delete,
            ),
            // A line that takes in a backslash-newline and then is the
            // delimiter: bash, sh and zsh end the body there, dash and ksh
            // do not, so the line is Unreadable.
            (
                "echo \"$(cat <<EOF\nx\nEO\\\nF\nr\\\nm -rf /home/me\nEOF\n)\"",
                Rule::Unreadable,
            ),
            (
                "echo \"$(cat <<EOF\nx\nE\\\nOF\nr\\\nm -rf /home/me\nEOF\n)\"",
                Rule::Unreadable,
            ),
            (
                "echo \"`cat <<EOF\nx\nEO\\\nF\nr\\\nm -rf /home/me\nEOF\n`\"",
                Rule::Unreadable,
            ),
            // Joined, the line is the delimiter.
            (
                "psql <<EOF\nselect 1;\nEO\\\nF\ndrop table t;\nEOF",
                Rule::Unreadable,
            ),
            (
                "mysql <<EOF\nselect 1;\nEO\\\nF\ndrop table t;\nEOF",
                Rule::Unreadable,
            ),
            (
                "sh <<EOF\necho a\nE\\\nOF\nrm -rf /home/me\nEOF",
                Rule::Unreadable,
            ),
            // `<<-`: the tab is in front of the first piece only, and the
            // joined line is the delimiter after the tab comes off.
            (
                "psql <<-EOF\n\tselect 1;\n\tEO\\\nF\n\tdrop table t;\n\tEOF",
                Rule::Unreadable,
            ),
            (
                "mysql <<-EOF\n\tselect 1;\n\tEO\\\nF\n\tdrop table t;\n\tEOF",
                Rule::Unreadable,
            ),
            // A line that is the delimiter once joined from an empty piece.
            (
                "psql <<EOF\nselect 1;\nEOF\\\n\ndrop table t;\nEOF",
                Rule::Unreadable,
            ),
            // A piece is the delimiter (dash and ksh end the body there).
            (
                "psql <<EOF\nselect 1;\nx\\\nEOF\ndrop table t;\nEOF",
                Rule::Unreadable,
            ),
            (
                "mysql <<EOF\nselect 1;\nx\\\nEOF\ndrop table t;\nEOF",
                Rule::Unreadable,
            ),
            // Near the delimiter, joined or in a piece.
            (
                "psql <<EOF\nselect 1;\nEOF\\\n ;x\ndrop table t;\nEOF",
                Rule::Unreadable,
            ),
            (
                "psql <<EOF\nselect 1;\nx\\\n EOF\ndrop table t;\nEOF",
                Rule::Unreadable,
            ),
            // Inside a double-quoted substitution.
            (
                "echo \"$(psql <<EOF\nselect 1;\nEO\\\nF\ndrop table t;\nEOF\n)\"",
                Rule::Unreadable,
            ),
            (
                "echo \"$(psql <<-EOF\n\tselect 1;\n\tEO\\\nF\n\tdrop table t;\n\tEOF\n)\"",
                Rule::Unreadable,
            ),
            // With `<<-` the continued line keeps its tabs: the body goes on
            // to the real end line and its statements are read.
            (
                "psql <<-EOF\n\tselect 1;\n\tEO\\\n\tF\n\tdrop table t;\n\tEOF",
                Rule::DropData,
            ),
            (
                "mysql <<-EOF\n\tselect 1;\n\tEO\\\n\tF\n\tdrop table t;\n\tEOF",
                Rule::DropData,
            ),
        ],
    );
}

/// The shell runs a backtick substitution in the body of an unquoted
/// here-document, as it does a `$(...)`, so it is read as the code it is, and
/// a substitution that cannot be read makes the line `Unreadable`. A quoted
/// delimiter feeds the body as it is.
#[test]
fn a_backtick_substitution_in_an_unquoted_here_document_is_read_as_code() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "cat <<EOF\n`ls`\nEOF",
            "cat <<EOF\nlist: `echo hi` done\nEOF",
            "cat <<EOF\n``\nEOF",
            "cat <<EOF\n`echo é`\nEOF",
            "cat <<-EOF\n\t`ls`\n\tEOF",
            // A `\"` in the code reads the same with the backslash kept or off.
            "cat <<EOF\n`echo \"say \\\"hi\\\"\"`\nEOF",
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
            // A backtick in the text after an expansion is code, not a part
            // of the expansion.
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
            // After an expansion.
            ("cat <<EOF\n$USER `rm -rf /home/me`\nEOF", Rule::Delete),
            ("cat <<EOF\n${PWD} `rm -rf /home/me`\nEOF", Rule::Delete),
            ("cat <<EOF\n$(pwd) `rm -rf /home/me` $USER\nEOF", Rule::Delete),
            // The text around a backtick substitution does not hide it. An
            // escaped backtick is text; the next one is code.
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
            // Dash takes the backslash off `\"` (bash keeps it), so the
            // quote ends and the commands between two of them run.
            (
                "cat <<EOF\n`echo \"x\\\"; rm -rf /home/me; echo \\\"y\"`\nEOF",
                Rule::Delete,
            ),
            (
                "cat <<EOF\n`echo \"\\\"; rm -rf /home/me; \\\"\"`\nEOF",
                Rule::Delete,
            ),
            (
                "cat <<-EOF\n\t`echo \"x\\\"; rm -rf /home/me; echo \\\"y\"`\n\tEOF",
                Rule::Delete,
            ),
            // A quote in the code does not end it: the first backtick does.
            (
                "cat <<EOF\n`echo '` ; rm -rf /home/me ; echo '`\nEOF",
                Rule::Unreadable,
            ),
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

/// Text before a here-document that a plain scan misreads leaves the next
/// lines copied as a body, so a backslash-newline in them is never joined and
/// the `rm` it spells is never seen. A `<<` in arithmetic is a shift, not a
/// here-document. A backslash in `$'…'` escapes the next character, so `\'`
/// does not end it. A parenthesis in `${…}` (`${x/(/y}`) is text: counting it
/// kept the `)` that ends `$(` from being seen, and a later `'` in the
/// double-quoted rest then opened single quotes to the end of the text.
#[test]
fn text_before_a_here_document_that_a_scan_misreads_hides_nothing() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "echo \"$((1<<2))\"",
            "echo $((1<<2))\nls",
            "x=$(( x << 1 ))\nls",
            "((x<<1))\nls",
            "echo $'it\\'s'",
            "echo \"$(echo $'it\\'s')\"",
            "echo $$'a'\nls",
            "echo \"$(echo ${x/(/y}) it's\"",
            "echo \"$(echo ${x%(*}) it's\"\nls",
        ],
        &[
            // A shift in arithmetic.
            (
                "echo \"$((1<<2))\"\nr\\\nm -rf /home/me",
                Rule::Delete,
            ),
            (
                "echo \"$((x<<1))\"\nr\\\nm -rf /home/me",
                Rule::Delete,
            ),
            (
                "echo \"$(( x << 1 ))\"\nr\\\nm -rf /home/me",
                Rule::Delete,
            ),
            // Without the quotes, in an assignment, and as a command.
            ("echo $((1<<2))\nr\\\nm -rf /home/me", Rule::Delete),
            ("x=$(( x << 1 ))\nr\\\nm -rf /home/me", Rule::Delete),
            ("((x<<1))\nr\\\nm -rf /home/me", Rule::Delete),
            // A here-document line near its delimiter after such a prefix.
            (
                "echo \"$((1<<2))\"\npython3 - <<'PY'\nimport shutil\n PY\nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            // A word and the end of the line after `<<` in `$((` could be
            // the subshell `$((cat <<EOF` as well: not guessed at.
            (
                "echo \"$((cat <<EOF\nx\n EOF\nrm -rf /home/me\nEOF\n))\"",
                Rule::Unreadable,
            ),
            // An escaped quote in ANSI-C quotes.
            (
                "echo \"$(echo $'it\\'s')\"\nr\\\nm -rf /home/me",
                Rule::Delete,
            ),
            (
                "echo \"$(echo $'it\\'s')\" && r\\\nm -rf /home/me",
                Rule::Delete,
            ),
            (
                "echo \"$(printf $'a\\'b')\"\nr\\\nm -rf /home/me",
                Rule::Delete,
            ),
            (
                "echo \"`echo $'it\\'s'`\"\nr\\\nm -rf /home/me",
                Rule::Delete,
            ),
            // Without the double quotes.
            ("echo $'it\\'s'\nr\\\nm -rf /home/me", Rule::Delete),
            ("echo $(echo $'it\\'s')\nr\\\nm -rf /home/me", Rule::Delete),
            // An escaped backslash before the quote ends nothing: `\\` is
            // one backslash, and the quote after it ends the string.
            ("echo $'a\\\\'\nr\\\nm -rf /home/me", Rule::Delete),
            // A here-document line near its delimiter after such a prefix.
            (
                "echo \"$(echo $'it\\'s')\"\npython3 - <<'PY'\nimport shutil\n PY\nshutil.rmtree('/home/me')\nPY",
                Rule::Unreadable,
            ),
            // A parenthesis in an expansion in a substitution.
            (
                "echo \"$(echo ${x/(/y}) it's\"\nr\\\nm -rf /home/me",
                Rule::Delete,
            ),
            (
                "echo \"$(echo ${x%(*}) it's\"\nr\\\nm -rf /home/me",
                Rule::Delete,
            ),
            (
                "echo \"$(echo ${x#*(}) it's\"\nr\\\nm -rf /home/me",
                Rule::Delete,
            ),
            (
                "echo \"$(echo ${x//(/}) it's\"\nr\\\nm -rf /home/me",
                Rule::Delete,
            ),
            (
                "echo \"$(echo ${x/(/y})\" && echo \"it's\" && r\\\nm -rf /home/me",
                Rule::Delete,
            ),
            // Without the double quotes.
            (
                "echo $(echo ${x/(/y}) \"it's\"\nr\\\nm -rf /home/me",
                Rule::Delete,
            ),
            // Text the scan cannot close is not judged.
            ("echo \"$(echo ${x/(/y}) it's\n", Rule::Unreadable),
            ("echo 'a", Rule::Unreadable),
        ],
    );
}

/// A quoted delimiter is read through its closing quote, whatever it holds
/// (`<<'E;F'` is `E;F`): reading it short left the rest of the quote open, and
/// the body then copied everything after it, so a backslash-newline in the
/// lines below was never joined.
#[test]
fn a_quoted_delimiter_with_an_operator_or_space_is_read_whole() {
    let tail = "\nr\\\nm -rf /home/me";
    let rows: Vec<(String, Rule)> = [
        ("'E;F'", "E;F"),
        ("'E O'", "E O"),
        ("\"E O\"", "E O"),
        ("'E)'", "E)"),
        ("'E&F'", "E&F"),
        ("'E>F'", "E>F"),
        ("'E(F'", "E(F"),
        ("'E|F'", "E|F"),
    ]
    .iter()
    .flat_map(|(quoted, word)| {
        [
            format!("echo \"$(cat <<{quoted}\nx\n{word}\n)\"{tail}"),
            format!("echo \"`cat <<{quoted}\nx\n{word}\n`\"{tail}"),
        ]
    })
    .map(|line| (line, Rule::Delete))
    .collect();
    let rows: Vec<(&str, Rule)> = rows
        .iter()
        .map(|(line, rule)| (line.as_str(), *rule))
        .chain([
            // A here-document line near its delimiter after such a prefix.
            (
                "echo \"$(cat <<'E;F'\nx\nE;F\n)\"\npsql <<'EOF'\nselect 1;\n EOF\ndrop table t;\nEOF",
                Rule::Unreadable,
            ),
            // A quote that never closes is not read.
            ("cat <<'E;F\nx\nE;F", Rule::Unreadable),
        ])
        .collect();
    check(
        Shell::Posix,
        &posix(),
        &["echo \"$(cat <<'E;F'\nx\nE;F\n)\"", "cat <<'E O'\nx\nE O"],
        &rows,
    );
}
