//! The text a database client gets, read as the client gets it: what
//! `printf` and `echo` print (their escapes, octal, and what a shell leaves as
//! written), what `cat` passes on, here-documents and templates, every program
//! of a stage and every client after it, SQL that runs SQL it holds, and what
//! a client or its server reads in it (backslashes, the client's variables).
//! A text only known when it runs is `unknown`; a text that says too much is
//! not read. What each client does with a statement is in `drop_data.rs`.

mod common;

use std::fmt::Write;
use std::time::Duration;

use common::{assert_linear, check, filled, posix, took, windows};
use milo_guards_shell::{classify, Rule, Shell};

#[test]
fn text_fed_to_a_client() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "psql <<EOF\nSELECT 1;\nEOF",
            "psql app <<EOF\nINSERT INTO t VALUES (1);\nEOF",
            "psql app <<'EOF'\nSELECT '$x';\nEOF",
            "psql <<< 'SELECT 1'",
            "psql <<< \"SELECT * FROM users WHERE id = $id\"",
            "psql <<EOF\nDELETE FROM users WHERE id = $id;\nEOF",
            "mysql <<< 'SELECT 1'",
            "sqlite3 data.db <<< 'DROP TABLE t'",
            "sqlite3 data.db <<EOF\nDROP TABLE t;\nEOF",
            "cat <<EOF\nDROP TABLE t;\nEOF",
            "echo 'DROP TABLE users' | cat",
            "echo 'SELECT 1' | psql",
            "printf 'SELECT 1;\\n' | psql app",
            "cat schema.sql | psql app",
            "echo 'DROP TABLE users' | tee log.txt",
        ],
        &[
            ("psql <<EOF\nDROP TABLE users;\nEOF", Rule::DropData),
            (
                "psql app <<EOF\nSELECT 1;\nDELETE FROM users;\nEOF",
                Rule::DropData,
            ),
            ("psql app <<-EOF\n\tTRUNCATE users;\n\tEOF", Rule::DropData),
            ("psql app <<'EOF'\nDROP TABLE $x;\nEOF", Rule::DropData),
            ("psql <<EOF\nDROP TABLE $t;\nEOF", Rule::DropData),
            ("psql <<< 'DROP TABLE users'", Rule::DropData),
            ("psql <<< \"DELETE FROM users\"", Rule::DropData),
            ("psql <<< \"DROP TABLE $t\"", Rule::DropData),
            ("mysql <<< 'TRUNCATE users'", Rule::DropData),
            ("mysql app <<EOF\nDROP TABLE users;\nEOF", Rule::DropData),
            ("sqlite3 ~/x.db <<< 'DELETE FROM t'", Rule::DropData),
            ("psql <<< \"$Q\"", Rule::Unknown),
            ("psql <<EOF\n$Q\nEOF", Rule::Unknown),
            ("psql <<EOF\n$(cat q.sql)\nEOF", Rule::Unknown),
            ("psql <<EOF | cat\nDROP TABLE users;\nEOF", Rule::DropData),
            (
                "psql app <<EOF && echo done\nDROP TABLE users;\nEOF",
                Rule::DropData,
            ),
            (
                "{ psql app; } <<EOF\nDROP TABLE users;\nEOF",
                Rule::DropData,
            ),
            ("psql -c 'SELECT 1' <<< 'DROP TABLE users'", Rule::DropData),
            ("echo 'DROP TABLE users' | psql", Rule::DropData),
            ("echo 'DROP TABLE users;' | psql app", Rule::DropData),
            ("echo \"TRUNCATE users\" | mysql app", Rule::DropData),
            ("printf 'DROP TABLE %s;' users | psql", Rule::DropData),
            ("echo -n 'DROP TABLE users' | psql", Rule::DropData),
            (
                "cat <<EOF | psql app\nDROP TABLE users;\nEOF",
                Rule::DropData,
            ),
            ("echo \"$Q\" | psql", Rule::Unknown),
        ],
    );
}

#[test]
fn printf_and_echo_decode_their_escapes() {
    check(
        Shell::Posix,
        &posix(),
        &[
            r"printf 'SELECT 1;\n' | psql",
            r"printf '%s\n' 'SELECT 1' | psql",
            r"printf 'SELECT %d;\n' 1 | psql",
            r#"printf 'SELECT %s;\n' "$id" | psql"#,
            r"printf '%%\n' | psql",
            r"echo 'SELECT 1;\nSELECT 2;' | psql",
            r"echo -e 'SELECT 1;\tSELECT 2;' | psql",
            r"echo -n 'SELECT 1' | psql",
            r"printf 'SELECT 1;\n' | redis-cli",
            "printf 'SELECT 1;\\n' | sqlite3 data.db",
            // Octal, as every shell reads it.
            r"printf 'SELECT \061;\n' | psql",
            r"printf 'SELECT 1;\0121' | psql",
            // `%b` and `echo` take `\0NNN`.
            r"printf '%b' 'SELECT \0061;' | psql",
        ],
        &[
            (
                r"printf 'SELECT 1;\nDROP TABLE users;\n' | psql",
                Rule::DropData,
            ),
            (
                r"printf 'BEGIN;\nDELETE FROM users;\nCOMMIT;\n' | psql app",
                Rule::DropData,
            ),
            (
                r"echo -e 'SELECT 1;\nDROP TABLE users;' | psql",
                Rule::DropData,
            ),
            (
                r"echo 'SELECT 1;\nDROP TABLE users;' | psql",
                Rule::DropData,
            ),
            (
                r"echo -e 'SELECT 1;\nDROP TABLE users;' | mysql app",
                Rule::DropData,
            ),
            (r"printf 'SET a 1\nFLUSHALL\n' | redis-cli", Rule::DropData),
            (r"printf '\x44ROP TABLE users' | psql", Rule::DropData),
            (r"printf 'D\122OP TABLE users' | psql", Rule::DropData),
            (r"echo -e 'DR\x4fP TABLE users' | psql", Rule::DropData),
            (r"printf 'DR%sP TABLE users' O | psql", Rule::DropData),
            (r"printf 'DR%bP TABLE users' '\x4f' | psql", Rule::DropData),
            (
                r"printf 'SELECT %d;\nDROP TABLE t;' 1 | psql",
                Rule::DropData,
            ),
            // The format is used again while arguments are left.
            (
                r"printf '%s\n' 'SELECT 1' 'DROP TABLE users' | psql",
                Rule::DropData,
            ),
            (
                r"printf '%s;%s' 'SELECT 1' 'DROP TABLE users' | psql",
                Rule::DropData,
            ),
            (r#"printf "DROP TABLE %s\n" "$t" | psql"#, Rule::DropData),
            // `\0121` is a newline and a `1` in a format, not a `Q`: the
            // DROP is not in the comment.
            (
                r"printf 'SELECT -- x\0121 AS a; DROP TABLE t;' | psql",
                Rule::DropData,
            ),
            // `%b` and `echo` read `\0121` as a `Q`.
            (
                r"printf '%b' 'SELECT -- x\0121 AS a;\nDROP TABLE t;' | psql",
                Rule::DropData,
            ),
            (
                r"printf '%b' 'SELECT 1;\0121\nDROP TABLE t;' | psql",
                Rule::DropData,
            ),
            (r"printf '%b' 'D\0122OP TABLE t' | psql", Rule::DropData),
            // The first digit of an escape in a format may be any octal one.
            (r"printf 'DROP TABLE t;\101' | psql", Rule::DropData),
            // dash's `printf` leaves `\xHH` as written, and decodes `\n`:
            // the quote is not one there, and the DROP runs.
            (
                r"printf 'SELECT 1;\x27\nDROP TABLE t;\n\x27' | psql",
                Rule::DropData,
            ),
            (
                r"echo -e 'SELECT 1;\x27\nDROP TABLE t;\n\x27' | psql",
                Rule::DropData,
            ),
            (
                r"echo 'SELECT 1;\x27\nDROP TABLE t;\n\x27' | psql",
                Rule::DropData,
            ),
            (
                r"printf '%b' 'SELECT 1;\x27\nDROP TABLE t;\n\x27' | psql",
                Rule::DropData,
            ),
            // Where bash's `echo -e` and zsh's leave `\NNN` as written, dash
            // decodes it.
            (
                r"echo 'SELECT 1;\47\nDROP TABLE t;\n\47' | psql",
                Rule::DropData,
            ),
            // Bash decodes `\'` and zsh and dash leave it.
            (
                r#"printf "SELECT 'a\\'; DROP TABLE t; --'" | psql"#,
                Rule::DropData,
            ),
            // Anything else printf does is not read.
            (r"printf '%q' x | psql", Rule::Unknown),
            (r"printf '%5s\n' x | psql", Rule::Unknown),
            (r"printf '%d' x | psql", Rule::Unknown),
            (r"printf '\u0044ROP TABLE t' | psql", Rule::Unknown),
            (r"printf '\q' | psql", Rule::Unknown),
            (r#"printf '%s' "$Q" | psql"#, Rule::Unknown),
            (r"printf '\x80' | psql", Rule::Unknown),
            // `\c` in a format is read differently: unknown.
            (r"printf 'SELECT 1;\c' | psql", Rule::Unknown),
        ],
    );
}

#[test]
fn a_cat_that_reads_its_input_passes_the_text_on() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A file operand and no `-`: the text is not read.
            "cat seed.sql <<< 'DROP TABLE t' | psql",
            "cat schema.sql <<EOF | psql\nDROP TABLE t;\nEOF",
            "cat -n schema.sql <<EOF | psql\nDROP TABLE t;\nEOF",
            "cat -- schema.sql <<EOF | psql\nDROP TABLE t;\nEOF",
            "cat -- -n <<EOF | psql\nDROP TABLE t;\nEOF",
            "cat schema.sql | psql",
            // What it passes on is read.
            "cat - <<< 'SELECT 1' | psql",
            "cat -n <<< 'SELECT 1' | psql",
            "cat <<EOF | psql\nSELECT 1;\nEOF",
            "cat -s <<EOF | psql\nSELECT 1;\nEOF",
            "cat - schema.sql <<EOF | psql\nSELECT 1;\nEOF",
        ],
        &[
            ("cat <<< 'DROP TABLE t' | psql", Rule::DropData),
            ("cat - <<< 'DROP TABLE t' | psql", Rule::DropData),
            ("cat - - <<< 'DROP TABLE t' | psql", Rule::DropData),
            ("cat - <<EOF | psql\nDROP TABLE t\nEOF", Rule::DropData),
            ("cat <<EOF | psql\nDROP TABLE t;\nEOF", Rule::DropData),
            ("cat - <<EOF | psql\nDROP TABLE t;\nEOF", Rule::DropData),
            (
                "cat - schema.sql <<EOF | psql\nDROP TABLE t;\nEOF",
                Rule::DropData,
            ),
            (
                "cat schema.sql - <<EOF | psql\nDROP TABLE t;\nEOF",
                Rule::DropData,
            ),
            (
                "cat /dev/stdin <<EOF | psql\nDROP TABLE t;\nEOF",
                Rule::DropData,
            ),
            ("cat -s <<EOF | psql\nDROP TABLE t;\nEOF", Rule::DropData),
            (
                "cat -n -- - <<EOF | psql\nDROP TABLE t;\nEOF",
                Rule::DropData,
            ),
            (
                "cat -A - a.sql <<EOF | psql\nDROP TABLE t;\nEOF",
                Rule::DropData,
            ),
            // An operand only known when it runs may be `-`.
            ("cat $f <<EOF | psql\nDROP TABLE t;\nEOF", Rule::DropData),
            ("cat -s <<< 'DROP TABLE t;' | psql", Rule::DropData),
        ],
    );
}

#[test]
fn an_unquoted_here_document_is_read_as_the_shell_feeds_it() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // A quoted delimiter feeds the body as it is.
            "psql <<'EOF'\nSELECT '\\$HOME' AS a;\nEOF",
            "psql <<\\EOF\nSELECT '$HOME' AS a;\nEOF",
            // `\$` is a `$` that the client gets, so the string is a string.
            "psql <<EOF\nSELECT '\\$HOME' AS a;\nEOF",
            // `\\` is one backslash.
            "psql <<EOF\nSELECT 'it\\\\' AS a;\nEOF",
            "psql <<EOF\nSELECT 1,\\\n2;\nEOF",
            // With `<<-` the tabs of the line that goes on stay in every
            // shell (bash, sh, dash, ksh, zsh), so the client gets `DR`, a
            // tab and `OP TABLE t`, not `DROP`.
            "psql <<-EOF\n\tDR\\\n\tOP TABLE t\n\tEOF",
            // What a dollar-quoted string holds is not code, when its `$` are
            // the client's.
            "psql <<EOF\nSELECT \\$\\$ ; DROP TABLE t; \\$\\$;\nEOF",
            "psql <<'EOF'\nSELECT $$ ; DROP TABLE t; $$;\nEOF",
        ],
        &[
            // A backslash and a newline are taken out: `DROP`.
            ("psql <<EOF\nDR\\\nOP TABLE t\nEOF", Rule::DropData),
            ("cat <<EOF | psql\nDR\\\nOP TABLE t\nEOF", Rule::DropData),
            ("psql <<-EOF\n\tDR\\\nOP TABLE t\n\tEOF", Rule::DropData),
            // `$$` is the shell's process id, not a string.
            (
                "psql <<EOF\nSELECT $$ ; DROP TABLE t; $$\nEOF",
                Rule::DropData,
            ),
            (
                "cat <<EOF | psql\nSELECT $$ ; DROP TABLE t; $$\nEOF",
                Rule::DropData,
            ),
            // `\\!` is `\!` for the client.
            ("psql <<EOF\n\\\\! touch x\nEOF", Rule::Unknown),
            // `\$x` is `$x` and not a string.
            (
                "psql <<EOF\nSELECT 1; \\$x ; DROP TABLE t\nEOF",
                Rule::DropData,
            ),
            (
                "psql <<EOF\nSELECT 1; \\`x\\` ; DROP TABLE t\nEOF",
                Rule::DropData,
            ),
            // A body that has both an escaped and an expanding `$` is only
            // known when it runs.
            (
                "psql <<EOF\nSELECT 1; \\$( ; DROP TABLE t; $x\nEOF",
                Rule::Unknown,
            ),
            // A MySQL string that the backslashes leave open.
            ("mysql <<EOF\nSELECT 'a\\\\' AS x;\nEOF", Rule::Unknown),
        ],
    );
}

#[test]
fn an_escaped_dollar_or_backtick_in_a_template_is_not_known() {
    check(
        Shell::Posix,
        &posix(),
        &[
            // No escape: the expansions are read where they stand.
            "psql <<< \"SELECT 1 $x\"",
            "echo \"SELECT 1 $x\" | psql",
            // Escapes with no expansion are a plain string.
            "psql <<< \"SELECT '\\$HOME'\"",
            "echo \"SELECT '\\$HOME'\" | psql",
        ],
        &[
            (
                "psql <<< \"SELECT \\$( ; DROP TABLE t; ) $x\"",
                Rule::Unknown,
            ),
            (
                "psql <<< \"SELECT 1 \\`; DROP TABLE t; \\` $x\"",
                Rule::Unknown,
            ),
            (
                "psql <<< \"SELECT \\${ ; DROP TABLE t; } $x\"",
                Rule::Unknown,
            ),
            (
                "echo \"SELECT 1 \\`; DROP TABLE t; \\` $x\" | psql",
                Rule::Unknown,
            ),
            (
                "echo \"SELECT \\$( ; DROP TABLE t; ) $x\" | psql",
                Rule::Unknown,
            ),
            (
                "printf \"SELECT \\${ ; DROP TABLE t; } $x\" | psql",
                Rule::Unknown,
            ),
            (
                "psql -c \"SELECT \\$( ; DROP TABLE t; ) $x\"",
                Rule::Unknown,
            ),
            // Read as written, a drop still is one.
            ("psql <<< \"DROP TABLE t; $x\"", Rule::DropData),
            ("echo \"DROP TABLE $x\" | psql", Rule::DropData),
        ],
    );
}

#[test]
fn an_expansion_stuck_to_a_word_ends_the_word() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "psql -c \"SELECT 1 FROM t WHERE a = $x\"",
            "psql -c \"SELECT a$x FROM t\"",
            "psql -c \"SELECT $x FROM t\"",
            "psql -c \"DELETE FROM t WHERE a = $x\"",
            "mongosh --eval \"db.users.find$x()\"",
            "mongosh --eval \"db.users.find({a: $x})\"",
            // A `$` that is no expansion stays in the word.
            "psql -c 'DROP$x TABLE t'",
        ],
        &[
            ("psql -c \"DROP$x TABLE t\"", Rule::DropData),
            ("psql -c \"DROP${x} TABLE t\"", Rule::DropData),
            ("psql -c \"DROP$(x) TABLE t\"", Rule::DropData),
            ("psql -c \"TRUNCATE$x t\"", Rule::DropData),
            ("psql -c \"DELETE$opts FROM t\"", Rule::DropData),
            ("mysql -e \"DROP$x TABLE t\"", Rule::DropData),
            ("mongosh --eval \"db.dropDatabase$x()\"", Rule::DropData),
            ("mongosh --eval \"db.dropDatabase${x}()\"", Rule::DropData),
            ("mongosh --eval \"db.users.remove$x()\"", Rule::DropData),
            ("mongosh --eval \"db.users.drop${x}()\"", Rule::DropData),
            ("mongosh --eval \"db.drop${x}Database()\"", Rule::DropData),
        ],
    );
}

#[test]
fn on_powershell_and_cmd_an_expansion_in_a_statement_is_unknown() {
    // An expansion in a double-quoted word is not read as a word there:
    // what it holds is only known when it runs.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            r#"psql -c "SELECT 1""#,
            r"psql -c 'DELETE FROM t WHERE id = $id'",
            r#"psql -c "DELETE FROM t WHERE id = 3""#,
        ],
        &[
            (r#"psql -c "DELETE FROM t WHERE id = $id""#, Rule::Unknown),
            (
                r#"psql -c "SELECT * FROM t WHERE name = '$name'""#,
                Rule::Unknown,
            ),
            (r#"psql -c "DROP TABLE t; $x""#, Rule::Unknown),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            r#"psql -c "SELECT 1""#,
            r#"psql -c "DELETE FROM t WHERE id = 3""#,
        ],
        &[
            (r#"psql -c "DELETE FROM t WHERE id = %id%""#, Rule::Unknown),
            (r#"psql -c "DROP TABLE t; %x%""#, Rule::Unknown),
        ],
    );
}

/// Every program of a stage feeds one text to the clients after it, and every
/// client of the next stage reads it, each where it runs.
#[test]
fn every_program_and_every_client_of_a_stage_is_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "{ echo 'SELECT 1'; echo 'SELECT 2'; } | psql",
            "(echo 'BEGIN;'; echo 'SELECT 1;'; echo 'COMMIT;') | psql",
            "{ echo 'SELECT 1'; printf 'SELECT 2;\\n'; } | psql",
            "{ echo 'DROP TABLE users'; } | cat",
            "{ echo 'SELECT 1;'; } | { psql; mysql; sqlite3 :memory:; }",
            "{ echo '.backup backup.db'; } | { sqlite3 d.db; sqlite3 e.db; }",
            "{ echo '.backup /tmp/b.db'; } | sqlite3 d.db",
        ],
        &[
            (
                "{ echo 'BEGIN;'; echo 'DELETE FROM users;'; echo 'COMMIT;'; } | psql",
                Rule::DropData,
            ),
            (
                "(echo 'SELECT 1'; echo 'DROP TABLE users') | psql",
                Rule::DropData,
            ),
            (
                "(echo 'DROP TABLE users'; echo 'SELECT 1') | psql",
                Rule::DropData,
            ),
            (
                "{ echo 'SELECT 1'; printf 'DROP TABLE users;\\n'; } | psql",
                Rule::DropData,
            ),
            (
                "(echo 'SELECT 1'; echo 'FLUSHALL') | redis-cli",
                Rule::DropData,
            ),
            (
                "if true; then echo 'DROP TABLE users'; fi | psql",
                Rule::DropData,
            ),
            // What they say one after the other is one text.
            (
                "{ echo -n 'DR'; echo -n 'OP TABLE users'; } | psql",
                Rule::DropData,
            ),
            (
                "(printf 'DELETE FROM'; printf ' users') | psql",
                Rule::DropData,
            ),
            ("(echo 'SELECT 1'; echo \"$Q\") | psql", Rule::Unknown),
            // Every client after the stage.
            (
                "{ echo 'DROP TABLE t;'; } | { psql; mysql; }",
                Rule::DropData,
            ),
            (
                "{ echo 'DROP TABLE t;'; } | { sqlite3 :memory:; psql; }",
                Rule::DropData,
            ),
            (
                "{ echo 'FLUSHALL'; } | { redis-cli; redis-cli; }",
                Rule::DropData,
            ),
            (
                "{ printf 'DROP TABLE t;'; } | { redis-cli; psql; }",
                Rule::DropData,
            ),
            // What a stage backs up is judged where each client runs.
            (
                "{ echo '.backup ~/prod.db'; } | { sqlite3 d.db; sqlite3 e.db; }",
                Rule::DropData,
            ),
            (
                "{ echo '.backup backup.db'; } | { sqlite3 d.db; cd /home/me; sqlite3 e.db; }",
                Rule::DropData,
            ),
            (
                "{ echo '.backup ~/prod.db'; echo '.save ~/x.db'; } | duckdb d.db",
                Rule::DropData,
            ),
        ],
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_stage_that_says_too_much_is_not_read_and_stays_quick() {
    // Five printfs of 63 KB each are more than a stage may say: unknown, and
    // not printed in full for each client.
    let args = "a ".repeat(1000);
    let printf = format!("printf '%s{}' {args}; ", "x".repeat(60));
    let line = format!("{{ {}}} | psql", printf.repeat(5));
    assert!(took(&line, Shell::Posix, &posix()) < Duration::from_millis(500));
    check(Shell::Posix, &posix(), &[], &[(&line, Rule::Unknown)]);
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn many_clients_on_one_line_are_read_in_linear_time() {
    // Each `redis-cli del` that is given keys asks whether the line lists
    // keys; each client asks for the text fed to it. Neither may walk every
    // unit or every text of the line again.
    for part in ["redis-cli del $x; ", "psql <<< x; "] {
        assert_linear(part, Shell::Posix, &posix(), |size| filled(part, size, 0));
    }
    // Many clients of a stage that backs up to many files.
    assert_linear(
        "a stage of backups to many clients",
        Shell::Posix,
        &posix(),
        |size| {
            let mut said = String::new();
            for at in 0..size / 80 {
                let _ = write!(said, "echo '.backup /home/me/{at}.db'; ");
            }
            let clients = filled("sqlite3 ~/x.db; ", size / 2, 40);
            format!("{{ {said}}} | {{ {clients}}}")
        },
    );
    // The time grew with the clients times the programs feeding them.
    let args = "a ".repeat(1000);
    let printf = format!("printf '%s{}' {args}; ", "x".repeat(60));
    let clients = |count: usize| "psql; ".repeat(count);
    let lines = [
        // Fifteen printfs, each saying 63 KB: more than a stage may say.
        format!("{{ {}}} | {{ {}}}", printf.repeat(15), clients(1000)),
        format!(
            "{{ {}}} | {{ {}}}",
            "printf '%s' a b c; ".repeat(64),
            clients(1800)
        ),
        format!(
            "{{ echo '{}'; }} | {{ {}}}",
            "x".repeat(30_000),
            clients(5000)
        ),
        format!(
            "{{ echo '{}'; }} | {{ {}}}",
            "x".repeat(20_000),
            "sqlite3 ~/x.db; ".repeat(2500)
        ),
        format!(
            "{{ echo '{}'; }} | {{ {}}}",
            "x".repeat(20_000),
            "redis-cli; ".repeat(4000)
        ),
        // Risky: every client has a finding to give.
        format!(
            "{{ echo 'DROP TABLE t; {}'; }} | {{ {}}}",
            "x".repeat(20_000),
            "psql; ".repeat(5000)
        ),
    ];
    for line in &lines {
        let took = took(line, Shell::Posix, &posix());
        assert!(
            took < Duration::from_millis(500),
            "{} bytes took {took:?}",
            line.len()
        );
    }
}

#[test]
fn dynamic_sql_in_text_on_the_line_is_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            r#"psql -c "DO 'BEGIN PERFORM 1; END'""#,
            r#"psql -c "DO \$\$ BEGIN PERFORM 1; END \$\$""#,
            r#"psql -c "DO \$\$ BEGIN CREATE TRIGGER x AFTER INSERT ON t FOR EACH ROW EXECUTE FUNCTION f(); END \$\$""#,
            r#"mysql -e "PREPARE s FROM 'SELECT 1'; EXECUTE s""#,
            r#"sqlcmd -Q "EXEC sp_MSforeachtable 'SELECT COUNT(*) FROM ?'""#,
            r#"sqlcmd -Q "EXEC('SELECT 1')""#,
            r#"sqlcmd -Q "EXECUTE ('SELECT 1')""#,
            r#"sqlcmd -Q "EXEC sp_executesql N'SELECT 1'""#,
            r#"sqlcmd -Q "EXEC sp_executesql N'DELETE FROM t WHERE a = ''x''', N'@p int', @p = 1""#,
            r#"sqlcmd -Q "EXEC sys.sp_executesql @stmt = N'SELECT 1'""#,
        ],
        &[
            (r#"psql -c "DO 'BEGIN DROP TABLE t; END'""#, Rule::DropData),
            (
                r#"psql -c "DO LANGUAGE plpgsql 'BEGIN DELETE FROM t; END'""#,
                Rule::DropData,
            ),
            (
                r#"psql -c "DO 'BEGIN EXECUTE ''DROP TABLE t''; END'""#,
                Rule::Unknown,
            ),
            (
                r#"psql -c "DO \$\$ DECLARE r RECORD; BEGIN FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE'; END LOOP; END \$\$;""#,
                Rule::Unknown,
            ),
            (
                r#"psql -c "DO \$\$ BEGIN EXECUTE format('DROP TABLE %I', 't'); END \$\$""#,
                Rule::Unknown,
            ),
            (
                r#"mysql -e "PREPARE s FROM 'DROP TABLE t'; EXECUTE s""#,
                Rule::DropData,
            ),
            (r#"mysql -e "PREPARE s FROM @q; EXECUTE s""#, Rule::Unknown),
            (
                r#"sqlcmd -Q "EXEC sp_MSforeachtable 'DELETE FROM ?'""#,
                Rule::DropData,
            ),
            (
                r#"sqlcmd -Q "EXEC sp_MSforeachdb @command1 = N'DROP TABLE t'""#,
                Rule::DropData,
            ),
            (r#"sqlcmd -Q "EXEC sp_MSforeachtable @c""#, Rule::Unknown),
            (r#"sqlcmd -Q "EXEC('DROP TABLE t')""#, Rule::DropData),
            (r#"sqlcmd -Q "EXECUTE('DROP TABLE t')""#, Rule::DropData),
            (
                r#"sqlcmd -Q "EXEC('DELETE FROM t WHERE a = ''x''; DROP TABLE t')""#,
                Rule::DropData,
            ),
            (r#"sqlcmd -Q "EXEC('DROP ' + @t)""#, Rule::Unknown),
            (r#"sqlcmd -Q "EXEC(@sql)""#, Rule::Unknown),
            (
                r#"sqlcmd -Q "EXEC sp_executesql N'DROP TABLE t'""#,
                Rule::DropData,
            ),
            (r#"sqlcmd -Q "EXEC sp_executesql @sql""#, Rule::Unknown),
            (
                r#"sqlcmd -Q "EXEC [sp_executesql] N'DROP TABLE t'""#,
                Rule::DropData,
            ),
            (
                r#"sqlcmd -Q "EXEC sp_executesql N'DROP ' + @t""#,
                Rule::Unknown,
            ),
            (r#"sqlcmd -Q "EXEC('$verb TABLE t')""#, Rule::Unknown),
        ],
    );
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn sql_in_sql_is_read_a_few_levels_deep() {
    let mut text = "DROP TABLE t".to_string();
    for _ in 0..5 {
        text = format!("EXEC('{}')", text.replace('\'', "''"));
    }
    let line = format!("sqlcmd -Q \"{text}\"");
    check(Shell::Posix, &posix(), &[], &[(&line, Rule::DropData)]);
    // Deeper than that is not read, and what is not read is unknown.
    let mut text = "DROP TABLE t".to_string();
    for _ in 0..12 {
        text = format!("EXEC('{}')", text.replace('\'', "''"));
    }
    let line = format!("sqlcmd -Q \"{text}\"");
    check(Shell::Posix, &posix(), &[], &[(&line, Rule::Unknown)]);
    // A long chain of nested `DO` strings is read without going deep.
    let mut body = "SELECT 1".to_string();
    for level in 0..2_000 {
        body = format!("DO $t{level}$ {body} $t{level}$");
    }
    let line = format!("psql -c '{body}'");
    assert!(took(&line, Shell::Posix, &posix()) < Duration::from_millis(200));
    assert!(!classify(&line, Shell::Posix, &posix()).is_safe());
}

#[test]
fn a_backslash_in_a_string_is_read_both_ways_where_the_server_sets_it() {
    check(
        Shell::Posix,
        &posix(),
        &[
            r#"mysql -e "SELECT 'it\\'s'""#,
            r#"mysql -e "INSERT INTO t VALUES ('it\\'s'); SELECT 1""#,
            "psql <<'EOF'\nSELECT E'it\\'s' AS a;\nEOF",
            r#"psql -c "SELECT 'a\\nb' AS x; SELECT 1""#,
            "mysql -e 'SELECT 1; SELECT 2'",
        ],
        &[
            // `NO_BACKSLASH_ESCAPES`: the string is `'a\'`, and the next
            // statement runs.
            (
                r#"mysql -e "SET sql_mode='NO_BACKSLASH_ESCAPES'; SELECT 'a\\'; DROP TABLE t; -- '""#,
                Rule::DropData,
            ),
            // `ANSI_QUOTES`: `"a\"` is an identifier.
            (
                r#"mysql -e "SET sql_mode='ANSI_QUOTES'; SELECT \"a\\\"; DROP TABLE t; -- \"""#,
                Rule::DropData,
            ),
            // `standard_conforming_strings` off: the string takes `\'`.
            (
                "psql <<'EOF'\nSET standard_conforming_strings = off;\nSELECT 'a\\'' ; DROP TABLE t; --';\nEOF",
                Rule::DropData,
            ),
            (
                r#"psql -c "SET standard_conforming_strings = off; SELECT 'a\\'' ; DROP TABLE t; --';""#,
                Rule::DropData,
            ),
            // A program, from the other reading.
            (
                r#"mysql -e "SELECT 'a\\'; \! touch x; -- '""#,
                Rule::Unknown,
            ),
        ],
    );
}

#[test]
fn a_variable_the_client_fills_in_is_not_read_where_a_statement_starts() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "psql -c 'SELECT 1::int'",
            "psql -c 'SELECT a::text FROM t'",
            "psql -c \"SELECT ':q'\"",
            "psql -c 'SELECT * FROM t WHERE a = :x'",
            "psql -c 'SELECT 1; SELECT :x'",
            "psql -c 'SELECT 1 -- :q'",
            "sqlcmd -Q 'SELECT * FROM t WHERE a = $(x)'",
            "sqlcmd -Q 'SELECT 1'",
            // Only `psql` has `:name`, and only `sqlcmd` has `$(name)`.
            "mysql -e 'SELECT :x'",
            "sqlite3 :memory: ':q'",
        ],
        &[
            ("psql -v q='DROP TABLE t' <<< ':q'", Rule::Unknown),
            ("psql -v q='DROP TABLE t' <<< \":'q'\"", Rule::Unknown),
            ("psql -v q='DROP TABLE t' <<< ':\"q\"'", Rule::Unknown),
            ("psql <<EOF\n\\set q 'DROP TABLE t'\n:q\nEOF", Rule::Unknown),
            ("psql -c 'BEGIN; :q'", Rule::Unknown),
            ("psql -c 'SELECT 1; :q;'", Rule::Unknown),
            ("echo ':q' | psql -v q='DROP TABLE t'", Rule::Unknown),
            ("sqlcmd -v s=\"DROP TABLE t\" -Q '$(s)'", Rule::Unknown),
            ("sqlcmd -Q 'SELECT 1; $(s)'", Rule::Unknown),
            // The statements the variable does not start are still read.
            ("psql -c ':q; DROP TABLE t'", Rule::DropData),
        ],
    );
}
