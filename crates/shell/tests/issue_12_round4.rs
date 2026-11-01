//! What a fourth review of `drop_data` found: a dot command named by the
//! start of its name, a password option that takes a value only when it is
//! attached, a template read as the client does not get it, and a `cat` given
//! a here-document that passes it on. Each table holds the lines of one
//! finding, safe and risky.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

fn posix_rows(safe: &[&str], risky: &[(&str, Rule)]) {
    check(Shell::Posix, &posix(), safe, risky);
}

#[test]
fn a_dot_command_is_every_command_its_name_starts() {
    posix_rows(
        &[
            // Names that start no command the guard reads.
            "sqlite3 :memory: '.schema'",
            "sqlite3 :memory: '.sch'",
            "sqlite3 :memory: '.tables'",
            "sqlite3 :memory: '.mode csv'",
            "sqlite3 :memory: '.headers on'",
            "sqlite3 :memory: '.quit'",
            "duckdb -c '.tables'",
            "sqlite3 ./x.db '.import data.csv t'",
            "sqlite3 ./x.db '.imp data.csv t'",
            "sqlite3 ./x.db '.output out.txt'",
        ],
        &[
            // The start of `.shell` and `.system` runs the program.
            ("sqlite3 :memory: '.sh rm -rf ~'", Rule::Unknown),
            ("sqlite3 :memory: '.she rm -rf ~'", Rule::Unknown),
            ("sqlite3 :memory: '.shel rm -rf ~'", Rule::Unknown),
            ("sqlite3 :memory: '.sy rm -rf ~'", Rule::Unknown),
            ("sqlite3 :memory: '.syst rm -rf ~'", Rule::Unknown),
            ("duckdb -c '.sys rm -rf ~'", Rule::Unknown),
            ("sqlite3 :memory: <<'EOF'\n.sy rm -rf ~\nEOF", Rule::Unknown),
            // The start of `.output`, `.once`, `.read` and `.import` that
            // pipes to or reads from a program.
            ("sqlite3 :memory: '.o \"|rm -rf ~\"'", Rule::Unknown),
            ("sqlite3 :memory: '.onc \"|rm -rf ~\"'", Rule::Unknown),
            ("sqlite3 :memory: '.ou \"|rm -rf ~\"'", Rule::Unknown),
            ("sqlite3 x.db '.rea \"|rm -rf ~\"'", Rule::Unknown),
            ("sqlite3 x.db '.re \"|rm -rf ~\"'", Rule::Unknown),
            ("sqlite3 :memory: '.imp \"|rm -rf ~\" t'", Rule::Unknown),
            ("duckdb -c '.rea \"|rm -rf ~\"'", Rule::Unknown),
            // The start of `.open` and `.attach` reaches another file.
            (
                "sqlite3 x.db '.op /home/me/y.db' 'DELETE FROM t'",
                Rule::DropData,
            ),
            (
                "sqlite3 x.db '.att /home/me/y.db z' 'DROP TABLE t'",
                Rule::DropData,
            ),
            // The start of `.restore` replaces the database.
            ("sqlite3 ~/x.db '.rest b.db'", Rule::DropData),
            ("sqlite3 ~/x.db '.res b.db'", Rule::DropData),
            // The full names stay as they were.
            (
                "sqlite3 x.db '.open /home/me/y.db' 'DELETE FROM t'",
                Rule::DropData,
            ),
            ("sqlite3 ~/x.db '.restore b.db'", Rule::DropData),
        ],
    );
}

#[test]
fn a_password_option_with_no_value_does_not_take_the_statement_option() {
    posix_rows(
        &[
            "mongosh -u admin -p --eval 'db.users.find()'",
            "mongosh -u admin -p secret --eval 'db.users.find()'",
            "mongosh --username admin --password secret --eval 'db.users.find()'",
            "mongosh --username admin --password --eval 'db.users.find()'",
            "mongosh --password=secret --eval 'db.users.find()'",
            "mongo -u admin -p --eval 'db.users.find()'",
            "clickhouse-client --password secret --query 'SELECT 1'",
            "clickhouse-client --password --query 'SELECT 1'",
            "clickhouse-client --password=secret -q 'SELECT 1'",
            "clickhouse-client --password -q 'SELECT 1'",
        ],
        &[
            // The word after a password with no value is an option of its own.
            (
                "mongosh -u admin -p --eval 'db.dropDatabase()'",
                Rule::DropData,
            ),
            (
                "mongosh --username admin --password --eval 'db.dropDatabase()'",
                Rule::DropData,
            ),
            (
                "mongo -u admin -p --eval 'db.dropDatabase()'",
                Rule::DropData,
            ),
            (
                "mongosh --host -p --eval 'db.dropDatabase()'",
                Rule::DropData,
            ),
            (
                "clickhouse-client --password --query 'DROP TABLE t'",
                Rule::DropData,
            ),
            (
                "clickhouse-client --password -q 'DROP TABLE t'",
                Rule::DropData,
            ),
            ("clickhouse-client --pass -q 'DROP TABLE t'", Rule::DropData),
            // A password that has a value still leaves the statement read.
            (
                "mongosh -u admin -p secret --eval 'db.dropDatabase()'",
                Rule::DropData,
            ),
            (
                "clickhouse-client --password secret --query 'DROP TABLE t'",
                Rule::DropData,
            ),
            // A statement that starts with `-` is read as one too.
            ("mongosh --eval '-1; db.dropDatabase()'", Rule::DropData),
        ],
    );
}

#[test]
fn an_expansion_stuck_to_a_word_ends_the_word() {
    posix_rows(
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
fn an_escaped_dollar_or_backtick_in_a_template_is_not_known() {
    posix_rows(
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
fn a_cat_that_reads_its_input_passes_the_text_on() {
    posix_rows(
        &[
            // A file operand and no `-`: the text is not read.
            "cat schema.sql <<EOF | psql\nDROP TABLE t;\nEOF",
            "cat -n schema.sql <<EOF | psql\nDROP TABLE t;\nEOF",
            "cat -- schema.sql <<EOF | psql\nDROP TABLE t;\nEOF",
            "cat -- -n <<EOF | psql\nDROP TABLE t;\nEOF",
            "cat schema.sql | psql",
            // What it passes on is read.
            "cat <<EOF | psql\nSELECT 1;\nEOF",
            "cat -s <<EOF | psql\nSELECT 1;\nEOF",
            "cat - schema.sql <<EOF | psql\nSELECT 1;\nEOF",
        ],
        &[
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
