//! The format of the case files every guard's tests read: what a line holds,
//! that a text holds any command line exactly, and every line it refuses,
//! named by its file and line.

#[path = "common/cases.rs"]
mod format;

use format::{decode, encode, parse, read, Record, Word};

fn bare(word: &str) -> Word {
    Word::Bare(word.to_string())
}

fn field(name: &str, value: &str) -> Word {
    Word::Field(name.to_string(), value.to_string())
}

/// The one record of a one-line file.
fn one(line: &str) -> Record {
    let records = parse("t.cases", line);
    assert!(
        matches!(&records, Ok(records) if records.len() == 1),
        "{records:?}"
    );
    records.unwrap_or_default().remove(0)
}

/// What `source` is refused for; empty when it is read, which fails the
/// test's own check of what it holds.
fn refused(source: &str) -> String {
    parse("t.cases", source)
        .err()
        .unwrap_or_default()
        .join("\n")
}

#[test]
fn a_line_is_words_then_the_text_after_the_bar() {
    let record = one("posix finds=delete reason=\"deletes a file\" | rm -rf x | cat");
    assert_eq!(record.at, "t.cases:1");
    assert_eq!(
        record.words,
        [
            bare("posix"),
            field("finds", "delete"),
            field("reason", "deletes a file")
        ]
    );
    assert_eq!(record.text.as_deref(), Some("rm -rf x | cat"));
    // Words may be spaced to line up; a declaration has no text.
    let record = one("paths  home   cwd=/home/me home=C:\\\\Users\\\\me");
    assert_eq!(
        record.words,
        [
            bare("paths"),
            bare("home"),
            field("cwd", "/home/me"),
            field("home", "C:\\Users\\me")
        ]
    );
    assert_eq!(record.text, None);
    // A bar with nothing after it is the empty line.
    assert_eq!(one("posix safe |").text.as_deref(), Some(""));
}

#[test]
fn blank_lines_and_comments_are_skipped_and_lines_are_counted() {
    let records = parse(
        "t.cases",
        "# a comment\n\nposix safe | ls\n#posix safe | rm\nposix safe | pwd\n",
    )
    .expect("read");
    let at: Vec<&str> = records.iter().map(|record| record.at.as_str()).collect();
    assert_eq!(at, ["t.cases:3", "t.cases:5"]);
}

#[test]
fn a_text_holds_any_line_exactly() {
    let rows = [
        (r"cat < a\tb", "cat < a\tb"),
        (r"cd sub <<EOF\nx\nEOF", "cd sub <<EOF\nx\nEOF"),
        (r"echo hi\r\nrm -rf ~", "echo hi\r\nrm -rf ~"),
        (r"del ..\\x.txt", "del ..\\x.txt"),
        (r"\\\\host\\share", "\\\\host\\share"),
        (r#"echo "it's" '$HOME'"#, "echo \"it's\" '$HOME'"),
        (r"\sls\s", " ls "),
        (r"\s\s", "  "),
        (r"ls  -la", "ls  -la"),
        ("cat ~/José/日本/🦀", "cat ~/José/日本/🦀"),
        (r"rm\u{a0}-rf\u{2028}~\u{0}", "rm\u{a0}-rf\u{2028}~\u{0}"),
        (r"echo |", "echo |"),
        (r"# not a comment", "# not a comment"),
        (r"x=1 | y", "x=1 | y"),
    ];
    for (written, held) in rows {
        let record = one(&format!("posix safe | {written}"));
        assert_eq!(record.text.as_deref(), Some(held), "{written}");
        assert_eq!(encode(held), written, "{held:?}");
    }
}

#[test]
fn encode_and_decode_give_back_any_text() {
    let texts = [
        "",
        " ",
        "\\",
        "\\n",
        "\\s",
        "a\u{7f}b\u{1b}[0m",
        "\u{feff}x\u{200b}",
        "trailing\t",
        " lead",
        "tab\tin\rthe\nmiddle",
        "\"quoted\" 'single'",
    ];
    for text in texts {
        let written = encode(text);
        assert_eq!(decode(&written, false).as_deref(), Ok(text), "{written}");
        let record = one(format!("posix safe | {written}").trim_end_matches(' '));
        assert_eq!(record.text.as_deref(), Some(text), "{written}");
    }
}

#[test]
fn a_quoted_value_holds_spaces_bars_and_quotes() {
    let record = one(r#"posix reason="writes to \"a b\" | c\\d" | x"#);
    assert_eq!(record.words[1], field("reason", "writes to \"a b\" | c\\d"));
    assert_eq!(record.text.as_deref(), Some("x"));
}

#[test]
fn a_raw_control_character_is_refused() {
    assert!(refused("posix safe | a\tb").contains("t.cases:1: a raw \\t"));
    assert!(refused("posix safe | ls\r\n").contains("t.cases:1: a raw \\r"));
    assert!(refused("posix safe | a\u{1b}b").contains("t.cases:1: a raw \\u{1b}"));
}

#[test]
fn a_space_at_either_end_is_refused() {
    assert!(refused("posix safe | ls ").contains("t.cases:1: a space at the end"));
    assert!(refused(" posix safe | ls").contains("t.cases:1: a space at the start of the line"));
    assert!(refused("posix safe |  ls").contains("t.cases:1: a space at the start of the text"));
    assert!(refused("posix safe | ").contains("t.cases:1: a space at the end"));
    assert!(refused("# a comment \n").contains("t.cases:1: a space at the end"));
}

#[test]
fn an_unknown_or_unfinished_escape_is_refused() {
    assert!(refused(r"cmd safe | del ..\x.txt").contains(r"t.cases:1: an unknown escape `\x`"));
    assert!(refused(r#"posix safe | echo \""#).contains(r#"an unknown escape `\"`"#));
    assert!(refused(r"posix safe | ls \").contains("a backslash at the end"));
    assert!(refused(r"posix safe | \u{110000}").contains("is not a character"));
    assert!(refused(r"posix safe | \u{}").contains("one to six digits"));
    assert!(refused(r"posix safe | \u41").contains("one to six digits"));
    assert!(refused(r"paths x cwd=C:\Users").contains("an unknown escape `\\U`"));
}

#[test]
fn a_malformed_word_is_refused() {
    assert!(refused(r#"posix reason="open | x"#).contains("no closing quote"));
    assert!(refused(r#"posix reason="a"b | x"#).contains("a space must follow the quoted value"));
    assert!(refused(r#"posix reason=a"b | x"#).contains("must be quoted"));
    assert!(refused(r#"posix "safe" | x"#).contains("a malformed word"));
    assert!(refused("posix =x | ls").contains("a malformed field name"));
    assert!(refused("posix safe |ls").contains("a malformed word `|ls`"));
}

#[test]
fn every_refused_line_is_named_at_once() {
    let why = refused("posix safe | a\\q\nposix safe | ok\nposix safe | b \n");
    assert!(why.contains("t.cases:1:"), "{why}");
    assert!(!why.contains("t.cases:2:"), "{why}");
    assert!(why.contains("t.cases:3:"), "{why}");
}

#[test]
fn a_missing_file_is_refused() {
    let why = read("no_such_cases").expect_err("refused").join("\n");
    assert!(
        why.contains("tests/cases/no_such_cases.cases: no case file"),
        "{why}"
    );
}

#[test]
fn a_repeated_key_is_named_with_the_first() {
    let items = [
        ("t.cases:1".to_string(), "a"),
        ("t.cases:2".to_string(), "b"),
        ("t.cases:3".to_string(), "a"),
    ];
    assert_eq!(
        format::repeated(items),
        ["t.cases:3: repeats the case at t.cases:1"]
    );
}
