//! The promises every entry point of the guards keeps for any input, each a
//! function that panics on an input that breaks one, and the one way an
//! input is made of bytes. The fuzz targets in `tools/fuzz` call [`check`]
//! on what `libFuzzer` makes, and the gate's `tests/promises.rs` on case
//! lines changed at random, so `just verify` holds the same promises on
//! every change. The fuzz package includes this file by its path, with
//! [`super::seeds`] beside it, and it uses only the guards, their test
//! machines and their `testing` counts.
//!
//! What every entry point promises, whatever the input:
//!
//! - it returns: no panic, and inside the limits, which the fuzzer holds to
//!   a time and a memory limit for each input, and the counts below hold to
//!   a budget where a guard keeps one;
//! - the same input gives the same answer twice, and a risky answer always
//!   names a finding.
//!
//! And for each:
//!
//! - the shell guard ([`shell`]): a line `classify` calls unreadable is
//!   never safe, never reads-only, has no paths and is drawn so; `classify`,
//!   `effect`, `explain` and `effect_paths` (which locates what a reads-only
//!   line reads) agree, as every case of the shell guard's case files is
//!   held to (`disagreements` in its `tests/common`); and the bytes its
//!   lexers are handed stay within their budget, past which the line is
//!   unreadable;
//! - the file guard ([`file`]): a path that is no one literal path, or is
//!   too long, is unreadable, and every finding names the path as written;
//! - the URL guard ([`url`] and [`address`]): an unreadable finding carries
//!   no target, a control character inside a URL leaves it unread, a text
//!   with a `%` is never a safe address, and white space around either
//!   changes nothing;
//! - the secrets guard ([`secrets`]): a span for each finding, of its rule,
//!   in order, apart, on character boundaries and inside the text, and a
//!   finding never holds the value its span covers;
//! - the code reader ([`code`]): its parses stay within the budget, code
//!   whose reading is stopped is not read and not understood, a reading
//!   through one [`Budget`] is the reading `read` gives, a spent budget
//!   stops every reading after it, and code that is understood parses, has
//!   no control character and only opens files;
//! - the script guard ([`script`]): code that does not parse is never safe,
//!   and safe code is code the reader understands.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "the fuzz targets and the gate's test each use a part of it"
)]

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "the shell guard's test helpers, written for its tests"
)]
#[path = "../../../shell/tests/common/mod.rs"]
mod shell_common;

use std::borrow::Cow;

use milo_guards::code::{self, Act, Budget, Language, Understanding};
use milo_guards::file::{self, Access, MAX_PATH_LEN};
use milo_guards::script;
use milo_guards::secrets;
use milo_guards::shell::{self, Effect, Shell};
use milo_guards::url;
use milo_guards::{Paths, Protected, Secret};
use milo_guards_core::testing::{macos, posix, windows};

/// An entry point a fuzz target holds to its promises: the name is the
/// target's, in `tools/fuzz/Cargo.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `shell::classify`, `effect`, `explain` and `effect_paths` of a POSIX
    /// line.
    ShellPosix,
    /// The same, of a PowerShell line.
    ShellPowerShell,
    /// The same, of a cmd line.
    ShellCmd,
    /// `file::judge`, of a read or a write.
    File,
    /// `url::judge`.
    Url,
    /// `url::judge_address`.
    UrlAddress,
    /// `secrets::find`, `find_spans` and `find_high_entropy`.
    Secrets,
    /// The code reader: `read`, `understand` and a `Budget` asked both.
    Code,
    /// `script::judge`.
    Script,
}

impl Target {
    /// Every target, in the order `tools/fuzz/Cargo.toml` names them.
    pub const ALL: [Self; 9] = [
        Self::ShellPosix,
        Self::ShellPowerShell,
        Self::ShellCmd,
        Self::File,
        Self::Url,
        Self::UrlAddress,
        Self::Secrets,
        Self::Code,
        Self::Script,
    ];

    /// The name of its fuzz target.
    pub fn name(self) -> &'static str {
        match self {
            Self::ShellPosix => "shell_posix",
            Self::ShellPowerShell => "shell_powershell",
            Self::ShellCmd => "shell_cmd",
            Self::File => "file",
            Self::Url => "url",
            Self::UrlAddress => "url_address",
            Self::Secrets => "secrets",
            Self::Code => "code",
            Self::Script => "script",
        }
    }

    /// The target named `name`.
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|target| target.name() == name)
    }
}

/// How many machines an input may pick from: see [`machine`].
pub const MACHINES: u8 = 6;

/// The machine `index` names, of [`MACHINES`]: the test machines (a POSIX
/// one, a Mac and a Windows one), each of the POSIX and the Windows one with
/// a protected path and a secret the caller names, and a POSIX machine that
/// mounts the Windows drives (WSL, Git Bash), with its Windows home.
pub fn machine(index: u8) -> Paths {
    match index % MACHINES {
        0 => posix(),
        1 => macos(),
        2 => windows(),
        3 => posix()
            .with_protected([Protected::folder("/home/me/.agent", "the agent's settings")])
            .with_secrets([Secret::file(
                "/home/me/work/repo/.env",
                "the project's environment file",
            )]),
        4 => windows()
            .with_protected([Protected::file(
                r"C:\Users\me\.agent",
                "the agent's settings",
            )])
            .with_secrets([Secret::folder(
                r"C:\Users\me\dev\repo\secrets",
                "the project's secrets",
            )]),
        _ => posix()
            .with_drive_mounts(["/mnt", "/cygdrive"])
            .with_windows_home(r"C:\Users\me"),
    }
}

/// The input of a target: its first byte picks how the text is judged (the
/// machine, and the access or the language where the target takes one), and
/// the rest is the text, read as UTF-8 with each byte that is not replaced.
pub fn decode(data: &[u8]) -> (u8, Cow<'_, str>) {
    match data.split_first() {
        Some((choice, text)) => (*choice, String::from_utf8_lossy(text)),
        None => (0, Cow::Borrowed("")),
    }
}

/// The bytes [`decode`] reads as `choice` and `text`.
pub fn encode(choice: u8, text: &str) -> Vec<u8> {
    let mut data = Vec::with_capacity(text.len() + 1);
    data.push(choice);
    data.extend_from_slice(text.as_bytes());
    data
}

/// The choice of a read or a write on the machine `index`.
pub fn access_choice(write: bool, index: u8) -> u8 {
    u8::from(write) | (index << 1)
}

/// The choice of code in `language` on the machine `index`: the language in
/// its two low bits, the machine above them.
pub fn language_choice(language: Language, index: u8) -> u8 {
    let language = match language {
        Language::Python => 0,
        Language::JavaScript => 1,
        Language::Ruby => 2,
    };
    language | (index << 2)
}

/// The language a choice names.
fn language_of(choice: u8) -> Language {
    match choice & 3 {
        0 => Language::Python,
        1 => Language::JavaScript,
        _ => Language::Ruby,
    }
}

/// Hold `data`, as [`decode`] reads it, to the promises of `target`.
pub fn check(target: Target, data: &[u8]) {
    let (choice, text) = decode(data);
    match target {
        Target::ShellPosix => shell(&text, Shell::Posix, &machine(choice)),
        Target::ShellPowerShell => shell(&text, Shell::PowerShell, &machine(choice)),
        Target::ShellCmd => shell(&text, Shell::Cmd, &machine(choice)),
        Target::File => {
            let access = if choice & 1 == 0 {
                Access::Read
            } else {
                Access::Write
            };
            file(access, &text, &machine(choice >> 1));
        }
        Target::Url => url(&text, &machine(choice)),
        Target::UrlAddress => address(&text),
        Target::Secrets => secrets(&text),
        Target::Code => code(language_of(choice), &text),
        Target::Script => script(language_of(choice), &text, &machine(choice >> 2)),
    }
}

/// A risky answer names a finding: never an empty `Risky`.
fn says_why<R: std::fmt::Debug>(assessment: &milo_guards::Assessment<R>, what: &str) {
    assert_eq!(
        assessment.is_safe(),
        assessment.findings().is_empty(),
        "a risky answer with no finding: {what}"
    );
}

// ---- the shell guard ----

/// The bytes past its budget a lexer may be handed before its parse sees
/// it is past: the piece that took it there (`LEXED_PIECE`, and up to three
/// more to end where a character does), and each look the lexer takes after
/// that, as `tests/lexer_budget.rs` of the shell guard allows.
const LEXED_OVERRUN: usize = 2 * shell::testing::LEXED_PIECE;

/// The promises of the shell guard for `line`, run by `which` on `paths`.
pub fn shell(line: &str, which: Shell, paths: &Paths) {
    let what = format!("{which:?} {line:?}");
    let assessment = shell::classify(line, which, paths);
    let effect = shell::effect(line, which, paths);
    let listed = shell::effect_paths(line, which, paths);
    let explanation = shell::explain(line, which, paths);
    let tree = explanation.to_string();
    // The same line, the same answers.
    assert_eq!(
        assessment,
        shell::classify(line, which, paths),
        "classify twice: {what}"
    );
    assert_eq!(
        effect,
        shell::effect(line, which, paths),
        "effect twice: {what}"
    );
    assert_eq!(
        listed,
        shell::effect_paths(line, which, paths),
        "effect_paths twice: {what}"
    );
    assert_eq!(
        tree,
        shell::explain(line, which, paths).to_string(),
        "explain twice: {what}"
    );
    says_why(&assessment, &what);
    // What cannot be read is never safe, never reads only, and says so.
    let unreadable = assessment
        .findings()
        .iter()
        .any(|finding| finding.rule == shell::Rule::Unreadable);
    if unreadable {
        assert!(
            !matches!(effect, Effect::ReadsOnly(_)),
            "unreadable, but reads only: {what}"
        );
        assert_eq!(listed, None, "unreadable, but lists paths: {what}");
        assert!(
            tree.contains(shell::Rule::Unreadable.name()),
            "unreadable, but its tree does not say so: {what}"
        );
    }
    // The four answers agree.
    let wrong = shell_common::disagreements(which, paths, [line]);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    // Inside the budget of what its lexers are handed, and unreadable past
    // it.
    let lexed = shell::testing::lexed(line, which, paths);
    assert_eq!(lexed.answer, assessment, "lexed and classify: {what}");
    let budget = shell::testing::MAX_LEXED * lexed.parsed + shell::testing::MAX_LEXED_BASE;
    assert!(
        lexed.handed <= budget + LEXED_OVERRUN,
        "its lexers were handed {} bytes, past the budget of {budget}: {what}",
        lexed.handed
    );
    if lexed.handed > budget {
        assert!(unreadable, "past the budget, but read: {what}");
    }
}

// ---- the file guard ----

/// The promises of the file guard for `path`, read or written on `paths`.
pub fn file(access: Access, path: &str, paths: &Paths) {
    let what = format!("{access:?} {path:?}");
    let assessment = file::judge(access, path, paths);
    assert_eq!(
        assessment,
        file::judge(access, path, paths),
        "judge twice: {what}"
    );
    says_why(&assessment, &what);
    // What is no one literal path, or too long a one, is never read.
    let unreadable = path.is_empty()
        || path.contains(['\0', '\n', '*', '`'])
        || path.starts_with(' ')
        || path.len() > MAX_PATH_LEN;
    if unreadable {
        assert!(
            assessment
                .findings()
                .iter()
                .any(|finding| finding.rule == file::Rule::Unreadable),
            "not one literal path, but read: {what}: {assessment:?}"
        );
    }
    // Every finding names the path as written, or none past the longest.
    let target = (path.len() <= MAX_PATH_LEN).then_some(path);
    for finding in assessment.findings() {
        assert_eq!(
            finding.target.as_deref(),
            target,
            "a finding does not name the path as written: {what}"
        );
    }
}

// ---- the URL guard ----

/// The longest text the white space around it is added to: well inside
/// the URL guard's limit, so the text with it is read too.
const AROUND: usize = 16 * 1024;

/// An unreadable finding carries no target, so no copy of what was not
/// read.
fn no_unread_target(assessment: &url::Assessment, what: &str) {
    for finding in assessment.findings() {
        if finding.rule == url::Rule::Unreadable {
            assert_eq!(finding.target, None, "an unreadable target: {what}");
        }
    }
}

/// The white space a URL parser takes off around a URL or an address.
const AROUND_SPACE: [char; 5] = [' ', '\t', '\n', '\r', '\x0c'];

/// The promises of the URL guard for `text`, fetched on `paths`.
pub fn url(text: &str, paths: &Paths) {
    let what = format!("{text:?}");
    let assessment = url::judge(text, paths);
    assert_eq!(assessment, url::judge(text, paths), "judge twice: {what}");
    says_why(&assessment, &what);
    no_unread_target(&assessment, &what);
    // A control character inside is never read as a URL.
    let inner = text.trim_matches(AROUND_SPACE);
    if inner.chars().any(char::is_control) {
        assert_eq!(
            assessment.findings().first().map(|finding| finding.rule),
            Some(url::Rule::Unreadable),
            "a control character inside, but read: {what}"
        );
    }
    // White space around a URL changes nothing.
    if text.len() <= AROUND {
        assert_eq!(
            assessment,
            url::judge(&format!(" \t{text}\n "), paths),
            "white space around changes the answer: {what}"
        );
    }
}

/// The promises of the URL guard for the address `text`.
pub fn address(text: &str) {
    let what = format!("{text:?}");
    let assessment = url::judge_address(text);
    assert_eq!(
        assessment,
        url::judge_address(text),
        "judge_address twice: {what}"
    );
    says_why(&assessment, &what);
    no_unread_target(&assessment, &what);
    // A zone is read only on an address that is a finding, and an escape
    // is a spelling: a `%` is never a safe address.
    if text.contains('%') {
        assert!(!assessment.is_safe(), "a `%`, but safe: {what}");
    }
    if text.len() <= AROUND {
        assert_eq!(
            assessment,
            url::judge_address(&format!(" \t{text}\n ")),
            "white space around changes the answer: {what}"
        );
    }
}

// ---- the secrets guard ----

/// `target` without the count a mask ends with (`… (8 chars)`): what of the
/// text a finding shows.
fn shown_of(target: &str) -> &str {
    match target.rfind("… (") {
        Some(at) if target.ends_with(" chars)") || target.ends_with(" char)") => &target[..at],
        _ => target,
    }
}

/// Spans on character boundaries, inside the text, in order and apart.
fn spans_inside(text: &str, spans: &[secrets::Span], what: &str) {
    let mut at = 0;
    for span in spans {
        assert!(
            span.start >= at && span.start < span.end && span.end <= text.len(),
            "spans out of order, overlapping or outside: {what}: {spans:?}"
        );
        assert!(
            text.is_char_boundary(span.start) && text.is_char_boundary(span.end),
            "a span off a character boundary: {what}: {spans:?}"
        );
        at = span.end;
    }
}

/// The promises of the secrets guard for `text`.
pub fn secrets(text: &str) {
    let what = format!("{} bytes", text.len());
    let assessment = secrets::find(text);
    let spans = secrets::find_spans(text);
    assert_eq!(assessment, secrets::find(text), "find twice: {what}");
    assert_eq!(spans, secrets::find_spans(text), "find_spans twice: {what}");
    says_why(&assessment, &what);
    // A span for each finding, of its rule, in order and apart.
    assert_eq!(
        spans.len(),
        assessment.findings().len(),
        "a span for each finding: {what}"
    );
    spans_inside(text, &spans, &what);
    for (finding, span) in assessment.findings().iter().zip(&spans) {
        assert_eq!(finding.rule, span.rule, "a span of another rule: {what}");
        let target = finding.target.as_deref().unwrap_or_default();
        assert!(
            !finding.reason.is_empty() && !target.is_empty(),
            "a finding with no reason or no target: {what}"
        );
        // Never the value: what the target shows of the text does not hold
        // what the span covers.
        let value = &text[span.start..span.end];
        assert!(
            !shown_of(target).contains(value),
            "a finding holds the value it found: {what}: {:?} at {}..{}",
            finding.rule,
            span.start,
            span.end
        );
    }
    for bits in [3.0, 4.5] {
        let entropy = secrets::find_high_entropy(text, bits);
        assert_eq!(
            entropy,
            secrets::find_high_entropy(text, bits),
            "find_high_entropy twice: {what}"
        );
        spans_inside(text, &entropy, &what);
    }
}

// ---- the code reader ----

/// What understood code may do to a file: open one, at a path the reader
/// may not follow (`open('/home/me/.ssh/id_' + n)` is a read below the
/// folder, and the path it did not read).
fn opens_only(act: &Act) -> bool {
    matches!(
        act,
        Act::Read(_) | Act::Write(_) | Act::Opaque(_) | Act::Unread(_)
    )
}

/// Whether `code` holds a control character other than a line feed or a
/// tab, or a line separator: what no code that is read whole holds.
fn odd_characters(code: &str) -> bool {
    code.chars().any(|c| {
        (c.is_control() && !matches!(c, '\n' | '\t')) || matches!(c, '\u{2028}' | '\u{2029}')
    })
}

/// Whether a reading holds an act the reader did not read.
fn unread(acts: &[Act]) -> bool {
    acts.iter().any(|act| matches!(act, Act::Unread(_)))
}

/// The work of one budget is within what it allows for `len` bytes, as the
/// reader's own `tests/robust.rs` holds it.
fn within(work: &code::testing::Work, len: usize, what: &str) {
    use code::testing::{
        HANDED_BASE, HANDED_BYTES, LOGGED_WEIGHT, PIECE, QUIET_IN_ALL, REPORT_BASE, REPORT_BYTES,
        SELECTED_IN_ALL, TANGLE_BASE, WALK_BASE, WALK_BYTES,
    };
    let len = len.min(code::MAX_LEN);
    assert!(
        work.reports <= len / REPORT_BYTES + REPORT_BASE + 1
            && work.quiet <= QUIET_IN_ALL + 1
            && work.tangled <= TANGLE_BASE + 16
            && work.selected <= SELECTED_IN_ALL + 4096
            && work.walked <= len * WALK_BYTES + WALK_BASE + len
            && work.handed <= len * HANDED_BYTES + HANDED_BASE + 2 * PIECE * LOGGED_WEIGHT,
        "past the budget: {what}: {work:?}"
    );
}

/// The promises of the code reader for `code` in `language`.
pub fn code(language: Language, code: &str) {
    let what = format!("{language:?} {code:?}");
    let (reading, read_work) = code::testing::read(language, code);
    let (understood, asked) = code::testing::understand(language, code);
    within(&read_work, code.len(), &what);
    within(&asked, code.len(), &what);
    let acts = format!("{:?}", reading.acts);
    // The same code, the same answers.
    let again = code::read(language, code);
    assert_eq!(acts, format!("{:?}", again.acts), "read twice: {what}");
    assert_eq!(reading.deep, again.deep, "read twice: {what}");
    assert_eq!(
        understood,
        code::understand(language, code),
        "understand twice: {what}"
    );
    assert_eq!(
        code::parses(language, code),
        code::parses(language, code),
        "parses twice: {what}"
    );
    if language == Language::Python {
        assert_eq!(
            code::understand_python2(code),
            code::understand_python2(code),
            "understand_python2 twice: {what}"
        );
    }
    // Code whose reading is stopped is not read, and not understood.
    if read_work.stopped {
        assert!(unread(&reading.acts), "stopped, but read: {what}");
    }
    if read_work.stopped || asked.stopped {
        assert_eq!(
            understood,
            Understanding::NotUnderstood,
            "stopped, but understood: {what}"
        );
    }
    // One budget asked twice: the reading is `read`'s, asked again it is
    // answered the same, and once it is spent every reading after it is
    // stopped.
    let budget = Budget::new(code.len());
    assert_eq!(
        format!("{:?}", budget.read(language, code).acts),
        acts,
        "a budget's reading is not read's: {what}"
    );
    let through = budget.understand(language, code);
    if through != Understanding::NotUnderstood {
        assert_eq!(through, understood, "a budget understands more: {what}");
    }
    let second = budget.read(language, code);
    if budget.is_spent() {
        assert!(unread(&second.acts), "a spent budget read again: {what}");
        assert_eq!(
            budget.understand(language, code),
            Understanding::NotUnderstood,
            "a spent budget understands: {what}"
        );
    } else {
        assert_eq!(
            format!("{:?}", second.acts),
            acts,
            "a budget asked again answers otherwise: {what}"
        );
    }
    within(&code::testing::spent(&budget), code.len(), &what);
    // Understood code parses, holds no odd character, and only opens files.
    if let Understanding::Understood { imports } = understood {
        assert_eq!(
            imports,
            language == Language::Python,
            "understood, with imports {imports}: {what}"
        );
        assert!(
            code::parses(language, code),
            "understood, but no parse: {what}"
        );
        assert!(
            !odd_characters(code),
            "understood, with a control character: {what}"
        );
        assert!(
            reading.acts.iter().all(opens_only),
            "understood, but does more than open a file: {what}: {acts}"
        );
    }
}

// ---- the script guard ----

/// The promises of the script guard for `code` in `language`, run on
/// `paths`.
pub fn script(language: Language, code: &str, paths: &Paths) {
    let what = format!("{language:?} {code:?}");
    let assessment = script::judge(language, code, paths);
    assert_eq!(
        assessment,
        script::judge(language, code, paths),
        "judge twice: {what}"
    );
    says_why(&assessment, &what);
    // The work is one judging; the answer adds what each other set of paths
    // finds (`Paths::also_judged_on`), and never takes a finding away.
    let worked = script::testing::work(language, code, paths).answer;
    if paths.also_judged_on().is_empty() {
        assert_eq!(worked, assessment, "its work and judge: {what}");
    } else {
        for finding in worked.findings() {
            assert!(
                assessment.findings().contains(finding),
                "its work and judge: {what}"
            );
        }
    }
    for finding in assessment.findings() {
        assert!(
            !finding.reason.is_empty(),
            "a finding with no reason: {what}"
        );
    }
    // Code that does not parse is never safe, and safe code is code the
    // reader understands.
    if !code::parses(language, code) {
        assert!(!assessment.is_safe(), "no parse, but safe: {what}");
    }
    if assessment.is_safe() {
        assert!(
            matches!(
                code::understand(language, code),
                Understanding::Understood { .. }
            ),
            "safe, but not understood: {what}"
        );
        assert!(
            !odd_characters(code),
            "safe, with a control character: {what}"
        );
    }
}
