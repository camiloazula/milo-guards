//! The time the shell guard takes over the worst lines it is given. These
//! are timed, so they run one at a time (`SERIAL`), and in a binary of their
//! own, after the heavy tests of `limits.rs`: a clock read while other tests
//! hammer the cores measures the machine, not the guard.

mod common;
mod noise;

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use common::{
    assert_linear, assert_linear_by, assert_within, at, disagreements, filled, posix, took,
};
use milo_guards_shell::{classify, effect, Paths, Rule, Shell};
use noise::{lossy, paths_for, Lcg, SHELLS, WIDE_PIECES};

/// Held for the whole of a timed test, so no two are timed at once.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How the time of a row of a timed table grows with its length.
#[derive(Clone, Copy)]
enum Time {
    /// With the length: the row at the length limit takes about four times
    /// as long as the row a quarter as long, not sixteen (`assert_linear`).
    Grows,
    /// Up to a count or a budget the guard reads to, and no further: past
    /// it a longer line is no slower, so two lengths do not show how the
    /// time grows below it. The row is held to [`COUNTED`] at each of
    /// [`COUNTED_SIZES`], up to and past the count (`assert_within`).
    Stops,
}

use Time::{Grows, Stops};

/// What makes a row of a timed table of the size it is given, boxed, so
/// that a table holds rows that keep what they build from.
type Grown = Box<dyn Fn(usize) -> String>;

/// The bound a row whose time [`Stops`] is held to: it leaves room for a
/// machine several times slower and busy, about six times the slowest such
/// row an optimized build here takes with other gates running beside it,
/// 40 ms.
const COUNTED: Duration = Duration::from_millis(250);

/// The sizes, in KB, at which a row whose time [`Stops`] is held to
/// [`COUNTED`]: from a line shorter than any count a row reaches to the
/// length limit.
const COUNTED_SIZES: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];

impl Time {
    /// Holds the row `line` makes, of the size it is given, to how its time
    /// grows, with the time of a line taken by `took`.
    fn holds(self, what: &str, took: impl Fn(&str) -> Duration, line: impl Fn(usize) -> String) {
        match self {
            Grows => assert_linear_by(what, took, line),
            Stops => assert_within(what, COUNTED, &COUNTED_SIZES, took, line),
        }
    }
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a stall"
)]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn wide_random_lines_never_panic_and_stay_quick() {
    let _serial = serial();
    // The time a turn can wait for one line, with room for a machine several
    // times slower and busy: lines this short take microseconds.
    const WORST: Duration = Duration::from_millis(500);
    let mut random = Lcg(0x5eed);
    let mut worst = (Duration::ZERO, String::new());
    let (mut unreadable, mut lines) = (0, 0);
    for number in 0..4_500 {
        let length = random.next() % 32;
        let pieces: Vec<&str> = (0..length)
            .map(|_| WIDE_PIECES[random.next() % WIDE_PIECES.len()])
            .collect();
        let mut line = pieces.join(if random.next().is_multiple_of(3) {
            ""
        } else {
            " "
        });
        // A third of the lines are cut, or have stray bytes joined on.
        if number % 3 == 0 {
            line = lossy(&line, &mut random);
        }
        for shell in SHELLS {
            let paths = paths_for(shell);
            let started = Instant::now();
            let assessment = classify(&line, shell, &paths);
            let took = started.elapsed();
            if took > worst.0 {
                worst = (took, line.clone());
            }
            let _ = effect(&line, shell, &paths);
            let wrong = disagreements(shell, &paths, [line.as_str()]);
            assert!(wrong.is_empty(), "{shell:?}: {wrong:?}");
            lines += 1;
            unreadable += usize::from(
                assessment
                    .findings()
                    .iter()
                    .any(|finding| finding.rule == Rule::Unreadable),
            );
        }
    }
    assert!(worst.0 < WORST, "{:?} for {:?}", worst.0, worst.1);
    // The set really is noise: most of it cannot be read.
    assert!(unreadable * 3 > lines, "only {unreadable} of {lines}");
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch an explosion"
)]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn finds_in_finds_are_read_in_time_whatever_their_arguments_weigh() {
    let _serial = serial();
    // The work of `find -exec` is the bytes it builds, not the arguments it
    // hands on: a few arguments of many `{}` each, or one big one, made the
    // same blow-up through a budget counted in arguments. An optimized build
    // reads each in tens of milliseconds; the bound leaves room for a
    // machine several times slower and busy.
    const LIMIT: Duration = Duration::from_secs(2);
    let levels = |places: &str, each: usize, last: &str| {
        let mut line = format!("find {places}");
        for _ in 0..each {
            line += "-exec find . . . . . . . . ";
        }
        line + last
    };
    let lines = [
        // One place of a thousand bytes, four levels of eight places, and an
        // argument of a thousand `{}`: a megabyte for each of 4,096 runs.
        (
            "levels of long arguments",
            levels(
                &format!("{} ", "a".repeat(1_000)),
                4,
                &format!("-exec echo {} \\;", "{}".repeat(1_000)),
            ),
        ),
        // One place of 25,000 bytes and one argument of 17,000 `{}`: 425 MB.
        (
            "one huge argument",
            format!(
                "find {} -exec echo {} \\;",
                "a".repeat(25_000),
                "{}".repeat(17_000)
            ),
        ),
        // The same, with twelve levels in front.
        (
            "one huge argument, deeper",
            format!(
                "find {} {}-exec echo {} \\;",
                "a".repeat(25_000),
                "-exec find . ".repeat(12),
                "{}".repeat(17_000)
            ),
        ),
        // Eight places and seven levels, then a script of 55 KB.
        (
            "a script at the bottom",
            format!(
                "find . . . . . . . . {}-exec sh -c 'echo {}' \\;",
                "-exec find . . . . . . . . ".repeat(6),
                "a".repeat(55_000)
            ),
        ),
    ];
    for (what, line) in &lines {
        assert!(line.len() <= 64 * 1024, "{what}: {}", line.len());
        let started = Instant::now();
        let assessment = classify(line, Shell::Posix, &posix());
        let took = started.elapsed();
        assert!(took < LIMIT, "{what}: {took:?}");
        assert!(
            assessment
                .findings()
                .iter()
                .any(|finding| finding.rule == Rule::Unreadable),
            "{what}"
        );
    }
}

/// How long `classify` and `effect` take on `line` together, the quickest of
/// three runs.
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a stall"
)]
fn took_with_effect(line: &str, shell: Shell, paths: &Paths) -> Duration {
    (0..3)
        .map(|_| {
            let started = Instant::now();
            let _ = classify(line, shell, paths);
            let _ = effect(line, shell, paths);
            started.elapsed()
        })
        .min()
        .unwrap_or_default()
}

/// `unit` repeated between `head` and `tail` to fill `size` bytes, or no
/// `unit` when they fill it already.
fn fit(unit: &str, head: &str, tail: &str, size: usize) -> String {
    let count = size.saturating_sub(head.len() + tail.len()) / unit.len();
    format!("{head}{}{tail}", unit.repeat(count))
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn lines_up_to_the_length_limit_are_read_in_linear_time() {
    let _serial = serial();
    // The longest line there is, in the shapes a real or a broken line takes,
    // and each a quarter as long: the one takes about four times as long as
    // the other, `classify` and `effect` together. A POSIX line that turns
    // zsh's `extendedglob` on costs up to about twice as much: a word or
    // redirect the option reads another way is judged both ways, and a line
    // with a loop or a function body is read a second time; that doubles
    // both lengths alike.
    let nested = |open: &str, size: usize| {
        let count = (size - 4) / (open.len() + 1);
        format!("{}echo{}", open.repeat(count), ")".repeat(count))
    };
    // The separator that ends a command in `shell`: `;` is one in POSIX shell
    // and PowerShell, and a space in cmd, where `&` is.
    let chain = |shell: Shell| match shell {
        Shell::Cmd => "echo x & ",
        _ => "echo x; ",
    };
    let shapes = |shell: Shell| -> [(&str, Grown); 20] {
        let chain = chain(shell);
        [
            ("a chain", Box::new(move |size| fit(chain, "", "", size))),
            (
                "a pipeline",
                Box::new(|size| fit("echo x | ", "", "cat", size)),
            ),
            (
                "a conjunction",
                Box::new(|size| fit("echo x && ", "", "echo", size)),
            ),
            ("one word", Box::new(|size| fit("a", "echo ", "", size))),
            (
                "a quote left open",
                Box::new(|size| fit("a", "echo '", "", size)),
            ),
            ("a string", Box::new(|size| fit("a", "echo \"", "\"", size))),
            ("redirects", Box::new(|size| fit("echo >a; ", "", "", size))),
            ("brackets", Box::new(|size| fit("[", "echo ", "", size))),
            (
                "substitutions left open",
                Box::new(|size| fit("$(", "echo ", "", size)),
            ),
            (
                "parentheses nested",
                Box::new(move |size| nested("(", size)),
            ),
            (
                "substitutions nested",
                Box::new(move |size| nested("$(", size)),
            ),
            (
                "blocks left open",
                Box::new(|size| fit("if x; then ", "", "", size)),
            ),
            (
                "loops left open",
                Box::new(|size| fit("for i in a b; do ", "", "", size)),
            ),
            (
                "here-documents left open",
                Box::new(|size| fit("cat <<EOF; ", "", "", size)),
            ),
            // Each name a stop is given is matched against the processes the
            // system needs and the ones that protect it.
            (
                "pkill operands",
                Box::new(|size| fit(" x", "pkill", "", size)),
            ),
            (
                "pkill -f operands",
                Box::new(|size| fit(" x", "pkill -f", "", size)),
            ),
            (
                "killall operands",
                Box::new(|size| fit(" x", "killall", "", size)),
            ),
            (
                "Stop-Process names",
                Box::new(|size| fit(",x", "Stop-Process -Name x", "", size)),
            ),
            // Each splat of a table the line writes out binds its entries:
            // as many as a splat binds, and a table too big to bind.
            (
                "splats of a table",
                Box::new(|size| fit("Set-Content @p; ", &splatted(16), "", size)),
            ),
            (
                "splats of a big table",
                Box::new(|size| fit("Set-Content @p; ", &splatted(at(1500, size)), "", size)),
            ),
        ]
    };
    // PowerShell reads brackets and loops it cannot parse only to a count:
    // the openers left open, counted before it parses, and the recoveries
    // its grammar makes.
    let time = |shell: Shell, what: &str| {
        let counted = [
            "brackets",
            "substitutions left open",
            "parentheses nested",
            "substitutions nested",
            "loops left open",
        ];
        if shell == Shell::PowerShell && counted.contains(&what) {
            Stops
        } else {
            Grows
        }
    };
    for shell in SHELLS {
        let paths = paths_for(shell);
        for (what, line) in shapes(shell) {
            assert!(line(64 * 1024).len() <= 64 * 1024, "{what}");
            time(shell, what).holds(
                &format!("{what} in {shell:?}"),
                |line| took_with_effect(line, shell, &paths),
                line,
            );
        }
    }
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch an explosion"
)]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn wrappers_that_build_their_command_are_read_in_time() {
    let _serial = serial();
    // `parallel` builds a line for each job from its command and its values,
    // and `wsl`, `env -S`, `nix run`, `nix shell`, `nix-shell`, `limactl
    // shell`, `sem` and the other runners read their words as a command.
    // An optimized build reads each in a tenth of the bound or less.
    const LIMIT: Duration = Duration::from_secs(2);
    let values = |count: usize, each: usize| {
        (0..count)
            .map(|at| format!("{at:0each$}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let rows = [
        // Every value put in at each of many replacement strings.
        format!(
            "parallel echo {} ::: {}",
            "{}".repeat(8_000),
            values(255, 120)
        ),
        format!(
            "parallel echo {} ::: {}",
            "{1}".repeat(5_000),
            values(255, 120)
        ),
        // A long command run with many values.
        format!(
            "parallel echo {} ::: {}",
            "a".repeat(60_000),
            values(255, 4)
        ),
        format!(
            "parallel -q echo {} ::: {}",
            "a b ".repeat(15_000),
            values(255, 4)
        ),
        // Replacement strings that never close.
        format!("parallel echo {} ::: a b", "{".repeat(64_000)),
        format!("parallel echo {} ::: a b", "{1".repeat(32_000)),
        // A long replacement string, looked for at each byte.
        format!(
            "parallel -I {}b echo {} ::: x y",
            "a".repeat(20_000),
            "a".repeat(40_000)
        ),
        format!("parallel -I '' echo {} ::: x y", "a".repeat(60_000)),
        // Many sources.
        format!("parallel echo{}", " ::: a".repeat(10_000)),
        format!("parallel echo{}", " :::".repeat(15_000)),
        format!("parallel echo{}", " ::: a b".repeat(7_000)),
        format!("parallel{}", " ::: a".repeat(10_000)),
        format!("parallel ::: {} ::: {}", "a".repeat(30_000), values(255, 4)),
        // Many options.
        format!("parallel{} echo ::: a", " --jo x".repeat(9_000)),
        format!("parallel{} echo ::: a", " -j 1".repeat(12_000)),
        // Nested wrappers.
        format!("{}echo ::: a b", "parallel ".repeat(6_000)),
        format!("{}rm -rf ~", "strace -f chronic ".repeat(3_000)),
        format!("wsl {}", "a b ".repeat(16_000)),
        format!("wsl -e {}", "'a b' ".repeat(10_000)),
        format!("{}rm -rf ~", "wsl ".repeat(16_000)),
        format!("{}rm -rf ~", "env -S".repeat(10_000)),
        format!("env -S'{}'", "a ".repeat(32_000)),
        format!("nix run{} nixpkgs#hello -- rm", " --arg a b".repeat(6_000)),
        format!("nix shell{} -c rm", " nixpkgs#a".repeat(6_000)),
        format!("nix develop{} -c rm", " -vvL".repeat(12_000)),
        format!("{}rm -rf ~", "nix shell x -c ".repeat(4_000)),
        format!("nix --frobnicate{} shell -c rm", " a".repeat(30_000)),
        format!("nix-shell{} ls", " --run".repeat(10_000)),
        format!("nix-shell -p{} --run ls", " a".repeat(30_000)),
        format!("limactl shell{} default rm", " --shell a".repeat(6_000)),
        format!("{}rm -rf ~", "limactl shell default ".repeat(2_500)),
        format!("{}rm -rf ~", "sem ".repeat(16_000)),
        format!("sem{} rm", " -j 1".repeat(12_000)),
        format!("launchctl submit{} -- rm -rf ~", " -l x".repeat(12_000)),
        format!("script{} /dev/null rm", " -t 1".repeat(12_000)),
        format!("script{} -c ls /dev/null", " -t 1".repeat(12_000)),
        format!("doppler run{} -- rm", " -p x".repeat(12_000)),
        format!("aws-vault exec{} prod -- rm", " -d 1h".repeat(10_000)),
        format!("ls | xargs sh -c '{}' _", "rm -rf \"$1\"; ".repeat(4_000)),
        // Archivers: every operand under every pattern of `zip -i`, the
        // commands `tar` and `zip` run, and the options `ZIPOPT` gives.
        format!(
            "zip -m x.zip{} -i{}",
            " src".repeat(8_000),
            " '*.log'".repeat(4_000)
        ),
        format!("zip -m x.zip{} -i{}", " a".repeat(250), " b".repeat(250)),
        format!("tar -xf x.tar{}", " --to-command='rm a'".repeat(3_000)),
        format!("tar -cf x.tar -C a{} src", " -I 'gzip -9'".repeat(4_000)),
        format!("zip -T{} x.zip src", " -TT 'unzip -t'".repeat(4_000)),
        format!("{}zip -r x.zip src", "ZIPOPT='-q -m' ".repeat(4_000)),
        format!("ZIPOPT='{}' zip -r x.zip src", "-q ".repeat(20_000)),
        // A value read again at each of many `zip` calls: one too long to
        // split, one as long as the guard splits, and many assignments.
        format!(
            "export ZIPOPT='{}'; {}",
            "-q ".repeat(10_000),
            "zip x; ".repeat(5_000)
        ),
        format!(
            "export ZIPOPT='{}'; {}",
            "-q ".repeat(64),
            "zip x; ".repeat(9_000)
        ),
        format!(
            "export ZIP='{}'; {}",
            "\"-q\" ".repeat(64),
            "zip x; ".repeat(9_000)
        ),
        format!("{}{}", "ZIPOPT=-q; ".repeat(4_000), "zip x; ".repeat(3_000)),
        format!(
            "{}{}",
            "ZIPOPT+=-q; ".repeat(4_000),
            "zip x; ".repeat(2_000)
        ),
        format!("rar m x.rar{}", " ~/a".repeat(15_000)),
        // Package and environment runners: words of yarn taken off, options
        // a table does not list (each may take the word after it), lines
        // run side by side, nested runners.
        format!("yarn{} rimraf ~", " workspace a".repeat(5_000)),
        format!("yarn{} exec rm", " workspaces foreach -A".repeat(2_500)),
        format!("uvx{} rimraf ~", " --a x".repeat(10_000)),
        format!("pipx run{} rimraf ~", " -q".repeat(20_000)),
        format!("concurrently {}", "'rm -rf ~' ".repeat(5_000)),
        format!("npm-run-all {}", "'a:*' ".repeat(10_000)),
        format!("{}rm -rf ~", "poetry run ".repeat(5_000)),
        format!("{}rm -rf ~", "corepack npx ".repeat(4_000)),
        format!("{}rm -rf ~", "npx cross-env A=1 ".repeat(3_000)),
        format!("mise exec{} -- rm -rf ~", " a@1".repeat(12_000)),
        // A command set once in the environment and run by each `npx`, and
        // placeholders each filled in with every word passed on.
        format!(
            "export npm_config_call='{}'; {}",
            "rm -rf ~; ".repeat(4_800),
            "npx; ".repeat(200)
        ),
        format!(
            "export npm_config_call='rm -rf ~'; {}",
            "npx; ".repeat(12_000)
        ),
        format!(
            "concurrently -P '{}' -- {}",
            "rm {@}; ".repeat(2_000),
            "a ".repeat(12_000)
        ),
        format!(
            "{}rm -rf ~",
            "micromamba --log-level info run ".repeat(1_500)
        ),
        format!("micromamba{} run rm -rf ~", " --a x".repeat(10_000)),
    ];
    for line in &rows {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let started = Instant::now();
        let _ = classify(line, Shell::Posix, &posix());
        let took = started.elapsed();
        assert!(took < LIMIT, "{took:?} for {:?}", &line[..40]);
    }
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a stall"
)]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn cmd_commands_read_again_are_read_in_time() {
    let _serial = serial();
    // cmd's `ver && if …`, `i^f`, `f^or`, `ca^ll` and `call call` are each
    // read again as a statement of their own, and each holds the rest of the
    // line: repeated, the line would be read once for each. An optimized
    // build reads each in a tenth of the bound or less.
    const LIMIT: Duration = Duration::from_secs(2);
    let fit = |unit: &str| {
        let tail = "rd /s /q C:\\";
        let count = (64 * 1024 - tail.len()) / unit.len();
        format!("{}{tail}", unit.repeat(count))
    };
    let nested = |open: &str| {
        let count = 390;
        format!("{}rd /s /q C:\\{}", open.repeat(count), ")".repeat(count))
    };
    let lines = [
        fit("ver && if a "),
        fit("i^f a "),
        fit("f^or %%i in (a) do "),
        fit("ca^ll "),
        fit("call "),
        fit("call.bat & "),
        fit("call.rd x & "),
        nested("ver && if a ("),
        nested("i^f a ("),
    ];
    let paths = paths_for(Shell::Cmd);
    for line in &lines {
        let started = Instant::now();
        let assessment = classify(line, Shell::Cmd, &paths);
        let took = started.elapsed();
        assert!(took < LIMIT, "{took:?} for {:?}", &line[..40]);
        assert!(!assessment.is_safe(), "{:?}", &line[..40]);
    }
}

/// `count` folders, each the folder searched spelled its own way and ending
/// in `//`, each followed by a space.
fn distinct_folders(count: usize) -> String {
    (0..count)
        .map(|at| format!("s{at}/..// "))
        .collect::<Vec<_>>()
        .concat()
}

/// A line of a shape, and how it is made for a size.
type Shape = (&'static str, fn(usize) -> String);

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn find_expressions_are_read_in_linear_time() {
    let _serial = serial();
    // A `find` expression is read for `.git` and its entries below each
    // folder searched: its name and path patterns are asked of every name
    // `.git` holds, and a path pattern again for each folder.
    let paths = posix();
    let shapes: [Shape; 11] = [
        ("names joined by -o", |size| {
            format!("find . {}-delete", filled("-name HEAD -o ", size, 20))
        }),
        ("negations", |size| {
            format!("find . {}-name HEAD -delete", filled("! ", size, 30))
        }),
        ("brackets", |size| {
            let open = filled("( ", size / 2, 20);
            format!(
                "find . {open}-name HEAD{} -delete",
                " )".repeat(open.len() / 2)
            )
        }),
        ("folders and a path test", |size| {
            format!("find {}-path '*/HEAD' -delete", filled(". ", size, 30))
        }),
        ("folders and path tests", |size| {
            let half = size / 2;
            format!(
                "find {}{}-delete",
                filled(". ", half, 20),
                filled("-path '*/x' -o ", half, 20)
            )
        }),
        ("a long name pattern", |size| {
            format!("find . -name '{}' -delete", filled("*a", size, 30))
        }),
        ("a long path pattern", |size| {
            format!("find . -path '{}' -delete", filled("*a", size, 30))
        }),
        ("prunes", |size| {
            format!(
                "find . {}-name HEAD -exec rm {{}} +",
                filled("-name .git -prune -o ", size, 40)
            )
        }),
        ("tests and actions", |size| {
            format!(
                "find . {}-delete",
                filled("-type f -print -mtime 1 , ", size, 20)
            )
        }),
        // A folder ending in `//` spells `.git` three ways, a bracket reads
        // the pattern twice, and `*?` keeps every position of it live.
        (
            "folders spelled three ways and a live path pattern",
            |size| {
                let half = size / 2;
                format!(
                    "find {}-ipath '{}[Z]' -delete",
                    filled(".// ", half, 20),
                    filled("*?", half, 20)
                )
            },
        ),
        ("distinct folders and a live path pattern", |size| {
            let half = size / 2;
            // Each is the folder searched, spelled its own way.
            let folders = distinct_folders(half / 12);
            format!(
                "find {folders}-ipath '{}[Z]' -delete",
                filled("*?", half, 20)
            )
        }),
    ];
    for (what, line) in shapes {
        assert_linear(what, Shell::Posix, &paths, line);
        assert!(
            !classify(&line(64 * 1024), Shell::Posix, &paths).is_safe(),
            "{what}"
        );
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn find_path_tests_over_many_folders_are_read_in_time() {
    let _serial = serial();
    // Each of these short lines asks a path pattern of every name `.git`
    // holds, for each folder searched and each way it spells `.git`: they
    // took seconds before the work was counted. They take milliseconds; the
    // bound leaves room for a slower machine.
    const LIMIT: Duration = Duration::from_millis(250);
    let paths = posix();
    let live = |pairs: usize| "*?".repeat(pairs);
    let lines = [
        format!(
            "find {}-ipath '{}[Z]' -delete",
            ".// ".repeat(250),
            live(120)
        ),
        format!(
            "find {}-ipath '{}[Z]' -delete",
            distinct_folders(250),
            live(120)
        ),
        format!("find {}-ipath '{}' -delete", ".// ".repeat(120), live(250)),
        format!("find {}-ipath '{}' -delete", ".// ".repeat(30), live(1000)),
        // Just inside the work allowed, and just past it.
        format!("find .// -ipath '{}[Z]' -delete", live(260)),
        format!("find .// -ipath '{}[Z]' -delete", live(280)),
        format!("find . -path '{}' -delete", live(2000)),
    ];
    for line in lines {
        let took = took(&line, Shell::Posix, &paths);
        assert!(took < LIMIT, "{took:?} for {:?}", &line[..40]);
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn shapes_that_stalled_a_grammar_or_a_rule_are_read_in_linear_time() {
    let _serial = serial();
    // Each took from half a second to over a minute in a release build: the
    // grammar went back over the rest of the line at every token (stopped
    // by the budget of what its lexer reads, `MAX_LEXED` in `unit.rs`), a
    // pipeline ending in an error (counted, `MAX_PIPES` in `tangled.rs`,
    // also behind a shift in arithmetic and through compound commands),
    // the readings of `Copy-Item` and `Move-Item` taken pair by pair (now
    // once for each spelling), each path of `New-Item` joined with each item
    // of a list given to its `-Name` (one name, the list joined), a folder one deeper at each `cd` read again
    // for every path (`MAX_DIR_LEN` in `unit.rs`, which folds a round trip
    // down and back up), PowerShell's children asked one by one for the
    // next, and a long word read back to its start at each `(` (`qualifier`
    // in `posix.rs`). Brackets left open, where the grammar recovers from an
    // error at each (PowerShell's lexer also reads on to the next `}` at
    // each `${`), took a tenth of a second to a second at the length limit,
    // and 3.4 s on a slow machine for `${` repeated, inside the budget of
    // what a lexer reads: they are counted before parsing (`Openers` in
    // `tangled.rs`). A chain of PowerShell assignments (`$a = $a = … gc
    // .env`), whose value was read again for its variables at each level,
    // took over two seconds in a debug build: each level now reads only its
    // own nodes (`variables` in `powershell.rs`). A path is judged again from
    // each other folder a `cd` that may have failed or not run may have left
    // the line in, which made the `cd` rows two to three times slower until a
    // `cd ..` back from one after `&&` added none and every folder only known
    // when it runs counted as one (`MAX_ELSEWHERE` in `unit.rs`). Noise the
    // POSIX and PowerShell grammars recover from at every token (`${a}`,
    // `1 2 ` or `$a[0]` repeated, `{` ten deep then closed) took a second at
    // the length limit, a few tens of microseconds for each recovery, while
    // it read no more text than a plain line: the recoveries are counted
    // from the grammar's log (`MAX_RECOVERIES` in `unit.rs`). A `cp` of
    // thousands of names into a folder thousands of bytes long placed each
    // name with the whole folder, for every time it was given: each name is
    // now placed once, and the bytes placed are counted (`MAX_LANDING_BYTES`
    // in `detect.rs`), also where the copies are followed for a send
    // (`copied_by` in `detect/send.rs`). The log the recoveries are counted
    // from makes the lines that read the same 30 to 70 per cent slower (a
    // parse first runs without it for a line's first steps, `MAX_QUIET` in
    // `unit.rs`, which a line of a few kilobytes fits, so a longer line
    // still pays for it): the slowest, a `cd` back up in PowerShell or a
    // runner that starts another, take up to 190 ms at the length limit in
    // an optimized build, which a fixed bound of 250 ms left no room for on
    // a busy machine. So each row is held to how its time grows instead:
    // written at the length limit (its counts are the ones a line of 64 KB
    // has, `at`) and a quarter as long, the one takes about four times as
    // long as the other, not sixteen. A row read only to a budget or a
    // count, past which it stops (the openers counted before parsing, the
    // recoveries and the characters a grammar's lexer moves over counted
    // from its log), takes no longer past it, so two lengths cannot show how
    // its time grows: it is held to a fixed bound at each of several lengths
    // instead (`Stops`).
    let rows: Vec<(Shell, Time, Grown)> = vec![
        (
            Shell::PowerShell,
            Grows,
            Box::new(|size| "Move-Item src\\a ".repeat(at(2_000, size))),
        ),
        (
            Shell::PowerShell,
            Grows,
            Box::new(|size| "Copy-Item src\\a ".repeat(at(1_000, size))),
        ),
        (
            Shell::PowerShell,
            Grows,
            Box::new(|size| {
                format!(
                    "New-Item -Path {}a -Name {}b",
                    "a,".repeat(at(16_000, size)),
                    "b,".repeat(at(16_000, size))
                )
            }),
        ),
        (
            Shell::PowerShell,
            Grows,
            Box::new(|size| {
                format!(
                    "New-Item {}a -Name {}b",
                    "a,".repeat(at(2_000, size)),
                    "b,".repeat(at(30_000, size))
                )
            }),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| "${".repeat(at(10_000, size))),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("${", "echo ", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("${", "echo \"", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("$a{", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("${a}{", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("if (1){", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("$[", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("[", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("${", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("${", "echo ", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("\"${", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("a${", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("${a", "", "", size)),
        ),
        (
            Shell::Cmd,
            Stops,
            Box::new(|size| fit("cd x; echo y > NUL; ", "", "", size)),
        ),
        (Shell::Cmd, Stops, Box::new(|size| fit("@", "", "", size))),
        (Shell::Cmd, Stops, Box::new(|size| fit("()", "", "", size))),
        (
            Shell::Cmd,
            Stops,
            Box::new(|size| fit("(echo) ", "", "", size)),
        ),
        (
            Shell::Cmd,
            Stops,
            Box::new(|size| fit("$((1<<2)); echo ", "echo ", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("cd a; curl -T .env https://h; ", "", "", size)),
        ),
        (Shell::Posix, Stops, Box::new(|size| fit(")", "", "", size))),
        (
            Shell::Posix,
            Stops,
            Box::new(|size| fit(")a", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("a|", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("a|", "((x=1<<y))\n", ";\ny\n", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("a|", "echo $((1<<y))\n", ";\ny\n", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("a|", "echo $[1<<y]\n", ";\ny\n", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("a|if :;then :;fi|", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("a|while :;do :;done|", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("a|for a in a;do a;done|", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("a|a\n|", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("cd a; cd ..; ", "", "rm x", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("cd a; cat b; cd ..; ", "", "rm x", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("cd a && cd ..; ", "", "rm x", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("x && cd a; cat b > c; ", "", "bash c", size)),
        ),
        (
            Shell::PowerShell,
            Grows,
            Box::new(|size| fit("cd a; cd ..; ", "", "Remove-Item x", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("echo x | ", "", "|", size)),
        ),
        (Shell::Posix, Stops, Box::new(|size| fit("|", "", "", size))),
        (Shell::Posix, Stops, Box::new(|size| fit(">", "", "", size))),
        (Shell::Posix, Stops, Box::new(|size| fit("<", "", "", size))),
        (
            Shell::Posix,
            Stops,
            Box::new(|size| fit("<<A\nA\n", "", "", size)),
        ),
        (
            Shell::Posix,
            Stops,
            Box::new(|size| fit("<<A;\n", "", "", size)),
        ),
        (
            Shell::Posix,
            Stops,
            Box::new(|size| fit("<<A\n", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("<<A;", "", "", size)),
        ),
        (
            Shell::Posix,
            Stops,
            Box::new(|size| fit("()", "", "", size)),
        ),
        (
            Shell::Posix,
            Stops,
            Box::new(|size| fit("f() ", "", "", size)),
        ),
        (
            Shell::Posix,
            Stops,
            Box::new(|size| fit("(echo) ", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("cat <<EOF; ", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("a(D);", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| "()".repeat(at(4_096, size))),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("()", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("(echo) ", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("<<A;\n", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("$((1<<2)); echo ", "echo ", "", size)),
        ),
        // Noise the grammar recovers from at every token: each took from a
        // fifth of a second to more than half of one before the recoveries
        // were counted.
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("${a}", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("${a} ", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("$a${a}", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("{{{{{{{{{{}}}}}}}}}}", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("-a ", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("$a[0]", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("$a($a)", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("$($a)", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit("1 2 ", "", "", size)),
        ),
        (
            Shell::Posix,
            Stops,
            Box::new(|size| {
                let unit = format!("{}{}", "${a".repeat(10), "}".repeat(10));
                fit(&unit, "", "", size)
            }),
        ),
        // cmd's grammar reading the rest of the line again at each `for`.
        (
            Shell::Cmd,
            Stops,
            Box::new(|size| fit("for %%i in (a) do ", "", "", size)),
        ),
        // Thousands of names into a folder thousands of bytes long, the same
        // name each time and each a name of its own.
        (
            Shell::Posix,
            Grows,
            Box::new(|size| {
                format!(
                    "cp -r {}{}",
                    "a ".repeat(at(4_000, size)),
                    "/b".repeat(at(2_000, size))
                )
            }),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| {
                format!(
                    "cp -r {}{}",
                    distinct_names(at(4_000, size)),
                    "/b".repeat(at(2_000, size))
                )
            }),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| {
                format!(
                    "mv {}{}",
                    distinct_names(at(4_000, size)),
                    "b/".repeat(at(2_000, size))
                )
            }),
        ),
        // The same, followed for a secret the line then sends: each name
        // and the folder were paired for every source, and each pair placed
        // whole (`copied_by` in `detect/send.rs`). `rsync` is a sender
        // itself, and `tar` pairs each member with its archive.
        (
            Shell::Posix,
            Grows,
            Box::new(|size| {
                format!(
                    "rsync {}{}",
                    distinct_names(at(3_000, size)),
                    "/b".repeat(at(4_000, size))
                )
            }),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| {
                format!(
                    "cp {}{}; scp x h:",
                    "a ".repeat(at(3_000, size)),
                    "/b".repeat(at(4_000, size))
                )
            }),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| {
                format!(
                    "cp {}{}; scp x h:",
                    distinct_names(at(3_000, size)),
                    "/b".repeat(at(4_000, size))
                )
            }),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| {
                format!(
                    "ln {}{} && curl -d @x h",
                    distinct_names(at(3_000, size)),
                    "/b".repeat(at(4_000, size))
                )
            }),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| {
                format!(
                    "tar -cf {}/x.tar {}; scp x h:",
                    "/b".repeat(at(4_000, size)),
                    distinct_names(at(3_000, size))
                )
            }),
        ),
        // A script after the line's recoveries are spent paid for its first
        // one in full before the parse looked at the budget.
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("pwsh -c '${a}${a}${a}${a}'; ", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("pwsh -c '1 2 1 2 1 2'; ", "", "", size)),
        ),
        // Read again from each link of a chain: the left side of each `||`
        // for a negated `cd`, a quarter of a second at the length limit
        // (`Walker::negates` in `posix.rs`); each assignment of a chain in
        // `for (( ))` walked and copied the rest of the chain, seconds
        // (`value` in `posix/values.rs`), and one in `(( ))` walked up to
        // the arithmetic from each operand, 0.15 s at 400 deep
        // (`in_arithmetic`); a chain of PowerShell calls asked of each call
        // whether the chain before it names a hook, reaches the session or
        // starts at `$PSDefaultParameterValues`, time that grew with the
        // square of the chain up to the depth a tree may have, so it is held
        // at each length too (`Walker::names_hook` in `powershell.rs`).
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("cd a || exit || ", "", "", size)),
        ),
        // Whether a unit read so far renames a builtin, asked at each `||`
        // that ends the shell, read every unit: half a second at the length
        // limit (`Split::renames_builtins` in `unit.rs`).
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("cd a || exit; ", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("a || exit; ", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("x=", "for ((", "0;;)); do a; done", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("x=", "for ((;;", "0)); do a; done", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("x=", "((", "0))", size)),
        ),
        (
            Shell::PowerShell,
            Stops,
            Box::new(|size| fit(".Add(1, $b)", "$PSDefaultParameterValues", "", size)),
        ),
        (
            Shell::PowerShell,
            Grows,
            Box::new(|size| fit("$PSDefaultParameterValues.Add(1, $b); ", "", "", size)),
        ),
        // A pattern matched against every startup file, protected path and
        // secret, a tenth of a millisecond each, half a second at the length
        // limit: the same one again (`placed` in `path.rs`), and each its
        // own, with letters and digits or with none (`could_pick` and
        // `plain_matches` in core's `resolve.rs`).
        (
            Shell::PowerShell,
            Grows,
            Box::new(|size| fit("sc *a x;.\\b;", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Grows,
            Box::new(|size| distinct_patterns(size, |at| format!("*a{at}"))),
        ),
        (
            Shell::PowerShell,
            Grows,
            Box::new(|size| {
                distinct_patterns(size, |at| {
                    (0..13)
                        .map(|bit| if at >> bit & 1 == 1 { '?' } else { '-' })
                        .collect()
                })
            }),
        ),
        // Thousands of names into a short folder.
        (
            Shell::Posix,
            Grows,
            Box::new(|size| format!("cp {}b", distinct_names(at(9_000, size)))),
        ),
        // A runner that starts another, each read in turn: up to a fifth of
        // a second at the length limit in a release build.
        (
            Shell::Cmd,
            Grows,
            Box::new(|size| fit("bun exec ", "", "", size)),
        ),
        (
            Shell::Posix,
            Grows,
            Box::new(|size| fit("bun exec ", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Grows,
            Box::new(|size| fit("bun exec ", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Grows,
            Box::new(|size| fit("cmd /c ", "", "", size)),
        ),
        (
            Shell::PowerShell,
            Grows,
            Box::new(|size| fit("$a = ", "", "gc .env", size)),
        ),
        (Shell::PowerShell, Grows, Box::new(distinct_assignments)),
    ];
    for (shell, time, line) in &rows {
        let longest = line(64 * 1024);
        assert!(longest.len() <= 64 * 1024, "{}", longest.len());
        let paths = paths_for(*shell);
        let what = format!("{:?} in {shell:?}", &longest[..20]);
        time.holds(&what, |line| took(line, *shell, &paths), line);
    }
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a stall"
)]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn commands_of_a_name_the_line_sets_many_times_are_read_in_linear_time() {
    let _serial = serial();
    // Every command may run any of the targets the line sets its name to, so
    // the readings are bounded, and past the bound the line is unreadable.
    // Each line, at the length limit and a quarter as long, takes about four
    // times as long as the other, `classify` and `effect` together.
    let paths = paths_for(Shell::PowerShell);
    let mut many = String::new();
    for at in 0..100 {
        let at = at.to_string();
        many.push_str(&["Set-Alias x t", &at, "; Set-Alias t", &at, " y; "].concat());
    }
    // Targets of the name's own key add no reading, so they never run the
    // bound out: each command must still cost one lookup, not a walk of
    // every target.
    let mut same = String::new();
    for at in 0..64 {
        same.push_str(&["Set-Alias x C:\\a", &at.to_string(), "\\x.exe; "].concat());
    }
    for (head, unit, risky) in [
        (many.as_str(), "x ~; ", true),
        ("Set-Alias x Remove-Item; ", "x b; ", true),
        (same.as_str(), "x; ", false),
        (same.as_str(), "x | x | x | x; ", false),
    ] {
        let line = |size| fit(unit, head, "", size);
        assert_linear_by(
            &format!("{}… {unit}…", &head[..20]),
            |line| took_with_effect(line, Shell::PowerShell, &paths),
            line,
        );
        if risky {
            let assessment = classify(&line(64 * 1024), Shell::PowerShell, &paths);
            assert!(
                assessment
                    .findings()
                    .iter()
                    .any(|finding| matches!(finding.rule, Rule::Unreadable | Rule::Unknown)),
                "{assessment:?}"
            );
        }
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn blocks_held_in_variables_properties_and_members_are_read_in_linear_time() {
    let _serial = serial();
    // The variables of a line are read once for the whole of it, and the
    // ones that may reach the session are followed from one to the next once
    // each; a chain of members or calls is walked down only as deep as a
    // tree is; a value is read for blocks only as deep as a limit; and the
    // letters of numbers are made lower case in one pass, subexpressions in
    // strings only as deep as a limit; a cmdlet is given at most 16 default
    // parameter values, and the cmdlets of a line at most 1024 arguments by
    // them. Each row is the part repeated, the head and the tail.
    // A table of 16 entries, each `entry`.
    let defaults = |entry: &str| {
        format!(
            "$PSDefaultParameterValues = @{{ {} }}; ",
            vec![entry; 16].join("; ")
        )
    };
    let sixteen = format!(
        "$PSDefaultParameterValues = @{{ {} }}; ",
        (0..16)
            .map(|at| format!("'*:P{at}' = '~'"))
            .collect::<Vec<_>>()
            .join("; ")
    );
    let any_p = defaults("'Remove-*:P*' = '~'");
    let path = defaults("'Remove-*:Path' = '~'");
    // The most entries a splat binds.
    let bound = splatted(16);
    let rows = [
        ("Invoke-Command $sb; ", "$sb = { Get-ChildItem }; ", ""),
        // A splat of a table the line writes out binds what it holds.
        (
            "Set-Content @p; ",
            "$p = @{ Path = 'x'; Value = 'y' }; ",
            "",
        ),
        ("$q = @{ Path = 'x' }; Set-Content @q; ", "", ""),
        ("Set-Content @p; ", bound.as_str(), ""),
        ("$v = 1; ", "", "Invoke-Command $v"),
        ("$v = { 1 }; Invoke-Command $v; ", "", ""),
        (".a()", "$x", ""),
        (".a()", "$ExecutionContext", ""),
        (".a", "$ExecutionContext", " = $b"),
        ("[0]", "$ExecutionContext.InvokeCommand", ".Value = $b"),
        (".Add(1, $b)", "$PSDefaultParameterValues", ""),
        ("Remove-Item -Recurse; ", sixteen.as_str(), ""),
        (
            "$PSDefaultParameterValues['*:Path'] = '~'; ",
            "",
            "Remove-Item",
        ),
        ("ri;", any_p.as_str(), ""),
        ("ri;", path.as_str(), ""),
        ("gci|ri;", any_p.as_str(), ""),
        ("iex 'ri';", any_p.as_str(), ""),
        ("Update-TypeData -Force -TypeName X ", "", "x.ps1xml"),
        ("$env:BASH_ENV = 'x.sh'; bash; ", "", ""),
        ("@{e=", "Get-ChildItem | Sort-Object ", ""),
        ("@{e=@{e=1}}, ", "Get-ChildItem | Sort-Object ", "x"),
        (" -replace 'a', $b", "'a'", ""),
        (" -replace 'a', 'b'", "'a'", ""),
        ("1MB ", "echo ", ""),
        ("1MB+", "", "1"),
        ("\"$(1MB)\" ", "echo ", ""),
        ("\"$(", "echo ", ""),
        (".SessionStateProxy", "$x", ".$h = $b"),
        (".$h", "$x.InvokeCommand", " = $b"),
        (
            "[0]",
            "$x",
            ".psobject.Properties['CommandNotFoundAction'].Value = $b",
        ),
        (
            "$a = $e; $e = $a; ",
            "$e = $ExecutionContext; ",
            "$a.$m.$h = $b",
        ),
        ("Name, ", "Get-ChildItem | Select-Object ", "x"),
        ("Name, ", "Compare-Object $a $c -Property ", "x"),
        (" -split $b", "'a'", ""),
        ("Invoke-Command; ", "", ""),
        (
            "$h.Add(1, 2); ",
            "$h = @{}; ",
            "Get-ChildItem | Select-Object $h",
        ),
        ("$o | Add-Member ScriptMethod X $b; ", "", ""),
        (
            "-Value $b ",
            "Add-Member -MemberType ScriptMethod -Name X ",
            "",
        ),
    ];
    let paths = paths_for(Shell::PowerShell);
    for (part, head, tail) in rows {
        assert_linear(
            &format!("{head}{part}…{tail}"),
            Shell::PowerShell,
            &paths,
            |size| {
                format!(
                    "{head}{}{tail}",
                    filled(part, size, head.len() + tail.len())
                )
            },
        );
    }
}

/// A PowerShell table of `count` entries, each a key of its own, held in
/// `$p`: `$p = @{ K0 = 'v'; K1 = 'v'; … }; `.
fn splatted(count: usize) -> String {
    format!(
        "$p = @{{ {} }}; ",
        (0..count)
            .map(|at| format!("K{at} = 'v'"))
            .collect::<Vec<_>>()
            .join("; ")
    )
}

/// `count` names, each other than the rest: `a0 a1 a2 …`, each with a space
/// after it.
fn distinct_names(count: usize) -> String {
    (0..count)
        .map(|at| format!("a{at}"))
        .collect::<Vec<_>>()
        .join(" ")
        + " "
}

/// PowerShell writes of a pattern each other than the rest, `pattern` of
/// each count, each followed by a run of a script (`sc *a0 x;.\b;sc *a1
/// x;.\b;…`), of at most `size` bytes.
fn distinct_patterns(size: usize, pattern: impl Fn(usize) -> String) -> String {
    let mut line = String::new();
    for at in 0.. {
        let next = format!("sc {} x;.\\b;", pattern(at));
        if line.len() + next.len() > size {
            break;
        }
        line.push_str(&next);
    }
    line
}

/// A chain of PowerShell assignments, each to a variable of its own
/// (`$a0 = $a1 = … gc .env`), of at most `size` bytes.
fn distinct_assignments(size: usize) -> String {
    let tail = "gc .env";
    let mut line = String::new();
    for at in 0.. {
        let next = format!("$a{at} = ");
        if line.len() + next.len() + tail.len() > size {
            break;
        }
        line += &next;
    }
    line + tail
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn drives_devices_and_session_places_are_read_in_linear_time() {
    let _serial = serial();
    // Each drive the line makes is looked up by name, a word on a session
    // drive is read once, a variable a program reads as its arguments is
    // noted once for a value only known when it runs, and a path past
    // `/dev/fd` is walked once.
    let windows = common::windows();
    let distinct = |each: fn(usize) -> String| {
        move |size: usize| {
            let mut line = String::new();
            for at in 0.. {
                let next = each(at);
                if line.len() + next.len() > size {
                    break;
                }
                line.push_str(&next);
            }
            line
        }
    };
    assert_linear(
        "New-PSDrive d<n> …; Remove-Item d<n>:\\x",
        Shell::PowerShell,
        &windows,
        distinct(|at| format!("New-PSDrive d{at} Registry HKCU:\\; Remove-Item d{at}:\\x; ")),
    );
    assert_linear(
        "Set-Item Env:x<n> 1; Remove-Item $env:TEMP\\x",
        Shell::PowerShell,
        &windows,
        distinct(|at| format!("Set-Item Env:x{at} 1; Remove-Item -Recurse \"$env:TEMP\\x\"; ")),
    );
    for (what, head, part) in [
        ("Set-Item Env:$n x …", "", "Set-Item Env:$n x; "),
        ("Set-Item Env:* x …", "", "Set-Item Env:* x; "),
        ("cd Env:; Set-Item $n x …", "cd Env:; ", "Set-Item $n x; "),
        ("Rename-Item Env:* a …", "", "Rename-Item Env:* a; "),
        (
            "Rename-Item Env:* npm_config_call …",
            "",
            "Rename-Item Env:* npm_config_call; ",
        ),
        (
            "Set-Item Env`:TEMP x …",
            "",
            "Set-Item Env`:TEMP x; Remove-Item \"$env:TEMP\\x\"; ",
        ),
    ] {
        assert_linear(what, Shell::PowerShell, &windows, |size| {
            format!("{head}{}", filled(part, size, head.len()))
        });
    }
    assert_linear(
        "Remove-Item Temp:\\x …",
        Shell::PowerShell,
        &windows,
        |size| filled("Remove-Item Temp:\\x\\NUL; ", size, 0),
    );
    assert_linear(
        "echo x > /dev/fd/../fd/…",
        Shell::Posix,
        &posix(),
        |size| {
            format!(
                "echo x > /dev/fd/{}1",
                filled("../fd/", size, "echo x > /dev/fd/1".len())
            )
        },
    );
    assert_linear(
        "echo x > /dev/fd/../cwd/../stdout; …",
        Shell::Posix,
        &posix(),
        |size| filled("echo x > /dev/fd/../cwd/../stdout; ", size, 0),
    );
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn values_only_known_when_they_run_are_read_in_linear_time() {
    let _serial = serial();
    // Each value only known when it runs is read once: as an output of
    // `dd`, an operand an option's value adds, a destination, and an
    // option that destroys or changes a setting, split into words or
    // starting with a `-`.
    let (shell, paths) = (Shell::Posix, posix());
    for (head, part, tail) in [
        ("dd if=a ", "of=$x bs=$b ", ""),
        ("tar -cf x.tar ", "--exclude $e -C $d ", "--remove-files"),
        ("tar -cf x.tar ", "\"--$x\" ", "src"),
        ("zip -m x.zip ", "-b $t ", "src"),
        ("shred ", "-n $n ", "x"),
        ("mv ", "-S $x ", "a b"),
        ("cp ", "--target-directory=\"$t\" ", "a"),
        ("git push ", "$f ", "origin main"),
        ("git push ", "\"-$f\" \"${x:---force}\" ", "origin main"),
        ("find ~ -name x ", "\"$a\" ", ""),
        ("docker image prune ", "$f ", ""),
        ("terraform apply ", "$f ", ""),
        ("iptables ", "-s $ip ", ""),
    ] {
        assert_linear(&format!("{head}{part}…"), shell, &paths, |size| {
            format!(
                "{head}{}{tail}",
                filled(part, size, head.len() + tail.len())
            )
        });
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn powershell_lines_scanned_for_a_refused_less_than_are_read_in_linear_time() {
    let _serial = serial();
    // Each node's own text is scanned once for a `<` PowerShell refuses
    // (`refused_input` in `powershell.rs`): a quote that runs on past a
    // child, a `<` inside a substitution in a string, and a `<` the grammar
    // reads as a redirect over and over.
    let (shell, paths) = (Shell::PowerShell, paths_for(Shell::PowerShell));
    for (head, part, tail) in [
        ("echo ", "a\"$a<\" ", ""),
        ("echo \"", "$(1)<", "\""),
        ("echo ", "< ", ""),
    ] {
        assert_linear(&format!("{head}{part}…"), shell, &paths, |size| {
            format!(
                "{head}{}{tail}",
                filled(part, size, head.len() + tail.len())
            )
        });
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn loops_and_function_bodies_that_run_again_elsewhere_are_read_in_linear_time() {
    let _serial = serial();
    // Each unit and redirect of a loop with a `cd`, or of a function body a
    // `cd` comes after, is judged once more from a folder only known when it
    // runs, and from the few folders the walk knows it runs from (where each
    // call is made, where a loop's body ends), however many loops and bodies
    // it is nested in and however many calls there are.
    let (shell, paths) = (Shell::Posix, posix());
    for (what, head, part) in [
        (
            "f() { … }; cd …; f; cd …; f…",
            "f() { rm -rf b > o < i; }; ",
            "cd d; f; cd /e; f; ",
        ),
        (
            "for … f … cd …",
            "f() { rm -rf b > o; }; for i in 1 2; do ",
            "f; cd /a; f; cd b; ",
        ),
        (
            "TRAPEXIT() { … }; cd …",
            "TRAPEXIT() { rm -rf b > o; }; ",
            "cd /a || cd b; ",
        ),
        // Every call is made before the `cd`.
        (
            "f() { … }; f; cd …; ls…",
            "f() { rm -rf b > o; }; ",
            "f; cd d; ls; ",
        ),
        // A use of an alias with words runs its last command with them.
        (
            "alias x='…' y=x; cd …; y ……",
            "alias x='rm -rf b' y=x; ",
            "cd d; y c > o; ",
        ),
    ] {
        assert_linear(what, shell, &paths, |size| {
            let tail = if head.contains(" do ") { "done" } else { "" };
            format!(
                "{head}{}{tail}",
                filled(part, size, head.len() + tail.len())
            )
        });
    }
    for (what, part, tail) in [
        (
            "for … cd …; done…",
            "for i in 1 2; do rm -rf b > o; cd x; done; ",
            "",
        ),
        ("f() { … }…; cd /", "f() { rm -rf b > o; }; ", "cd /"),
        (
            "f() { … cd …; }; f…",
            "f() { rm -rf b > o; cd x; }; f; ",
            "",
        ),
        // zsh's `repeat` runs its body again, as a loop does.
        (
            "repeat 2 { … cd …; }…",
            "repeat 2 { rm -rf b > o; cd x; }; ",
            "",
        ),
        (
            "repeat 2 do … cd …; done…",
            "repeat 2 do rm -rf b > o; cd x; done; ",
            "",
        ),
        // A short `repeat` repeats the chain its command starts: each one
        // in the chain is a body to the end of it.
        (
            "repeat 2 a && … cd …",
            "repeat 2 rm -rf b > o && cd x && ",
            "ls",
        ),
        // An alias's value is a body too, read from where it is used.
        ("alias x='…'…; cd /", "alias x='rm -rf b > o'; x; ", "cd /"),
        (
            "alias x='… cd …'; x…",
            "alias x='rm -rf b > o; cd x' y=ls; x; ",
            "",
        ),
        // What a here-string on a loop runs is read from where it starts.
        (
            "while …; do cd ..; done <<< \"$(…)\"…",
            "while read l; do cd ..; done <<< \"$(rm -rf b)\"; ",
            "",
        ),
        // With `autocd` on, a command of one word is a `cd`.
        ("setopt autocd; a; b…", "setopt autocd; a; rm -rf b; ", ""),
        (
            "alias x='…' y=x; y ……",
            "alias x='rm -rf b' y=x; y c > o; ",
            "",
        ),
        // A body may run after the line turns it on.
        (
            "f() { a; … }; setopt autocd; f…",
            "f() { a; rm -rf b; }; setopt autocd; f; ",
            "",
        ),
    ] {
        assert_linear(what, shell, &paths, |size| {
            format!("{}{tail}", filled(part, size, tail.len()))
        });
    }
    for (what, open, close) in [
        ("while x; do … (100 deep)", "while x; do ", "done; "),
        ("f() { f() { … (100 deep)", "f() { ", "}; "),
    ] {
        let (open, close) = (open.repeat(100), close.repeat(100));
        assert_linear(what, shell, &paths, |size| {
            let slack = open.len() + close.len() + 6;
            format!(
                "{open}{}cd /; {close}",
                filled("rm -rf b > o < i; ", size, slack)
            )
        });
    }
    // The grammar reads a `repeat`'s body as the commands after it, so its
    // bodies nest as deep as the line is long.
    for (what, open, close) in [
        (
            "repeat 2 { … (nested to the length)",
            "repeat 2 { rm -rf b > o; cd x; ",
            "}; ",
        ),
        (
            "repeat 2 do … (nested to the length)",
            "repeat 2 do rm -rf b > o; cd x; ",
            "done; ",
        ),
        // Inside a loop the grammar reads, whose `done` it pairs with the
        // innermost `do`.
        (
            "for … do repeat 2 { … (nested to the length)",
            "for i in 1; do repeat 2 { rm -rf b > o; cd x; ",
            "}; done; ",
        ),
        (
            "for … do repeat 2 do … (nested to the length)",
            "for i in 1; do repeat 2 do rm -rf b > o; cd x; ",
            "done; done; ",
        ),
    ] {
        assert_linear(what, shell, &paths, |size| {
            let deep = size / (open.len() + close.len());
            format!("{}{}", open.repeat(deep), close.repeat(deep))
        });
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn machine_settings_given_many_patterns_names_or_options_are_read_in_linear_time() {
    let _serial = serial();
    // Each unit pattern is tested against the units that protect the
    // machine and the ones it needs, each name copied into a folder against
    // the files SELinux reads (the folder placed once), each service folder
    // named as `.` placed where it lands, and each option of a settings
    // program read once: a line at the length limit of them is read in time
    // that grows with its length. Each row is the shell, the part repeated,
    // the head and the tail.
    let rows = [
        (
            Shell::Posix,
            ("'*a*b*c*d*e*f*g*h*i*j*k*l*m*n*o*p' ", "systemctl stop ", ""),
        ),
        (Shell::Posix, ("'[a-z]?*[0-9]' ", "systemctl edit ", "")),
        (Shell::Posix, ("? ", "systemctl stop ", "")),
        (Shell::Posix, ("d*@x* ", "sv down ", "")),
        (Shell::Posix, ("conf* ", "cp ", " /etc/selinux/")),
        (Shell::Posix, ("s* ", "cp -r ", " /etc/")),
        (Shell::Posix, ("$x ", "auditctl -k ", "")),
        (Shell::Posix, ("-v ", "efibootmgr ", "")),
        (Shell::Posix, ("-nv ", "iptables ", "")),
        (Shell::Posix, ("a=b ", "sysctl ", "")),
        (Shell::Posix, ("x ", "semanage fcontext ", "")),
        (Shell::Posix, ("--info ALL ", "grubby ", "")),
        (Shell::PowerShell, ("x ", "service ", " stop")),
        (Shell::Posix, ("$x ", "service ", " sshd onedisable")),
        (Shell::Posix, ("-j x ", "service ", " sshd stop")),
        (Shell::Posix, (". ", "cd /etc/service/sshd && sv down ", "")),
        (
            Shell::Posix,
            (". ", "cd /run/service/sshd && s6-svc -d ", ""),
        ),
        (Shell::Posix, ("'d*@x*' ", "rcctl stop ", "")),
        (Shell::Posix, ("x_enable=YES ", "sysrc ", "")),
        (Shell::Posix, ("-wd ", "s6-svc ", " /run/service/x")),
        (Shell::Posix, ("d*@x* ", "s6-rc -d change ", "")),
        (Shell::Posix, ("--force ", "dinitctl ", " stop x")),
        (Shell::Posix, ("-v ", "insserv ", " x")),
        (Shell::Posix, ("start 20 2 . ", "update-rc.d x ", "")),
        (Shell::Posix, ("'d*@x*' ", "brew services stop ", "")),
        (Shell::Posix, ("-a ", "nsenter ", " true")),
    ];
    for (shell, (part, head, tail)) in rows {
        assert_linear(
            &format!("{head}{part}…{tail} in {shell:?}"),
            shell,
            &paths_for(shell),
            |size| {
                format!(
                    "{head}{}{tail}",
                    filled(part, size, head.len() + tail.len())
                )
            },
        );
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn writers_given_many_files_commands_or_libraries_are_read_in_linear_time() {
    let _serial = serial();
    // Each file, ex command, option and library is read once: ex commands
    // joined by bars, a `:g` that runs many, a long pattern, many `-c`
    // options, awk's `@include`s and operands, and certutil's operands.
    let (shell, paths) = (Shell::Posix, posix());
    for (head, part, tail) in [
        ("ex -sc '", "s/a/b/|", "wq' a"),
        ("ex -sc 'g/x/", "d|", "' a"),
        ("ex -sc '%s/", "\\/a", "/b/|wq' a"),
        ("vim -es ", "-c wq ", "a"),
        ("vim -es ", "a b ", ""),
        ("awk '", "@include \"inplace\" ", "1' a"),
        ("awk -i inplace 1 ", "a x=1 ", ""),
        ("sort a | sponge ", "a ", ""),
        ("certutil -decode a ", "b ", ""),
    ] {
        assert_linear(&format!("{head}{part}…"), shell, &paths, |size| {
            format!(
                "{head}{}{tail}",
                filled(part, size, head.len() + tail.len())
            )
        });
    }
}
