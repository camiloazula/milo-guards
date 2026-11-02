//! The rules about stopping processes by name: `killall`, `pkill`,
//! `taskkill` and `Stop-Process` are judged one way. A plain name is the
//! agent's own business (stopping a dev server is everyday work); a pattern
//! that matches every process, every process of a user, or a process the
//! system needs, stops the system.

use std::rc::Rc;

use super::regex;
use super::Checker;
use crate::powershell::{Param, Params};
use crate::unit::{Arg, Between, Unit};
use crate::{Rule, Shell};

/// A `Get-Process` that starts a pipeline: its arguments, and what each
/// later stage (the first of them at `between[0]`) does to the processes.
pub(super) struct Pipeline {
    args: Vec<Arg>,
    between: Vec<Between>,
}

/// How a program reads the name it is given.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Names {
    /// As written: `killall node`.
    Literal,
    /// As a regular expression, searched for in each name: `pkill node`.
    /// `exact` is `pkill -x`, which wants the whole name to match;
    /// `ignore_case` is `pkill -i` and `killall -I`; `full` is `pkill -f`,
    /// which searches the whole command line, not only the name.
    /// `dotnet` is PowerShell's `-match`, a .NET expression, where a `/` is
    /// a plain character and not the end of a folder.
    Regex {
        exact: bool,
        ignore_case: bool,
        full: bool,
        dotnet: bool,
    },
    /// With the wildcards `*`, `?` and `[a-z]`: `Stop-Process -Name node*`,
    /// `taskkill /IM node*`.
    Wildcard,
}

/// Processes the system needs, as they are named without `.exe`: stopping
/// one logs you out, locks you out of a remote machine, freezes the screen
/// or takes the machine down.
const SYSTEM_PROCESSES: [&str; 26] = [
    "launchd",
    "systemd",
    "init",
    "kernel_task",
    "kthreadd",
    "WindowServer",
    "loginwindow",
    "explorer",
    "csrss",
    "winlogon",
    "wininit",
    "lsass",
    "smss",
    "services",
    "svchost",
    // The remote login, the macOS preferences and menu bar, the Linux
    // display server, desktops and login session, and the Windows
    // compositor.
    "sshd",
    "cfprefsd",
    "SystemUIServer",
    "Xorg",
    "gnome-shell",
    "plasmashell",
    "kwin_x11",
    "kwin_wayland",
    "dbus-daemon",
    "systemd-logind",
    "dwm",
];

/// The command lines the system processes usually start with: the program
/// and the arguments they are started with, where there are any (launchd's
/// job for `loginwindow` runs it as `loginwindow console` and the one for
/// `WindowServer` as `WindowServer -daemon`); a match that goes on past the
/// end is read as more arguments, which are not known. `pkill -f` searches
/// these as a whole, so a pattern that is part of one (`/System/Library`,
/// `console`, `-daemon`) stops the process.
const SYSTEM_COMMAND_LINES: [&str; 17] = [
    "/sbin/launchd",
    "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow console",
    "/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer -daemon",
    "/sbin/init",
    "/lib/systemd/systemd",
    "/usr/lib/systemd/systemd",
    "/usr/sbin/sshd",
    "/usr/sbin/cfprefsd daemon",
    "/System/Library/CoreServices/SystemUIServer.app/Contents/MacOS/SystemUIServer",
    "/usr/lib/xorg/Xorg",
    "/usr/bin/gnome-shell",
    "/usr/bin/plasmashell",
    "/usr/bin/kwin_x11",
    "/usr/bin/kwin_wayland",
    "/usr/bin/dbus-daemon",
    "/lib/systemd/systemd-logind",
    "/usr/lib/systemd/systemd-logind",
];

/// `Stop-Process`'s own parameters.
const STOP_PROCESS: [Param; 7] = [
    Param::value("name", &["processname"]),
    Param::value("id", &[]),
    Param::value("inputobject", &[]),
    Param::switch("passthru", &[]),
    Param::switch("force", &[]),
    Param::switch("whatif", &["wi"]),
    Param::switch("confirm", &["cf"]),
];

/// `Get-Process`'s own parameters.
const GET_PROCESS: [Param; 7] = [
    Param::value("name", &["processname"]),
    Param::value("id", &["pid"]),
    Param::value("inputobject", &[]),
    Param::value("computername", &["cn"]),
    Param::switch("module", &[]),
    Param::switch("fileversioninfo", &[]),
    Param::switch("includeusername", &[]),
];

impl Checker<'_> {
    /// `killall`: names as written, or regular expressions with `-r`.
    pub(super) fn killall(&mut self, args: &[Arg]) {
        // psmisc's `killall` also takes its long options with one dash
        // (`-user me`, `-ignore-case`, `-context x`), which the BSD one
        // reads as letters, so a line is read both ways and the riskier
        // counts.
        let letters = Options::read(args, "suyoZctn", &KILLALL_LONGS, false);
        let words = Options::read(args, "suyoZctn", &KILLALL_LONGS, true);
        self.killall_options(&letters);
        if words != letters {
            self.killall_options(&words);
        }
    }

    fn killall_options(&mut self, options: &Options<'_>) {
        let kind = if options.has("r") || options.has("m") || options.has("regexp") {
            Names::Regex {
                exact: false,
                ignore_case: options.has("I") || options.has("ignore-case"),
                full: false,
                dotnet: false,
            }
        } else {
            Names::Literal
        };
        // `-c name` is a name too, judged as the operands are.
        let mut names = options.operands.clone();
        names.extend(options.values("c"));
        let picks = if ["u", "user"].iter().any(|name| options.has_value(name)) {
            Some("stops every process of a user")
        } else if options.has_value("t") {
            Some("stops every process on a terminal")
        } else if ["Z", "context"].iter().any(|name| options.has_value(name)) {
            // `-Z` makes the names optional and stops every process whose
            // security context matches, as `-u` does for a user.
            Some("stops every process a filter picks")
        } else {
            None
        };
        self.stop_all(&names, kind, picks);
    }

    /// `pkill`: regular expressions, searched for in each name.
    pub(super) fn pkill(&mut self, args: &[Arg]) {
        let options = Options::read(args, "uUGgPstFjMNqrO", &PKILL_LONGS, false);
        if options.has("v") || options.has("inverse") {
            // Everything but what matches: what a pattern or a selection
            // (`-P 1234`, `-F pids.txt`, `-t tty`) names is the only thing
            // left running, and with neither the program is an error.
            self.add(
                Rule::StopSystem,
                "stops every process but the ones it names",
                options.operands.first().copied(),
            );
            return;
        }
        let kind = Names::Regex {
            exact: options.has("x") || options.has("exact"),
            ignore_case: options.has("i") || options.has("ignore-case"),
            full: options.has("f") || options.has("full"),
            dotnet: false,
        };
        let user = ["u", "U", "G", "euid", "uid", "group"]
            .iter()
            .any(|name| options.has_value(name));
        // Given no pattern, a selection stops everything it picks: a user's
        // processes, the children of `init`, every process older than a
        // second, a terminal's.
        let picks = if user {
            Some("stops every process of a user")
        } else if picks_without_pattern(&options) {
            Some("stops every process a filter picks")
        } else {
            None
        };
        self.stop_all(&options.operands, kind, picks);
    }

    /// The names a stop is given, or what a selection stops when it is given
    /// no name (`picks` says what it picks).
    fn stop_all(&mut self, names: &[&Arg], kind: Names, picks: Option<&str>) {
        if names.is_empty() {
            if let Some(reason) = picks {
                self.add(Rule::StopSystem, reason, None);
            }
            return;
        }
        for name in names {
            self.stop_named(name, kind);
        }
    }

    /// One name or pattern a stop is given.
    fn stop_named(&mut self, name: &Arg, kind: Names) {
        let Some(text) = name.known() else {
            self.add(
                Rule::StopSystem,
                "stops processes named only when it runs",
                Some(name),
            );
            return;
        };
        let everything = match kind {
            Names::Literal => false,
            Names::Regex { .. } => !regex::needs_literal(text),
            Names::Wildcard => !wildcard_needs_literal(&process_name(text)),
        };
        if everything {
            self.add(Rule::StopSystem, "stops every process", Some(name));
        } else if names_system_process(text, kind) {
            self.add(
                Rule::StopSystem,
                "stops a process the system needs",
                Some(name),
            );
        }
    }

    /// `taskkill /IM name`, `/FI "IMAGENAME eq name"`, `/FI "USERNAME eq me"`.
    pub(super) fn taskkill(&mut self, args: &[Arg]) {
        let mut iter = args.iter();
        let mut named = false;
        let mut filters = Vec::new();
        while let Some(arg) = iter.next() {
            let Some(text) = arg.known() else { continue };
            match text.to_ascii_lowercase().as_str() {
                "/im" | "-im" => {
                    if let Some(name) = iter.next() {
                        named = true;
                        self.stop_named(name, Names::Wildcard);
                    }
                }
                // Stopping by id: the processes are named, and the id is
                // judged (see `stop_id`).
                "/pid" | "-pid" => {
                    named = true;
                    if let Some(id) = iter.next() {
                        self.stop_id(id);
                    }
                }
                "/fi" | "-fi" => filters.extend(iter.next()),
                _ => {}
            }
        }
        // A filter on the image name names the process; any other filter
        // narrows what it names.
        let named = named
            || filters.iter().any(|filter| {
                let mut words = filter.known().unwrap_or_default().split_whitespace();
                let field = words.next().map(str::to_ascii_lowercase);
                let operator = words.next().map(str::to_ascii_lowercase);
                matches!(
                    (field.as_deref(), operator.as_deref()),
                    (Some("imagename" | "pid"), Some("eq"))
                )
            });
        for filter in filters {
            let Some(text) = filter.known() else {
                if !named {
                    self.add(
                        Rule::StopSystem,
                        "stops processes picked by a filter only known when it runs",
                        Some(filter),
                    );
                }
                continue;
            };
            let words: Vec<&str> = text.split_whitespace().collect();
            let field = words.first().map(|word| word.to_ascii_lowercase());
            let operator = words.get(1).map(|word| word.to_ascii_lowercase());
            let value = words
                .get(2..)
                .map(|rest| rest.join(" "))
                .unwrap_or_default();
            match (field.as_deref(), operator.as_deref()) {
                (Some("imagename"), Some("eq")) => {
                    self.stop_named(&Arg::Known(value), Names::Wildcard);
                }
                // `PID eq 1234` names one process, judged as `/PID 1234` is.
                (Some("pid"), Some("eq")) => self.stop_id(&Arg::Known(value)),
                (Some("imagename"), Some(_)) => {
                    self.add(
                        Rule::StopSystem,
                        "stops every process but the ones it names",
                        Some(filter),
                    );
                }
                (Some("username"), Some(_)) if !named => {
                    self.add(
                        Rule::StopSystem,
                        "stops every process of a user",
                        Some(filter),
                    );
                }
                // The programs that hang: what `taskkill` is everyday for.
                (Some("status"), Some("eq")) if value.eq_ignore_ascii_case("not responding") => {}
                // Without a name or an id, whatever the filter picks is
                // stopped; with one, a filter only narrows what is named.
                _ if !named => {
                    self.add(
                        Rule::StopSystem,
                        "stops every process a filter picks",
                        Some(filter),
                    );
                }
                _ => {}
            }
        }
    }

    /// `tskill name`, `tskill 1234 /a`: the Terminal Services program that
    /// ends a process by its name or its id, judged as `taskkill /IM` and
    /// `taskkill /PID` are. Its options (`/a`, `/v`, `/server:name`,
    /// `/id:n`) start with a slash and name no process.
    pub(super) fn tskill(&mut self, args: &[Arg], shell: Shell) {
        for arg in args {
            match arg.known() {
                Some(text) if text.starts_with('/') => {}
                // In PowerShell a word that holds a variable is not the text
                // written, whatever the walker could read of it.
                Some(text) if expands(text, shell) => self.stop_id(&Arg::Unknown(text.to_string())),
                // A number is an id and any other word a name.
                Some(text) if !text.is_empty() && !text.bytes().all(|b| b.is_ascii_digit()) => {
                    self.stop_named(arg, Names::Wildcard);
                }
                _ => self.stop_id(arg),
            }
        }
    }

    /// `Stop-Process -Name name`, and the processes a `Get-Process` listing
    /// hands it, which it stops (every process when the listing names none).
    pub(super) fn stop_process(&mut self, unit: &Unit) {
        let params = Params::cmdlet(&unit.args, &STOP_PROCESS);
        let names = params.values(&["name"]);
        if !names.is_empty() {
            // `-Name a,b` gives the second name as a positional argument.
            let rest = params
                .positional
                .iter()
                .filter(|arg| arg.known().is_none_or(|text| text.parse::<u64>().is_err()));
            for name in names.into_iter().chain(rest.copied()) {
                self.stop_named(name, Names::Wildcard);
            }
            return;
        }
        if params.has(&["id", "inputobject"]) || !params.positional.is_empty() {
            // Picked by id or by object: judged by what they hold, a
            // listing written in the argument or `$_` in a block that is a
            // stage after one. After a `Get-Process`, a value built on `$_`
            // that is not the item or one of the process's own members
            // (`$_.Parent`, `($_.Parent)`, `$_ + 1`) is another process, only
            // known when it runs; after anything else `$_` is not a process.
            let listed = unit
                .stage
                .is_some_and(|stage| stage.index > 0 && self.pipeline(stage.pipeline).is_some());
            if unit.unread_item && listed {
                self.add(
                    Rule::StopSystem,
                    "stops processes only known when it runs",
                    None,
                );
            }
            for listing in &unit.listings {
                self.judge_listing(&listing.args, &listing.between);
            }
            // What is left is a process picked by an id, and it is judged
            // as `taskkill /PID` is: an id written out is a process the
            // agent picked, and any other value may be any process.
            let values: Vec<&Arg> = params
                .values(&["id", "inputobject"])
                .into_iter()
                .chain(params.positional.iter().copied())
                .collect();
            for value in &values {
                if **value != Arg::Input && !is_listed(unit, value) {
                    self.stop_id(value);
                }
            }
            if values.iter().any(|arg| **arg == Arg::Input) {
                let judged = unit
                    .stage
                    .filter(|stage| stage.index > 0)
                    .is_some_and(|stage| self.judge_before(stage));
                // The item of a block that does not follow a `Get-Process`
                // is not a process the guard can name.
                if !judged {
                    self.add(
                        Rule::StopSystem,
                        "stops processes only known when it runs",
                        None,
                    );
                }
            }
            return;
        }
        let Some(stage) = unit.stage.filter(|stage| stage.index > 0) else {
            return;
        };
        if !self.judge_before(stage) {
            self.add(
                Rule::StopSystem,
                "stops processes only known when it runs",
                None,
            );
        }
    }

    /// `wmic process where name="node.exe" call terminate` and
    /// `wmic process where processid=1234 delete`: they stop the processes
    /// the `where` clause picks, judged as `taskkill` judges a name and an
    /// id. A clause that is not one of those two comparisons (a `like`, a
    /// second condition), or none at all, picks processes only known when it
    /// runs, and none is every process.
    pub(super) fn wmic_process(&mut self, args: &[Arg], shell: Shell) {
        let word = |arg: &Arg| arg.text().to_ascii_lowercase();
        if !args
            .iter()
            .any(|arg| matches!(word(arg).as_str(), "terminate" | "delete"))
        {
            return;
        }
        let Some(at) = args.iter().position(|arg| word(arg) == "where") else {
            self.add(Rule::StopSystem, "stops every process", None);
            return;
        };
        let clause: Vec<&Arg> = args[at + 1..]
            .iter()
            .take_while(|arg| !matches!(word(arg).as_str(), "call" | "delete"))
            .collect();
        let unread = |this: &mut Self| {
            this.add(
                Rule::StopSystem,
                "stops processes picked by a filter only known when it runs",
                clause.first().copied(),
            );
        };
        // A bareword of PowerShell that holds a variable (`name=$n`) is
        // handed over as the text written, but is another text when it runs.
        if clause
            .iter()
            .any(|arg| arg.known().is_none_or(|text| expands(text, shell)))
        {
            unread(self);
            return;
        }
        let text: String = clause.iter().filter_map(|arg| arg.known()).collect();
        let text = text.replace(['"', '\''], "");
        match text.split_once('=') {
            Some((field, value))
                if !value.is_empty()
                    && !value.contains(['=', '%', '*', '?', ' '])
                    && field.eq_ignore_ascii_case("name") =>
            {
                self.stop_named(&Arg::Known(value.to_string()), Names::Wildcard);
            }
            Some((field, value))
                if !value.is_empty() && field.eq_ignore_ascii_case("processid") =>
            {
                self.stop_id(&Arg::Known(value.to_string()));
            }
            _ => unread(self),
        }
    }

    /// `Invoke-CimMethod -MethodName Terminate` and `Invoke-WmiMethod -Name
    /// Terminate` stop the processes their instances are, which come from a
    /// listing the guard does not follow.
    pub(super) fn wmi_method(&mut self, args: &[Arg]) {
        if let Some(method) = args.iter().find(|arg| {
            arg.known()
                .is_some_and(|text| text.eq_ignore_ascii_case("terminate"))
        }) {
            self.add(
                Rule::StopSystem,
                "stops processes through a WMI method, picked only when it runs",
                Some(method),
            );
        }
    }

    /// One process id a stop is given (`Stop-Process -Id`, `taskkill /PID`).
    /// An id written out in digits is a process the agent picked, unless it
    /// is one `kill` already refuses to take lightly: 0 is the caller's own
    /// process group (where PowerShell runs on Linux and macOS, as `kill 0`)
    /// and 1 the first process of the system. `$PID` is the shell that runs
    /// the line. Any other value (a variable, a substitution, a file's text,
    /// another cmdlet's listing, a word that is not a number) is only known
    /// when it runs and may be any process, those included.
    fn stop_id(&mut self, id: &Arg) {
        let read = match id {
            Arg::Known(text) => {
                let digits = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
                match text.parse::<u64>() {
                    Ok(0) if digits => {
                        self.add(
                            Rule::StopSystem,
                            "stops every process in its own group",
                            Some(id),
                        );
                        return;
                    }
                    Ok(1) if digits => {
                        self.add(
                            Rule::StopSystem,
                            "stops the system's first process",
                            Some(id),
                        );
                        return;
                    }
                    Ok(_) => digits,
                    Err(_) => false,
                }
            }
            Arg::Unknown(text) => matches!(text.to_ascii_lowercase().as_str(), "$pid" | "${pid}"),
            Arg::Template { .. } | Arg::Input | Arg::Null => false,
        };
        if !read {
            self.add(
                Rule::StopSystem,
                "stops processes only known when it runs",
                Some(id),
            );
        }
    }

    /// Judge the `Get-Process` that starts the pipeline a stage is in, with
    /// what stands between it and the stage. False when the pipeline does
    /// not start with one.
    fn judge_before(&mut self, stage: crate::unit::Stage) -> bool {
        let Some(pipeline) = self.pipeline(stage.pipeline) else {
            return false;
        };
        let before = stage.index.saturating_sub(1).min(pipeline.between.len());
        self.judge_listing(&pipeline.args, &pipeline.between[..before]);
        true
    }

    /// The `Get-Process` that starts a pipeline, when one does, and what
    /// each later stage does to what it lists. Worked out once for the whole
    /// pipeline, so a long one is read in linear time.
    fn pipeline(&mut self, id: usize) -> Option<Rc<Pipeline>> {
        if let Some(known) = self.pipelines.get(&id) {
            return known.clone();
        }
        let at = |index: usize| {
            self.producers
                .get(&(id, index))
                .and_then(|&at| self.split.units.get(at))
        };
        let stages = self.lengths.get(&id).copied().unwrap_or(0);
        let pipeline = at(0)
            .filter(|first| first.key().as_deref() == Some("get-process"))
            .map(|first| {
                Rc::new(Pipeline {
                    args: first.args.clone(),
                    between: (1..stages)
                        .map(|index| at(index).map_or(Between::Other, between))
                        .collect(),
                })
            });
        self.pipelines.insert(id, pipeline.clone());
        pipeline
    }

    /// Judge what `Get-Process` lists, narrowed by the stages after it, as
    /// a `Stop-Process` stops it.
    fn judge_listing(&mut self, listing: &[Arg], between: &[Between]) {
        // A stage that may hand on processes the listing did not.
        if between.iter().any(|stage| matches!(stage, Between::Other)) {
            self.add(
                Rule::StopSystem,
                "stops processes only known when it runs",
                None,
            );
            return;
        }
        let params = Params::cmdlet(listing, &GET_PROCESS);
        let by_id = params.has(&["id", "inputobject"]);
        let mut names = params.values(&["name"]);
        // After `-Id`, the words of a list (`-Id 1234, 5678`) are ids.
        if !by_id {
            names.extend(params.positional.iter().copied());
        }
        // Named by the listing: what follows can only narrow it.
        if !names.is_empty() {
            for name in names {
                self.stop_named(name, Names::Wildcard);
            }
            return;
        }
        // Picked by id or by object: the values are judged as `Stop-Process`
        // judges them.
        if by_id {
            for value in params
                .values(&["id", "inputobject"])
                .into_iter()
                .chain(params.positional.iter().copied())
            {
                self.stop_id(value);
            }
            return;
        }
        if between.is_empty() {
            self.add(Rule::StopSystem, "stops every process", None);
            return;
        }
        // Every process, narrowed: by a name that a filter spells out, or by
        // one the guard cannot read.
        let mut read = false;
        for stage in between {
            if let Between::Where(args) = stage {
                if let Some((name, kind)) = filter_name(args) {
                    read = true;
                    self.stop_named(name, kind);
                }
            }
        }
        if !read {
            self.add(
                Rule::StopSystem,
                "stops processes picked by a filter only known when it runs",
                None,
            );
        }
    }
}

/// Whether a word is, in PowerShell, text with a variable or an escape in it
/// (`name=$n`, `name=$env:P`, a backtick): a bareword the walker reads as
/// written, whose value is only known when it runs. cmd and POSIX shells read
/// a `$` as it is written.
fn expands(text: &str, shell: Shell) -> bool {
    shell == Shell::PowerShell && text.contains(['$', '`'])
}

/// Whether an argument of a `Stop-Process` holds a `Get-Process` listing,
/// which the listing rules judge.
fn is_listed(unit: &Unit, arg: &Arg) -> bool {
    unit.args
        .iter()
        .position(|candidate| std::ptr::eq(candidate, arg))
        .and_then(|at| unit.listed.get(at))
        .copied()
        .unwrap_or(false)
}

/// What a stage between a listing and a stop does to the processes.
fn between(unit: &Unit) -> Between {
    match unit.key().as_deref() {
        Some("where-object") => Between::Where(unit.args.clone()),
        Some("select-object" | "select") => Between::select(&unit.args),
        Some("sort-object" | "sort") => Between::Narrows,
        _ => Between::Other,
    }
}

/// The name a `Where-Object` stage picks processes by, and how it reads it,
/// when it is only a comparison of `Name` or `ProcessName` with `-eq`,
/// `-like` or `-match`: `Where-Object Name -eq node`, `-Property ProcessName
/// -Like -Value 'node*'` (a block of the same is read into this form by the
/// splitter). A name `-match` is given is a pattern searched for in each name,
/// as `pkill` reads it, so `-match 'node'` is read as `-like '*node*'`.
fn filter_name(args: &[Arg]) -> Option<(&Arg, Names)> {
    let mut property = None;
    let mut value = None;
    let mut positional = Vec::new();
    let mut compares = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(name) = arg
            .known()
            .and_then(|text| text.strip_prefix('-'))
            .filter(|name| name.starts_with(|c: char| c.is_ascii_alphabetic()))
        else {
            positional.push(arg);
            continue;
        };
        let name = name.trim_end_matches(':').to_ascii_lowercase();
        let abbreviates = |full: &str| name.len() >= 3 && full.starts_with(name.as_str());
        match name.as_str() {
            "eq" | "ieq" | "ceq" | "like" | "ilike" | "clike" => {
                if compares
                    .replace(Names::Wildcard)
                    .is_some_and(|kind| kind != Names::Wildcard)
                {
                    return None;
                }
            }
            // The riskier reading of the case: `-cmatch` too is searched as
            // if it ignored it.
            "match" | "imatch" | "cmatch" => {
                let regex = Names::Regex {
                    exact: false,
                    ignore_case: true,
                    full: false,
                    dotnet: true,
                };
                if compares.replace(regex).is_some_and(|kind| kind != regex) {
                    return None;
                }
            }
            _ if abbreviates("property") => property = iter.next(),
            _ if abbreviates("value") => value = iter.next(),
            _ if abbreviates("filterscript") => {}
            _ => return None,
        }
    }
    let mut positional = positional.into_iter();
    let property = property.or_else(|| positional.next())?;
    let value = value.or_else(|| positional.next())?;
    let property = property.known()?.to_ascii_lowercase();
    let kind = compares?;
    // A `-match` pattern is a .NET expression, read here only in the POSIX
    // subset: one that uses more is not read (a lookaround, an option, `\x6f`,
    // `\p{L}`, `\k<n>`), and the filter is any other.
    let dotnet =
        matches!(kind, Names::Regex { .. }) && value.known().is_some_and(regex::dotnet_only);
    (positional.next().is_none()
        && !dotnet
        && matches!(property.as_str(), "name" | "processname")
        && value.known().is_some())
    .then_some((value, kind))
}

/// killall's options with a long form.
const KILLALL_LONGS: [Long; 15] = [
    Long::value("signal"),
    Long::value("user"),
    Long::value("younger-than"),
    Long::value("older-than"),
    Long::value("context"),
    Long::value("ns"),
    Long::flag("regexp"),
    Long::flag("exact"),
    Long::flag("ignore-case"),
    Long::flag("interactive"),
    Long::flag("list"),
    Long::flag("process-group"),
    Long::flag("quiet"),
    Long::flag("verbose"),
    Long::flag("wait"),
];

/// pkill's options with a long form.
const PKILL_LONGS: [Long; 23] = [
    Long::value("signal"),
    Long::value("euid"),
    Long::value("uid"),
    Long::value("group"),
    Long::value("pgroup"),
    Long::value("parent"),
    Long::value("session"),
    Long::value("terminal"),
    Long::value("pidfile"),
    Long::value("ns"),
    Long::value("nslist"),
    Long::value("cgroup"),
    Long::value("env"),
    Long::value("older"),
    Long::value("runstates"),
    Long::value("queue"),
    Long::flag("inverse"),
    Long::flag("exact"),
    Long::flag("full"),
    Long::flag("newest"),
    Long::flag("oldest"),
    Long::flag("ignore-case"),
    Long::flag("ignore-ancestors"),
];

/// The long options `name` is, written in full or as a prefix that fits.
/// A prefix that fits several is an error to the program; it is read as all
/// of them, so that the riskier reading counts.
fn matching<'l>(name: &str, longs: &'l [Long]) -> Vec<&'l Long> {
    match longs.iter().find(|full| full.name == name) {
        Some(full) => vec![full],
        None if name.is_empty() => Vec::new(),
        None => longs
            .iter()
            .filter(|full| full.name.starts_with(name))
            .collect(),
    }
}

/// A long option, and whether it takes a value.
struct Long {
    name: &'static str,
    value: bool,
}

impl Long {
    const fn value(name: &'static str) -> Self {
        Self { name, value: true }
    }

    const fn flag(name: &'static str) -> Self {
        Self { name, value: false }
    }
}

/// The options and operands of `killall` or `pkill`, read as they read
/// them: bundled letters, `-u me` or `-ume`, `--user me` or `--user=me`,
/// a signal (`-9`, `-HUP`), and long options that may be abbreviated.
#[derive(PartialEq)]
struct Options<'a> {
    operands: Vec<&'a Arg>,
    /// Every option given, by its short letter or full long name, and the
    /// value it was given, if any.
    given: Vec<(String, Option<Arg>)>,
}

impl<'a> Options<'a> {
    /// With `long_only`, a word with one dash that fits a long option is
    /// that option (`killall -user me`), and letters otherwise.
    fn read(args: &'a [Arg], short_values: &str, longs: &[Long], long_only: bool) -> Self {
        let mut options = Self {
            operands: Vec::new(),
            given: Vec::new(),
        };
        let mut iter = args.iter();
        let mut reading = true;
        while let Some(arg) = iter.next() {
            let Some(text) = arg.known().filter(|_| reading) else {
                options.operand(arg, iter.as_slice());
                continue;
            };
            if text == "--" {
                reading = false;
            } else if let Some(long) = text.strip_prefix("--") {
                options.long(long, longs, &mut iter);
            } else if text.len() > 1 && text.starts_with('-') {
                // With one dash, the word is a long option when it fits one
                // (and is not a signal) and letters otherwise, as
                // `getopt_long_only` reads it.
                let word = &text[1..];
                let fits = word.chars().count() > 1
                    && !is_signal(word)
                    && !matching(word.split_once('=').map_or(word, |(name, _)| name), longs)
                        .is_empty();
                if long_only && fits {
                    options.long(word, longs, &mut iter);
                } else {
                    options.bundle(word, short_values, &mut iter);
                }
            } else {
                options.operand(arg, iter.as_slice());
            }
        }
        options
    }

    /// A long option, written after `--` (or after one `-`, when it fits
    /// one). `getopt_long` takes the name as written, or else any prefix
    /// that fits a long option; a prefix that fits several is read as all of
    /// them (see [`matching`]).
    fn long(&mut self, long: &str, longs: &[Long], iter: &mut std::slice::Iter<'a, Arg>) {
        let name = long.split_once('=').map_or(long, |(name, _)| name);
        let found = matching(name, longs);
        if found.is_empty() {
            self.given.push((name.to_string(), None));
            return;
        }
        let value = if found.iter().any(|full| full.value) {
            match long.split_once('=') {
                Some((_, value)) => Some(Arg::Known(value.to_string())),
                None => iter.next().cloned(),
            }
        } else {
            None
        };
        for full in found {
            let value = value.clone().filter(|_| full.value);
            self.given.push((full.name.to_string(), value));
        }
    }

    /// The first operand, and every word after it: macOS and BSD `killall`
    /// and `pkill` stop reading options at the first name, so each later
    /// word (a `-u` and its user included) is a name there, while GNU
    /// `pkill` reads on and takes them as options. The words are options
    /// here too, so that both readings are judged and the riskier counts.
    fn operand(&mut self, arg: &'a Arg, rest: &'a [Arg]) {
        if self.operands.is_empty() {
            self.operands.push(arg);
            self.operands.extend(rest);
        }
    }

    /// The letters after one `-`.
    fn bundle(&mut self, letters: &str, short_values: &str, iter: &mut std::slice::Iter<'a, Arg>) {
        // A signal, not letters: `-9`, `-KILL`, `-SIGHUP`, `-USR1`. A bundle
        // of capitals and digits that is not one is letters: `-P1` is
        // `-P 1`, `-U0` is `-U 0`.
        if is_signal(letters) {
            return;
        }
        for (at, letter) in letters.char_indices() {
            if short_values.contains(letter) {
                let rest = &letters[at + letter.len_utf8()..];
                let value = if rest.is_empty() {
                    iter.next().cloned()
                } else {
                    Some(Arg::Known(rest.to_string()))
                };
                self.given.push((letter.to_string(), value));
                return;
            }
            self.given.push((letter.to_string(), None));
        }
    }

    fn has(&self, name: &str) -> bool {
        self.given.iter().any(|(given, _)| given == name)
    }

    /// Whether an option was given a value.
    fn has_value(&self, name: &str) -> bool {
        self.given
            .iter()
            .any(|(given, value)| given == name && value.is_some())
    }

    /// The values an option was given, each time it was.
    fn values(&self, name: &str) -> Vec<&Arg> {
        self.given
            .iter()
            .filter(|(given, _)| given == name)
            .filter_map(|(_, value)| value.as_ref())
            .collect()
    }
}

/// The signals a program is given by name, without `SIG`.
const SIGNALS: &[&str] = &[
    "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "IOT", "EMT", "FPE", "KILL", "BUS", "SEGV", "SYS",
    "PIPE", "ALRM", "TERM", "URG", "STOP", "TSTP", "CONT", "CHLD", "CLD", "TTIN", "TTOU", "IO",
    "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "INFO", "USR1", "USR2", "POLL", "PWR", "STKFLT",
    "LOST", "UNUSED", "RTMIN", "RTMAX",
];

/// Whether the text after a `-` is a signal: a number, or a name with or
/// without `SIG` (`HUP`, `SIGHUP`, `USR1`, `RTMIN+3`).
fn is_signal(letters: &str) -> bool {
    if letters.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    let name = letters.strip_prefix("SIG").unwrap_or(letters);
    let name = match name.split_once(['+', '-']) {
        Some((base @ ("RTMIN" | "RTMAX"), number))
            if number.chars().all(|c| c.is_ascii_digit()) =>
        {
            base
        }
        _ => name,
    };
    SIGNALS.contains(&name)
}

/// Whether a `pkill` given the selections in `options` and no pattern stops
/// every process they pick: the children of `init` or of nothing (`-P 1`),
/// the processes older than a time, in a state, a control group, a namespace
/// or with a variable, and a terminal's.
fn picks_without_pattern(options: &Options<'_>) -> bool {
    // A parent, session or process group that is `launchd`'s or `init`'s (1),
    // the caller's own (0: `pkill -s 0` is the terminal's processes and the
    // shell that runs this) or only known when it runs. `pkill -P $$`, the
    // children of this shell, is read by its source text.
    let picks = |names: [&str; 2], own_shell_is_known: bool| {
        names.iter().any(|name| {
            options
                .values(name)
                .iter()
                .any(|value| match value.known() {
                    Some(text) => text
                        .split(',')
                        .any(|id| matches!(id.trim().parse::<u64>(), Ok(0 | 1))),
                    None => !(own_shell_is_known && matches!(value.text(), "$$" | "\"$$\"")),
                })
        })
    };
    picks(["P", "parent"], true)
        || picks(["s", "session"], false)
        || picks(["g", "pgroup"], false)
        || [
            "older",
            "O",
            "runstates",
            "r",
            "cgroup",
            "ns",
            "nslist",
            "env",
            "t",
            "terminal",
        ]
        .iter()
        .any(|name| options.has(name))
}

/// The name as a process is known: lower case, without `.exe`.
fn process_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

/// Whether a systemd unit (`systemd-logind`, `systemd-logind.service`) runs
/// a process the system needs. The units `ssh` and `dbus` are named apart
/// from their programs (`sshd`, `dbus-daemon`) on most distributions.
pub(super) fn is_system_unit(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let unit = lower.strip_suffix(".service").unwrap_or(&lower);
    matches!(unit, "ssh" | "dbus") || names_system_process(unit, Names::Literal)
}

/// Whether a launchd label or target (`com.apple.WindowServer`,
/// `system/com.apple.WindowServer`, `gui/501/com.apple.cfprefsd.xpc.agent`)
/// runs a process the system needs: its name is a part of the label.
pub(super) fn is_system_label(target: &str) -> bool {
    let label = target.rsplit('/').next().unwrap_or(target);
    label
        .split('.')
        .any(|part| names_system_process(part, Names::Literal))
}

/// Whether `text` names a process the system needs, or (for a wildcard
/// or a regular expression) matches one.
fn names_system_process(text: &str, kind: Names) -> bool {
    match kind {
        // `killall` picks a process by its file when the name has a folder in
        // it (`/sbin/init`): the last part is the name.
        Names::Literal => {
            let name = text.rsplit('/').next().unwrap_or(text);
            SYSTEM_PROCESSES
                .iter()
                .any(|system| process_name(system) == process_name(name))
        }
        Names::Regex {
            exact,
            ignore_case,
            full,
            dotnet,
        } => {
            // Each alternative of a pattern, without its anchors and
            // brackets, and its folder when it is a command line's program,
            // compared whole (`Explorer`, `explorer.exe`); and the
            // expression itself, which may match the name in part.
            text.split('|').any(|alternative| {
                let bare = alternative.trim_matches(['^', '$', '(', ')']);
                let name = bare.rsplit('/').next().unwrap_or(bare);
                SYSTEM_PROCESSES
                    .iter()
                    .any(|system| process_name(system) == process_name(name))
            }) || regex::matches_any(text, &SYSTEM_PROCESSES, exact, ignore_case, dotnet)
                // `-f` searches the whole command line, whose program is not
                // the last part of a path the pattern spells.
                || (full
                    && regex::matches_command_line(
                        text,
                        &SYSTEM_COMMAND_LINES,
                        exact,
                        ignore_case,
                    ))
        }
        Names::Wildcard => {
            let pieces = wildcard_pieces(&process_name(text));
            SYSTEM_PROCESSES.iter().any(|system| {
                let name: Vec<char> = process_name(system).chars().collect();
                wildcard_matches(&pieces, &name)
            })
        }
    }
}

/// One piece of a wildcard.
#[derive(Clone, Copy)]
enum Piece {
    /// `*`: any run of characters. Runs of them are one.
    Star,
    /// `?`, or a `[…]` set, which counts as any one character (that can only
    /// make a pattern match more).
    One,
    Char(char),
}

/// A wildcard as pieces. A `[` with no `]` after it is a plain character.
fn wildcard_pieces(pattern: &str) -> Vec<Piece> {
    let chars: Vec<char> = pattern.chars().collect();
    // A `[` has a `]` after it only before the last one, so the scan for
    // its close runs only when there is one and the set is skipped.
    let last_close = chars.iter().rposition(|c| *c == ']');
    let mut pieces = Vec::new();
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        at += 1;
        match c {
            '*' => {
                if !matches!(pieces.last(), Some(Piece::Star)) {
                    pieces.push(Piece::Star);
                }
            }
            '?' => pieces.push(Piece::One),
            '[' if last_close.is_some_and(|close| close >= at) => {
                if let Some(close) = chars[at..].iter().position(|c| *c == ']') {
                    at += close + 1;
                }
                pieces.push(Piece::One);
            }
            c => pieces.push(Piece::Char(c)),
        }
    }
    pieces
}

/// Whether the wildcard `pieces` match `name`, in time proportional to
/// their number times the name's length.
fn wildcard_matches(pieces: &[Piece], name: &[char]) -> bool {
    // Every piece but a star takes one character, so a name shorter than
    // that many pieces is not matched; this also keeps the work below to the
    // name's length, however long the wildcard is.
    let needed = pieces
        .iter()
        .filter(|piece| !matches!(piece, Piece::Star))
        .count();
    if needed > name.len() {
        return false;
    }
    // The positions in `pieces` the matching can be at, after the name so
    // far; a star can also match nothing.
    let spread = |at: &mut [bool]| {
        for index in 0..pieces.len() {
            if at[index] && matches!(pieces[index], Piece::Star) {
                at[index + 1] = true;
            }
        }
    };
    let mut at = vec![false; pieces.len() + 1];
    let mut next = vec![false; pieces.len() + 1];
    at[0] = true;
    spread(&mut at);
    for &c in name {
        next.fill(false);
        for (index, piece) in pieces.iter().enumerate() {
            if !at[index] {
                continue;
            }
            match piece {
                Piece::Star => next[index] = true,
                Piece::One => next[index + 1] = true,
                Piece::Char(p) => next[index + 1] |= *p == c,
            }
        }
        spread(&mut next);
        std::mem::swap(&mut at, &mut next);
    }
    at[pieces.len()]
}

/// Whether a wildcard holds a letter or digit outside its `[…]` sets: with
/// none, it matches every name.
fn wildcard_needs_literal(pattern: &str) -> bool {
    let mut in_set = false;
    for c in pattern.chars() {
        match c {
            '[' => in_set = true,
            ']' => in_set = false,
            c if !in_set && c.is_alphanumeric() => return true,
            _ => {}
        }
    }
    false
}
