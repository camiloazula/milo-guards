//! Script blocks a cmdlet runs: one written out where it stands is read by
//! the walk; one that comes from anywhere else (`$b`, `(Get-Block)`,
//! `[scriptblock]::Create($code)`) is code the guard does not read.

use tree_sitter::Node;

use crate::unit::{self, Arg, Split};
use crate::{Rule, Shell};

/// How a cmdlet takes the script block it runs by position.
#[derive(Clone, Copy)]
enum Positional {
    /// One block among the arguments no parameter takes: the others may be
    /// a computer or a name.
    One,
    /// Every argument after the first may be one more block
    /// (`ForEach-Object { begin } { process } { end }`); a plain word is a
    /// member name.
    Every,
    /// Only the first argument no parameter takes can be a block; a plain
    /// word there is another parameter's value (`Where-Object Name -eq x`).
    First,
}

/// A cmdlet that runs a script block it is given.
struct Cmdlet {
    name: &'static str,
    /// The parameters that take a script block; a prefix names one.
    blocks: &'static [&'static str],
    /// The other parameters that take a value, so the value is not
    /// mistaken for a block given by position.
    values: &'static [&'static str],
    positional: Option<Positional>,
    /// The parameters a block can also be given by position, in the order
    /// their positions run, each with the names that bind it (`-Command` is
    /// an alias of `-ScriptBlock`). A positional argument takes the first
    /// of them no name has bound, so `Start-Job -ScriptBlock { … } $init`
    /// hands `$init` to `-InitializationScript`. Empty: the block is the
    /// only one by position.
    slots: &'static [&'static [&'static str]],
    /// Whether one block parameter is all there is to give a block to: a
    /// splat (`@p`) beside a block written out cannot add another.
    lone: bool,
}

/// The cmdlets whose script blocks the guard reads. The ones that register
/// an event action are read with the events (`Register-ObjectEvent` and the
/// like), each for its own parameter order.
const CMDLETS: [Cmdlet; 13] = [
    Cmdlet {
        name: "invoke-command",
        blocks: &["scriptblock", "command"],
        values: &[
            "computername",
            "session",
            "argumentlist",
            "credential",
            "port",
            "configurationname",
            "filepath",
            "throttlelimit",
            "jobname",
            "sessionoption",
            "authentication",
            "inputobject",
            "hostname",
            "username",
            "keyfilepath",
            "vmname",
            "containerid",
            "applicationname",
            "connectionuri",
            "certificatethumbprint",
        ],
        positional: Some(Positional::One),
        slots: &[],
        lone: true,
    },
    Cmdlet {
        name: "foreach-object",
        blocks: &["process", "begin", "end", "parallel", "remainingscripts"],
        values: &[
            "membername",
            "argumentlist",
            "inputobject",
            "throttlelimit",
            "timeoutseconds",
        ],
        positional: Some(Positional::Every),
        slots: &[],
        lone: false,
    },
    Cmdlet {
        name: "start-job",
        blocks: &["scriptblock", "command", "initializationscript"],
        values: &[
            "name",
            "argumentlist",
            "credential",
            "workingdirectory",
            "filepath",
            "inputobject",
            "psversion",
            "authentication",
            "definitionname",
            "definitionpath",
            "type",
            "literalpath",
        ],
        positional: Some(Positional::One),
        slots: &[&["scriptblock", "command"], &["initializationscript"]],
        lone: false,
    },
    Cmdlet {
        name: "start-threadjob",
        blocks: &["scriptblock", "initializationscript"],
        values: &[
            "name",
            "argumentlist",
            "inputobject",
            "throttlelimit",
            "streaminghost",
            "psversion",
        ],
        positional: Some(Positional::One),
        slots: &[&["scriptblock"]],
        lone: false,
    },
    Cmdlet {
        name: "register-scheduledjob",
        blocks: &["scriptblock", "initializationscript"],
        values: &[
            "name",
            "filepath",
            "argumentlist",
            "credential",
            "trigger",
            "scheduledjoboption",
            "maxresultcount",
            "runevery",
        ],
        positional: Some(Positional::One),
        // The name comes first, then the block.
        slots: &[&["name"], &["scriptblock"]],
        lone: false,
    },
    Cmdlet {
        name: "set-psbreakpoint",
        blocks: &["action"],
        values: &[
            "script", "line", "column", "command", "variable", "mode", "runspace",
        ],
        positional: None,
        slots: &[],
        lone: true,
    },
    Cmdlet {
        name: "new-module",
        blocks: &["scriptblock"],
        values: &["name", "function", "cmdlet", "argumentlist"],
        positional: Some(Positional::One),
        slots: &[],
        lone: true,
    },
    Cmdlet {
        name: "measure-command",
        blocks: &["expression"],
        values: &["inputobject"],
        positional: Some(Positional::One),
        slots: &[],
        lone: true,
    },
    // The filter runs on every item: `-FilterScript` is the first parameter
    // by position, and a word there is the `-Property` of the comparison form.
    Cmdlet {
        name: "where-object",
        blocks: &["filterscript"],
        values: &["inputobject", "property", "value"],
        positional: Some(Positional::First),
        slots: &[],
        lone: true,
    },
    // `-Expression` is the second parameter by position, after `-Name`. The
    // `-Command` it can be given instead runs a command by name, which the
    // guard does not read either.
    Cmdlet {
        name: "trace-command",
        blocks: &["expression", "command"],
        values: &[
            "name",
            "argumentlist",
            "filepath",
            "option",
            "listeneroption",
            "inputobject",
        ],
        positional: Some(Positional::One),
        slots: &[&["name"], &["expression", "command"]],
        lone: false,
    },
    // The completer runs whenever the command's arguments are completed.
    Cmdlet {
        name: "register-argumentcompleter",
        blocks: &["scriptblock"],
        values: &["commandname", "parametername"],
        positional: None,
        slots: &[],
        lone: true,
    },
    // The handler runs when its key is pressed; the key comes first by
    // position, then the block.
    Cmdlet {
        name: "set-psreadlinekeyhandler",
        blocks: &["scriptblock"],
        values: &[
            "chord",
            "key",
            "function",
            "briefdescription",
            "description",
            "vimode",
        ],
        positional: Some(Positional::One),
        slots: &[&["chord", "key"], &["scriptblock"]],
        lone: true,
    },
    Cmdlet {
        name: "use-transaction",
        blocks: &["transactedscript"],
        values: &[],
        positional: Some(Positional::One),
        slots: &[],
        lone: true,
    },
];

/// A cmdlet that takes a property it reads from each item, which may be a
/// script block or a table that holds one (a calculated property,
/// `@{n='x';e={ … }}`), and runs it on each item.
struct Properties {
    names: &'static [&'static str],
    /// The parameters that take such a property; a prefix names one.
    properties: &'static [&'static str],
    /// The other parameters that take a value.
    values: &'static [&'static str],
    /// Whether the property is also given by position.
    positional: bool,
}

/// The cmdlets that run a block given as a property.
const PROPERTIES: [Properties; 8] = [
    Properties {
        names: &["sort-object", "sort"],
        properties: &["property"],
        values: &["top", "bottom", "culture", "inputobject"],
        positional: true,
    },
    Properties {
        names: &["group-object", "group"],
        properties: &["property"],
        values: &["culture", "inputobject"],
        positional: true,
    },
    Properties {
        names: &["select-object", "select"],
        properties: &["property"],
        values: &[
            "first",
            "last",
            "skip",
            "skiplast",
            "index",
            "skipindex",
            "excludeproperty",
            "expandproperty",
            "inputobject",
        ],
        positional: true,
    },
    Properties {
        names: &["format-table", "ft"],
        properties: &["property", "groupby"],
        values: &["view", "expand", "inputobject"],
        positional: true,
    },
    Properties {
        names: &["format-list", "fl"],
        properties: &["property", "groupby"],
        values: &["view", "expand", "inputobject"],
        positional: true,
    },
    Properties {
        names: &["format-wide", "fw"],
        properties: &["property", "groupby"],
        values: &["view", "expand", "column", "inputobject"],
        positional: true,
    },
    Properties {
        names: &["format-custom", "fc"],
        properties: &["property", "groupby"],
        values: &["view", "expand", "depth", "inputobject"],
        positional: true,
    },
    Properties {
        names: &["measure-object", "measure"],
        properties: &["property"],
        values: &["inputobject"],
        positional: true,
    },
];

/// The member types `Add-Member` and `Update-TypeData` add that run no
/// script of their own; any other (`ScriptMethod`, `ScriptProperty`, a number
/// or a value only known when it runs) may run its value as a block.
const PLAIN_MEMBERS: [&str; 8] = [
    "noteproperty",
    "aliasproperty",
    "codeproperty",
    "codemethod",
    "propertyset",
    "memberset",
    "property",
    "method",
];

/// The parameters every cmdlet here takes a value for, and which are never a
/// block: the common parameters with their aliases, and `-Args`, the alias of
/// `-ArgumentList`. A prefix names one.
pub(super) const SHARED_VALUES: [&str; 21] = [
    "erroraction",
    "ea",
    "errorvariable",
    "ev",
    "outvariable",
    "ov",
    "outbuffer",
    "ob",
    "pipelinevariable",
    "pv",
    "warningaction",
    "wa",
    "warningvariable",
    "wv",
    "informationaction",
    "infa",
    "informationvariable",
    "iv",
    "progressaction",
    "proga",
    "args",
];

/// The properties of `$ExecutionContext.InvokeCommand` that hold a block
/// PowerShell runs when a command is looked up or is not found, or when the
/// location changes. Each has a `set_` method that does the same.
pub(super) const HOOKS: [&str; 4] = [
    "commandnotfoundaction",
    "precommandlookupaction",
    "postcommandlookupaction",
    "locationchangedaction",
];

/// What the grammar says of an argument, beside its value: the walk flattens
/// a comma list into one argument each, and a block or a splat is told by
/// its node, not by its text.
#[derive(Clone, Copy, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is a separate fact the grammar tells of the argument; none combine into a state"
)]
pub(super) struct Shape {
    /// A script block written out.
    pub block: bool,
    /// A splat (`@p`): any parameters at all.
    pub splat: bool,
    /// Not the first of a comma list (`-ArgumentList $x, $y`: `$y`), so it
    /// belongs to what the list belongs to.
    pub joined: bool,
    /// Holds a `Get-Process` listing, which the rules for stopping processes
    /// judge (`Stop-Process -Id (Get-Process node).Id`).
    pub listing: bool,
    /// Cannot be a script block only known when it runs: text, a number, a
    /// word, a block written out, a table of them, or a variable the line
    /// sets to one (see [`super::variables::Variables::inert`]).
    pub plain: bool,
}

/// An argument and its shape.
struct Item<'a> {
    arg: &'a Arg,
    shape: Shape,
}

/// The nodes the grammar wraps an expression in, each holding one thing when
/// nothing is applied to it.
const WRAPPERS: [&str; 19] = [
    "pipeline",
    "pipeline_chain",
    "logical_expression",
    "bitwise_expression",
    "comparison_expression",
    "additive_expression",
    "multiplicative_expression",
    "format_expression",
    "range_expression",
    "array_literal_expression",
    "unary_expression",
    "argument_expression",
    "logical_argument_expression",
    "bitwise_argument_expression",
    "comparison_argument_expression",
    "additive_argument_expression",
    "multiplicative_argument_expression",
    "format_argument_expression",
    "range_argument_expression",
];

/// Whether an expression (an assigned value, a method's argument) is a script
/// block written out, however many nodes the grammar wraps it in.
pub(super) fn written(node: Node<'_>) -> bool {
    super::is_script_block(unwrap(node))
}

/// What an expression holds inside the nodes the grammar wraps it in, each
/// with one child.
pub(super) fn unwrap(node: Node<'_>) -> Node<'_> {
    let mut node = node;
    while WRAPPERS.contains(&node.kind()) && node.named_child_count() == 1 {
        match node.named_child(0) {
            Some(only) => node = only,
            None => break,
        }
    }
    node
}

/// The name of a parameter (`-Action`, `-Action:`), in lower case.
fn parameter(arg: &Arg) -> Option<String> {
    let name = arg.known()?.strip_prefix('-')?;
    name.starts_with(|c: char| c.is_ascii_alphabetic())
        .then(|| name.trim_end_matches(':').to_ascii_lowercase())
}

/// Whether `name` is a parameter in `fulls`, as PowerShell takes a prefix.
fn names(name: &str, fulls: &[&str]) -> bool {
    fulls.iter().any(|full| full.starts_with(name))
}

/// A cmdlet's block that is not written out is code the guard does not read,
/// and so is what a splat may hold. True when it is a `ForEach-Object` that
/// calls a method which stops a process on each item (`% Kill`), which the
/// caller judges as the `Stop-Process` it stands for.
pub(super) fn check(
    split: &mut Split,
    key: &str,
    args: &[Arg],
    shapes: &[Shape],
    command: &str,
    depth: usize,
) -> bool {
    if let Some(table) = PROPERTIES.iter().find(|table| table.names.contains(&key)) {
        properties(split, table, args, shapes, command);
        return false;
    }
    if matches!(key, "add-member" | "update-typedata") {
        script_members(split, key, args, shapes, command);
        return false;
    }
    let Some(cmdlet) = CMDLETS.iter().find(|cmdlet| cmdlet.name == key) else {
        return false;
    };
    let mut stops = false;
    let items: Vec<Item<'_>> = args
        .iter()
        .zip(shapes)
        .map(|(arg, shape)| Item { arg, shape: *shape })
        .collect();
    let mut unread = false;
    // A script file only known when it runs (`-FilePath $f`).
    let mut file_unread = false;
    let mut named = false;
    let mut written_out = false;
    let mut bound = Vec::new();
    let mut positional = Vec::new();
    // What `ForEach-Object` is given as a member name by `-MemberName`, and
    // the arguments it is given for the member by `-ArgumentList`.
    let mut members: Vec<&Arg> = Vec::new();
    let mut arguments: Vec<&Item<'_>> = Vec::new();
    let mut iter = items.iter().peekable();
    while let Some(item) = iter.next() {
        if item.shape.splat {
            continue;
        }
        let Some(name) = parameter(item.arg) else {
            positional.push(item);
            continue;
        };
        let colon = item.arg.known().is_some_and(|text| text.ends_with(':'));
        if names(&name, cmdlet.blocks) {
            named = true;
            bound.push(name);
            if let Some(value) = iter.next() {
                unread |= !value.shape.block;
                written_out |= value.shape.block;
                // A list of blocks (`-Process { 1 }, { 2 }`) is all blocks.
                while let Some(more) = iter.next_if(|next| next.shape.joined) {
                    unread |= !more.shape.block;
                }
            }
        } else if colon
            || ((names(&name, cmdlet.values) || names(&name, &SHARED_VALUES))
                && iter
                    .peek()
                    .is_some_and(|next| parameter(next.arg).is_none()))
        {
            // A parameter written with a colon (`-Confirm:$false`) takes the
            // argument after it, whatever its name.
            let for_each = key == "foreach-object";
            let list = for_each && (names(&name, &["argumentlist"]) || names(&name, &["args"]));
            // A parameter that holds a place by position (`-Name`) leaves
            // the next place to the arguments that follow.
            bound.push(name.clone());
            if let Some(value) = iter.next() {
                if matches!(
                    key,
                    "invoke-command" | "start-job" | "register-scheduledjob"
                ) && names(&name, &["filepath", "literalpath"])
                    && value.arg.known().is_none()
                {
                    file_unread = true;
                }
                if for_each && names(&name, &["membername"]) {
                    members.push(value.arg);
                }
                if list {
                    arguments.push(value);
                }
            }
            // A list belongs to the parameter: `-ArgumentList $x, $y`.
            while let Some(more) = iter.next_if(|next| next.shape.joined) {
                if list {
                    arguments.push(more);
                }
            }
        }
    }
    let loose = |item: &&Item<'_>| item.arg.known().is_none() && !item.shape.block;
    written_out |= positional.iter().any(|item| item.shape.block);
    // `ForEach-Object` calls a member when it is given `-MemberName` or a
    // word first (a string never converts to a block): what comes after is
    // the member's arguments, not blocks.
    let first_word = positional
        .first()
        .filter(|item| !item.shape.block && item.arg.known().is_some())
        .copied();
    let member_call = key == "foreach-object" && (!members.is_empty() || first_word.is_some());
    unread |= match cmdlet.positional {
        Some(Positional::Every) if member_call => false,
        Some(Positional::Every) => positional.iter().any(loose),
        Some(Positional::One) if !cmdlet.slots.is_empty() => {
            let free = cmdlet.slots.iter().enumerate().filter(|(_, slot)| {
                !bound
                    .iter()
                    .any(|name| slot.iter().any(|full| full.starts_with(name.as_str())))
            });
            positional.iter().zip(free).any(|(item, (index, slot))| {
                // A place for a name (`Register-ScheduledJob`'s) holds no block.
                if !slot.iter().any(|full| cmdlet.blocks.contains(full)) {
                    false
                } else if index == 0 {
                    loose(item)
                } else {
                    !item.shape.block
                }
            })
        }
        Some(Positional::One) => {
            !named
                && !positional.iter().any(|item| item.shape.block)
                && positional.iter().any(loose)
        }
        Some(Positional::First) => {
            let property = items
                .iter()
                .filter_map(|item| parameter(item.arg))
                .any(|name| names(&name, &["property"]));
            !named && !property && positional.first().is_some_and(loose)
        }
        None => false,
    };
    if member_call {
        if members.is_empty() {
            if let Some(word) = first_word {
                members.push(word.arg);
                arguments.extend(positional.iter().skip(1));
            }
        } else {
            arguments.extend(positional.iter());
        }
        stops = member_names(split, &members, &arguments, command, depth);
    }
    // A splat holds parameters the line does not write out: a block, or one
    // more than the one written. The cmdlets that run one block only are
    // safe beside a block written out.
    if items.iter().any(|item| item.shape.splat) && !(cmdlet.lone && written_out) {
        unread = true;
    }
    if unread {
        split.problem(
            Rule::Unknown,
            "runs a script block only known when it runs",
            Some(command),
        );
    }
    if file_unread {
        split.problem(
            Rule::Unknown,
            "runs a script only known when it runs",
            Some(command),
        );
    }
    stops
}

/// A property given to `Sort-Object`, `Select-Object` and the like, by name
/// or by position, is a name, or a block it runs on each item, written out or
/// in a calculated property (`@{e={ … }}`). One that may be a block only
/// known when it runs (`Sort-Object $b`, `@{e=$b}`, a splat) is unknown.
fn properties(
    split: &mut Split,
    table: &Properties,
    args: &[Arg],
    shapes: &[Shape],
    command: &str,
) {
    let mut unread = false;
    let mut iter = args.iter().zip(shapes).peekable();
    while let Some((arg, shape)) = iter.next() {
        if shape.splat {
            unread = true;
            continue;
        }
        let Some(name) = parameter(arg) else {
            unread |= table.positional && !shape.plain;
            continue;
        };
        let colon = arg.known().is_some_and(|text| text.ends_with(':'));
        let takes = names(&name, table.properties);
        if takes
            || colon
            || ((names(&name, table.values) || names(&name, &SHARED_VALUES))
                && iter
                    .peek()
                    .is_some_and(|(next, _)| parameter(next).is_none()))
        {
            if let Some((_, value)) = iter.next() {
                unread |= takes && !value.plain;
            }
            while let Some((_, more)) = iter.next_if(|(_, next)| next.joined) {
                unread |= takes && !more.plain;
            }
        }
    }
    if unread {
        split.problem(
            Rule::Unknown,
            "runs a script block only known when it runs",
            Some(command),
        );
    }
}

/// `Add-Member` and `Update-TypeData` add a member to objects, and a script
/// member (`ScriptMethod`, `ScriptProperty`) runs its value as a block
/// whenever it is used: a value that is not a block written out, a member
/// type only known when it runs, a splat, and `Update-TypeData -TypeData`
/// (objects that may hold script members) are unknown.
fn script_members(split: &mut Split, key: &str, args: &[Arg], shapes: &[Shape], command: &str) {
    let add = key == "add-member";
    // Given by name: the member type (`None` when only known when it runs),
    // and whether it was given at all.
    let mut member_type: Option<Option<String>> = None;
    let mut note = false;
    let mut unread = false;
    let mut values: Vec<&Shape> = Vec::new();
    let mut bound: Vec<&str> = Vec::new();
    let mut positional: Vec<(&Arg, &Shape)> = Vec::new();
    let others: &[&str] = if add {
        &["name", "typename", "inputobject"]
    } else {
        &[
            "typename",
            "membername",
            "typeconverter",
            "typeadapter",
            "defaultdisplayproperty",
            "defaultdisplaypropertyset",
            "defaultkeypropertyset",
            "serializationmethod",
            "serializationdepth",
            "targettypeforserialization",
            "inheritpropertyserializationset",
            "stringserializationsource",
            "propertyserializationset",
            "appendpath",
            "prependpath",
        ]
    };
    let mut iter = args.iter().zip(shapes).peekable();
    while let Some((arg, shape)) = iter.next() {
        if shape.splat {
            unread = true;
            continue;
        }
        let Some(name) = parameter(arg) else {
            positional.push((arg, shape));
            continue;
        };
        if names(&name, &["membertype"]) || name == "type" {
            bound.push("membertype");
            if let Some((value, _)) = iter.next() {
                member_type = Some(value.known().map(str::to_ascii_lowercase));
            }
        } else if names(&name, &["value", "secondvalue"]) {
            bound.push(if names(&name, &["value"]) {
                "value"
            } else {
                "secondvalue"
            });
            if let Some((_, value)) = iter.next() {
                values.push(value);
            }
        } else if add
            && names(
                &name,
                &[
                    "notepropertyname",
                    "notepropertyvalue",
                    "notepropertymembers",
                ],
            )
        {
            note = true;
            iter.next();
        } else if !add && names(&name, &["typedata"]) {
            unread = true;
            iter.next();
        } else if names(&name, others) || names(&name, &SHARED_VALUES) {
            if names(&name, &["name"]) {
                bound.push("name");
            }
            if iter
                .peek()
                .is_some_and(|(next, _)| parameter(next).is_none())
            {
                iter.next();
            }
        } else {
            continue;
        }
        while iter.next_if(|(_, next)| next.joined).is_some() {}
    }
    // `Add-Member` takes its type, name, value and second value by position,
    // in that order, past the ones given by name.
    if add && !note {
        let slots = ["membertype", "name", "value", "secondvalue"]
            .into_iter()
            .filter(|slot| !bound.contains(slot));
        for ((arg, shape), slot) in positional.iter().zip(slots) {
            match slot {
                "membertype" => member_type = Some(arg.known().map(str::to_ascii_lowercase)),
                "value" | "secondvalue" => values.push(shape),
                _ => {}
            }
        }
    }
    let script = match &member_type {
        None => false,
        Some(None) => true,
        Some(Some(kind)) => !PLAIN_MEMBERS.contains(&kind.as_str()),
    };
    if unread || (script && values.iter().any(|value| !value.block)) {
        split.problem(
            Rule::Unknown,
            "adds a script member only known when it runs",
            Some(command),
        );
    }
}

/// A member name `ForEach-Object` is given (`% Invoke`, `-MemberName Delete`)
/// is a property or a method it calls on each item, with `arguments`: a
/// method that runs code or deletes is as risky as `.Invoke()` and
/// `.Delete()` written out, and so are the ones that build code from text
/// and the hooks set by name. True when one of them stops a process
/// ([`stops_process`]), which is left to the caller to judge by the items.
fn member_names(
    split: &mut Split,
    members: &[&Arg],
    arguments: &[&Item<'_>],
    command: &str,
    depth: usize,
) -> bool {
    let mut stops = false;
    for name in members.iter().map(|arg| arg.known()) {
        let Some(name) = name else {
            // A name only known when it runs may be any method.
            split.problem(
                Rule::Unknown,
                "calls a method only known when it runs",
                Some(command),
            );
            continue;
        };
        let name = bare(name);
        if stops_process(&name) {
            stops = true;
            continue;
        }
        if matches!(
            name.as_str(),
            "newscriptblock" | "invokescript" | "expandstring"
        ) {
            split.problem(
                Rule::Unknown,
                "builds or runs code the guard does not read",
                Some(command),
            );
            // The text, when written out, is read as the call path reads it.
            for argument in arguments {
                let text = match argument.arg {
                    Arg::Known(text) | Arg::Template { text, .. } => text,
                    Arg::Unknown(_) | Arg::Input | Arg::Null => continue,
                };
                unit::script(split, text, Shell::PowerShell, depth + 1);
            }
            continue;
        }
        // A hook is set by its `set_` method, or by its property given one
        // argument; the block must be written out.
        let (hook, sets) = match name.strip_prefix("set_") {
            Some(property) => (HOOKS.contains(&property), true),
            None => (HOOKS.contains(&name.as_str()), !arguments.is_empty()),
        };
        if hook {
            if sets && !arguments.first().is_some_and(|first| first.shape.block) {
                split.problem(
                    Rule::Unknown,
                    "sets a hook that runs a script block only known when it runs",
                    Some(command),
                );
            }
            continue;
        }
        if let Some((rule, reason)) = super::dotnet_rule(&name, "", false) {
            split.problem(rule, reason, Some(command));
        }
    }
    stops
}

/// Whether a method (lower case) stops the process it is called on:
/// `Kill`, `Terminate` (WMI's) and `CloseMainWindow`, which asks a process
/// to close. A call of one is judged as the `Stop-Process` of its object.
pub(super) fn stops_process(method: &str) -> bool {
    matches!(method, "kill" | "terminate" | "closemainwindow")
}

/// A member name without the quotes it was written in, in lower case.
pub(super) fn bare(name: &str) -> String {
    name.trim_matches(['\'', '"']).to_ascii_lowercase()
}

/// The method a call names, in lower case, when the name is written out: a
/// plain name, or a string with nothing in it that is only known when it runs
/// (a quoted name, or one with a backtick escape in double quotes). `None`
/// for a variable, an expression, a block or an expandable string with a `$`
/// part in it.
pub(super) fn called(member: Node<'_>, source: &str) -> Option<String> {
    let name = member.named_child(0)?;
    match name.kind() {
        "simple_name" => Some(bare(unit::text(&name, source))),
        "string_literal" => {
            let text = unit::text(&name, source);
            let quote = text.chars().next()?;
            let inner = text.get(1..text.len().checked_sub(1)?)?;
            let plain = match name.named_child(0) {
                Some(part) if part.kind() == "verbatim_string_characters" => quote == '\'',
                Some(part) if part.kind() == "expandable_string_literal" => {
                    quote == '"' && part.named_child_count() == 0
                }
                _ => false,
            };
            plain.then(|| {
                let inner = if quote == '"' {
                    super::unescape(inner)
                } else {
                    inner.to_string()
                };
                inner.to_ascii_lowercase()
            })
        }
        _ => None,
    }
}

/// The name of the property or method a member access or call ends in, as
/// written (`CommandNotFoundAction`, `"CommandNotFoundAction"`), in lower
/// case.
fn member(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let name = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "member_name")
        .last()?;
    Some(bare(unit::text(&name, source)))
}

/// `$ExecutionContext.InvokeCommand.CommandNotFoundAction = $b`: a hook that
/// runs for every command, a block the guard reads only when it is written
/// out.
pub(super) fn hook(split: &mut Split, node: Node<'_>, source: &str) {
    let Some(right) = node.child_by_field_name("value") else {
        return;
    };
    if assigned_member(node, source).is_some_and(|name| HOOKS.contains(&name.as_str()))
        && !written(right)
    {
        split.problem(
            Rule::Unknown,
            "sets a hook that runs a script block only known when it runs",
            Some(unit::text(&node, source)),
        );
    }
}

/// The property an assignment sets (`$x.CommandNotFoundAction = …`,
/// `[Environment]::CurrentDirectory = …`), in lower case; `None` when it sets
/// a variable.
pub(super) fn assigned_member(node: Node<'_>, source: &str) -> Option<String> {
    let mut left = node.named_child(0)?;
    // The grammar wraps the target in a chain of one-child nodes.
    while left.kind() != "member_access" && left.named_child_count() == 1 {
        left = left.named_child(0)?;
    }
    if left.kind() != "member_access" {
        return None;
    }
    member(left, source)
}

/// Whether a method call sets a hook (`$ExecutionContext.InvokeCommand
/// .set_PreCommandLookupAction({ … })`), whose block runs later.
pub(super) fn sets_hook(node: Node<'_>, source: &str) -> bool {
    let mut cursor = node.walk();
    let member = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "member_name");
    member
        .and_then(|member| called(member, source))
        .and_then(|method| {
            method
                .strip_prefix("set_")
                .map(|property| HOOKS.contains(&property))
        })
        .unwrap_or(false)
}

/// `$ExecutionContext.InvokeCommand.set_CommandNotFoundAction($b)`: the same
/// hook set by its method; `method` is the name called and `children` the
/// parts of the call.
pub(super) fn hook_call(
    split: &mut Split,
    method: &str,
    children: &[Node<'_>],
    node: Node<'_>,
    source: &str,
) {
    let Some(property) = method.strip_prefix("set_") else {
        return;
    };
    if !HOOKS.contains(&property) {
        return;
    }
    if !first_argument(children).is_some_and(written) {
        split.problem(
            Rule::Unknown,
            "sets a hook that runs a script block only known when it runs",
            Some(unit::text(&node, source)),
        );
    }
}

/// The first argument a method call is given; `children` are the call's
/// parts.
pub(super) fn first_argument<'tree>(children: &[Node<'tree>]) -> Option<Node<'tree>> {
    let list = children
        .iter()
        .find(|child| child.kind() == "argument_list")?;
    list.named_child(0)?.named_child(0)
}

/// The string a method call is given first, when it is written out as one
/// (`Create('…')`); `children` are the call's parts.
pub(super) fn first_string<'tree>(children: &[Node<'tree>]) -> Option<Node<'tree>> {
    let mut node = first_argument(children)?;
    loop {
        if node.kind() == "string_literal" {
            return Some(node);
        }
        if node.named_child_count() != 1 {
            return None;
        }
        node = node.named_child(0)?;
    }
}

/// Whether a chain of members (`$ExecutionContext.InvokeCommand.$h`,
/// `….psobject.Properties['CommandNotFoundAction'].Value`) reaches a member
/// by a way the guard cannot name: a name only known when it runs, an item
/// by index, the result of a call, or the object's own view of its members
/// (`psobject`, `psbase`, `psadapted`, `psextended`). Such a member may be a
/// hook, or a method that runs code.
pub(super) fn obscure(node: Node<'_>, source: &str) -> bool {
    let mut node = unwrap(node);
    for _ in 0..unit::MAX_TREE_DEPTH {
        match node.kind() {
            "member_access" => {
                let mut cursor = node.walk();
                let member = node
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() == "member_name")
                    .last();
                match member.and_then(|member| called(member, source)) {
                    None => return true,
                    Some(name)
                        if matches!(
                            name.as_str(),
                            "psobject" | "psbase" | "psadapted" | "psextended"
                        ) =>
                    {
                        return true;
                    }
                    Some(_) => {}
                }
            }
            "element_access" | "invokation_expression" => return true,
            "parenthesized_expression" => {}
            _ => return false,
        }
        let Some(object) = node.named_child(0) else {
            return false;
        };
        node = unwrap(object);
    }
    true
}

/// The member an assignment sets (`$x.y = …`, `$x[0] = …`), however the
/// grammar wraps it; `None` when it sets a variable.
pub(super) fn assigned_target(node: Node<'_>) -> Option<Node<'_>> {
    let mut left = node.named_child(0)?;
    if left.kind() == "left_assignment_expression" {
        left = left.named_child(0)?;
    }
    let left = unwrap(left);
    matches!(left.kind(), "member_access" | "element_access").then_some(left)
}
