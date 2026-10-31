//! Script blocks a cmdlet runs: one written out where it stands is read by
//! the walk; one that comes from anywhere else (`$b`, `(Get-Block)`,
//! `[scriptblock]::Create($code)`) is code the guard does not read.

use tree_sitter::Node;

use crate::unit::{self, Arg, Split};
use crate::Rule;

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
}

/// The cmdlets whose script blocks the guard reads. The ones that register
/// an event action are read with the events (`Register-ObjectEvent` and the
/// like), each for its own parameter order.
const CMDLETS: [Cmdlet; 8] = [
    Cmdlet {
        name: "invoke-command",
        blocks: &["scriptblock"],
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
    },
    Cmdlet {
        name: "foreach-object",
        blocks: &["process", "begin", "end", "parallel"],
        values: &[
            "membername",
            "argumentlist",
            "inputobject",
            "throttlelimit",
            "timeoutseconds",
        ],
        positional: Some(Positional::Every),
    },
    Cmdlet {
        name: "start-job",
        blocks: &["scriptblock", "initializationscript"],
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
        ],
        positional: Some(Positional::One),
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
    },
    Cmdlet {
        name: "set-psbreakpoint",
        blocks: &["action"],
        values: &[
            "script", "line", "column", "command", "variable", "mode", "runspace",
        ],
        positional: None,
    },
    Cmdlet {
        name: "new-module",
        blocks: &["scriptblock"],
        values: &["name", "function", "cmdlet", "argumentlist"],
        positional: Some(Positional::One),
    },
    Cmdlet {
        name: "measure-command",
        blocks: &["expression"],
        values: &["inputobject"],
        positional: Some(Positional::One),
    },
];

/// The properties of `$ExecutionContext.InvokeCommand` that hold a block
/// PowerShell runs when a command is looked up or is not found.
const HOOKS: [&str; 3] = [
    "commandnotfoundaction",
    "precommandlookupaction",
    "postcommandlookupaction",
];

/// Whether `arg` is a script block written out: the grammar hands one over
/// as the source text of the block, `{ … }`.
fn is_block(arg: &Arg) -> bool {
    arg.known().is_none() && block_text(arg.text())
}

fn block_text(text: &str) -> bool {
    text.starts_with('{') && text.ends_with('}')
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

/// A cmdlet's block that is not written out is code the guard does not read.
pub(super) fn check(split: &mut Split, key: &str, args: &[Arg], command: &str) {
    let Some(cmdlet) = CMDLETS.iter().find(|cmdlet| cmdlet.name == key) else {
        return;
    };
    let mut unread = false;
    let mut named = false;
    let mut positional = Vec::new();
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let Some(name) = parameter(arg) else {
            positional.push(arg);
            continue;
        };
        if names(&name, cmdlet.blocks) {
            named = true;
            if let Some(value) = iter.next() {
                unread |= !is_block(value);
            }
        } else if names(&name, cmdlet.values)
            && iter.peek().is_some_and(|next| parameter(next).is_none())
        {
            iter.next();
        }
    }
    let loose = |arg: &&Arg| arg.known().is_none() && !is_block(arg);
    unread |= match cmdlet.positional {
        Some(Positional::Every) => positional.iter().any(loose),
        Some(Positional::One) => {
            !named && !positional.iter().any(|arg| is_block(arg)) && positional.iter().any(loose)
        }
        None => false,
    };
    if unread {
        split.problem(
            Rule::Unknown,
            "runs a script block only known when it runs",
            Some(command),
        );
    }
}

/// `$ExecutionContext.InvokeCommand.CommandNotFoundAction = $b`: a hook that
/// runs for every command, a block the guard reads only when it is written
/// out.
pub(super) fn hook(split: &mut Split, node: Node<'_>, source: &str) {
    let Some(left) = node.named_child(0) else {
        return;
    };
    let mut cursor = node.walk();
    let Some(right) = node.named_children(&mut cursor).last() else {
        return;
    };
    let left = unit::text(&left, source).trim().to_ascii_lowercase();
    if HOOKS.iter().any(|hook| left.ends_with(hook))
        && !block_text(unit::text(&right, source).trim())
    {
        split.problem(
            Rule::Unknown,
            "sets a hook that runs a script block only known when it runs",
            Some(unit::text(&node, source)),
        );
    }
}

/// The string a method call is given first, when it is written out as one
/// (`Create('…')`); `children` are the call's parts.
pub(super) fn first_string<'tree>(children: &[Node<'tree>]) -> Option<Node<'tree>> {
    let list = children
        .iter()
        .find(|child| child.kind() == "argument_list")?;
    let mut node = list.named_child(0)?.named_child(0)?;
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
