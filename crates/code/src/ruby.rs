//! Inline Ruby: the calls that delete, write, move and run, with the paths
//! they name, found with tree-sitter-ruby.
//!
//! A call is found by its receiver and its name (`File.delete`,
//! `FileUtils.rm_rf`, `system`), its receiver a constant as written
//! (`FileUtils::Verbose` is `FileUtils`, `Kernel` and `self` are none); a
//! path is a literal string, `Dir.home`, `ENV["HOME"]`, `File.join`,
//! `File.expand_path`, `Pathname`, `+` and `#{…}` made only of those. A
//! name the code sets is a path only known when it runs. What the reader
//! has no row for is an `Unread` act, or an `Opaque` one where it is given
//! a path.

use std::collections::HashSet;

use tree_sitter::Node;

use super::{
    environment, kill, mode, named_path, path, read_path, walk, writes, Act, Language, Parts,
    Reading,
};
use crate::scan;
use crate::unit::{self, Arg, Budget, Parsed, Refusal, MAX_TREE_DEPTH};

pub(super) fn read(code: &str, budget: &Budget) -> Reading {
    let mut reading = Reading::default();
    // Code that declares an encoding other than UTF-8 is read by Ruby as
    // other text than the reader sees.
    if declares_other_encoding(code) {
        reading.unread(code);
        return reading;
    }
    // Code with an error is not read through it, and code whose parse is
    // stopped is not read.
    let Parsed::Tree(tree) = parse(budget, code) else {
        reading.unread(code);
        return reading;
    };
    let root = tree.root_node();
    let mut reader = Reader {
        src: code,
        budget,
        reading,
        fetched: HashSet::new(),
        fileutils: false,
        nesting: 0,
    };
    // A first line `#!…` is read by Ruby when it runs the code as a file.
    if shebang_runs_more(code) {
        reader.reading.unread(code);
    }
    reader.prepare(root);
    walk(budget, root, |node, _, _| {
        reader.visit(node);
        true
    });
    reader.past_end(root);
    // Code inside it whose parse was stopped is not read, wherever the
    // reader met it, and so is code whose walk ran out.
    if budget.is_spent()
        && !reader
            .reading
            .acts
            .iter()
            .any(|act| matches!(act, Act::Unread(_)))
    {
        reader.reading.unread(code);
    }
    reader.reading
}

/// Whether the first line of `code`, a `#!` line, makes Ruby run more than
/// the code when it runs it as a file: Ruby applies the switches on it
/// (`-r` and `-I` load files, `-C` changes the folder, `-x` skips lines),
/// and runs as the program it names a line that has no `ruby` in it. Whatever
/// is on the line after its program, any word that starts with a `-`, counts.
pub(super) fn shebang_runs_more(code: &str) -> bool {
    let Some(line) = code.lines().next().and_then(|line| line.strip_prefix("#!")) else {
        return false;
    };
    !line.contains("ruby") || line.split_whitespace().any(|word| word.starts_with('-'))
}

/// Whether `code` parses whole, read as [`read`] reads it.
///
/// Code whose parse is stopped (see [`Budget`]) is not said to parse.
pub(super) fn parses(code: &str, budget: &Budget) -> bool {
    matches!(parse(budget, code), Parsed::Tree(_))
}

/// Whether `code` may hand a program it starts something to read on its
/// input: an option `in` or `stdin_data` (`Open3.capture2('sh', stdin_data:
/// …)`), a `popen` of `Open3` (which hands back the program's input), and
/// `IO.popen` given more than its command (`IO.popen('sh', 'w')`). Code that
/// does not parse may.
pub(super) fn gives_input(code: &str, budget: &Budget) -> bool {
    // Code not read, as code that does not parse, may.
    let Parsed::Tree(tree) = parse(budget, code) else {
        return true;
    };
    let mut found = false;
    unit::for_each_node(budget, tree.root_node(), |node| match node.kind() {
        "pair" => {
            found |= node
                .child_by_field_name("key")
                .is_some_and(|key| matches!(key_name(key, code), "in" | "stdin_data" | "stdin"));
        }
        "call" => {
            let name = node
                .child_by_field_name("method")
                .map_or("", |method| unit::text(&method, code));
            let given = node
                .child_by_field_name("arguments")
                .map_or(0, |arguments| arguments.named_child_count());
            found |= matches!(
                name,
                "popen2" | "popen2e" | "popen3" | "pipeline_w" | "pipeline_rw" | "stdin"
            ) || (name == "popen" && given > 1);
        }
        _ => {}
    });
    // A walk cut short has not read the code: it may.
    found || budget.is_spent()
}

/// Whether `code` may hand a shell a list of words: a call that starts a
/// program (`system`, `exec`, `spawn`, `IO.popen`, `Open3`) given more than
/// one word, an array, or words spread from a name. On Windows Ruby joins
/// such words into a line a shell may read (a batch file's). Code that does
/// not parse may.
pub(super) fn gives_shell_a_list(code: &str, budget: &Budget) -> bool {
    // Code not read, as code that does not parse, may.
    let Parsed::Tree(tree) = parse(budget, code) else {
        return true;
    };
    let mut found = false;
    unit::for_each_node(budget, tree.root_node(), |node| {
        if node.kind() != "call" {
            return;
        }
        let name = node
            .child_by_field_name("method")
            .map_or("", |method| unit::text(&method, code));
        if !RUNS.contains(&name) && !OPEN3.contains(&name) && name != "popen" {
            return;
        }
        let words: Vec<Node<'_>> = arguments(node)
            .into_iter()
            .filter(|argument| !matches!(argument.kind(), "pair" | "hash"))
            .collect();
        found |= words.len() > 1
            || words
                .iter()
                .any(|word| matches!(word.kind(), "array" | "splat_argument"));
    });
    // A walk cut short has not read the code: it may.
    found || budget.is_spent()
}

/// Parse `code` as Ruby, within what is left of `budget`. Code whose
/// openers nest deeper than [`MAX_TREE_DEPTH`] (as the text is read, or on
/// its bytes alone), or that goes past what the grammar's scanner holds
/// (see [`scan::ruby`]), is not read.
pub(super) fn parse(budget: &Budget, code: &str) -> Parsed {
    unit::parse(budget, &tree_sitter_ruby::LANGUAGE.into(), code, |code| {
        let scanned = scan::ruby(code);
        let refused = scanned.depth > MAX_TREE_DEPTH
            || scanned.raw_depth > MAX_TREE_DEPTH
            || scanned.marks > 0;
        (scanned, refused.then_some(Refusal::Stopped))
    })
}

/// Whether Ruby reads `code` as other text than the reader does: a magic
/// comment in its first line (its second after a `#!` line) declares an
/// encoding other than UTF-8 (`# encoding: shift_jis`), for code that is
/// not all ASCII. Ruby reads no source in an encoding that is not
/// ASCII-compatible, so ASCII code reads the same in any.
pub(super) fn declares_other_encoding(code: &str) -> bool {
    if code.is_ascii() {
        return false;
    }
    let mut lines = code.lines();
    let first = lines.next().unwrap_or_default();
    let candidates = if first.starts_with("#!") {
        [lines.next(), None]
    } else {
        [Some(first), None]
    };
    candidates.into_iter().flatten().any(|line| {
        let Some(comment) = line.trim_start().strip_prefix('#') else {
            return false;
        };
        let lower = comment.to_ascii_lowercase();
        lower.match_indices("coding").any(|(at, word)| {
            let Some(rest) = lower[at + word.len()..].strip_prefix([':', '=']) else {
                return false;
            };
            let name: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
                .collect();
            !matches!(name.replace('_', "-").as_str(), "utf-8" | "utf8")
        })
    })
}

/// The calls of `Kernel` and `Process` that start a program as `system`
/// does: a line a shell reads when it is one string, a program and its
/// arguments when it is more.
const RUNS: [&str; 3] = ["system", "exec", "spawn"];

/// The calls of `Open3` that start a program as `spawn` does.
const OPEN3: [&str; 6] = [
    "capture2",
    "capture2e",
    "capture3",
    "popen2",
    "popen2e",
    "popen3",
];

/// The calls of `Open3` that start each command they are given.
const PIPELINES: [&str; 5] = [
    "pipeline",
    "pipeline_r",
    "pipeline_w",
    "pipeline_rw",
    "pipeline_start",
];

/// The calls of `FileUtils` that delete what their first argument names.
const FILEUTILS_REMOVE: [&str; 12] = [
    "rm",
    "rm_f",
    "rm_r",
    "rm_rf",
    "rmtree",
    "remove",
    "remove_dir",
    "remove_entry",
    "remove_entry_secure",
    "remove_file",
    "rmdir",
    "safe_unlink",
];

/// The calls of `FileUtils` that make what their first argument names.
const FILEUTILS_MAKE: [&str; 5] = ["touch", "mkdir", "mkdir_p", "makedirs", "mkpath"];

/// The calls of `FileUtils` that copy their first argument to their second.
const FILEUTILS_COPY: [&str; 7] = [
    "cp",
    "copy",
    "cp_r",
    "copy_file",
    "copy_entry",
    "install",
    "cp_lr",
];

/// The calls of `FileUtils` that link their second argument to their first.
const FILEUTILS_LINK: [&str; 6] = ["ln", "link", "ln_s", "symlink", "ln_sf", "ln_sr"];

/// The calls that run Ruby code given as a string.
const EVALS: [&str; 4] = ["eval", "instance_eval", "class_eval", "module_eval"];

/// The calls that load code from a file the reader does not read.
const LOADS: [&str; 4] = ["require", "require_relative", "load", "autoload"];

/// The calls that call or define a method by a name, or reach into an
/// object, so that what runs is no call the reader names.
const INDIRECT: [&str; 18] = [
    "send",
    "__send__",
    "public_send",
    "method",
    "public_method",
    "instance_method",
    "define_method",
    "define_singleton_method",
    "const_get",
    "const_set",
    "instance_variable_get",
    "instance_variable_set",
    "class_variable_get",
    "class_variable_set",
    "alias_method",
    "remove_method",
    "undef_method",
    "set_trace_func",
];

/// The receivers whose every call reaches into the interpreter or the
/// machine.
const INDIRECT_RECEIVERS: [&str; 5] = ["ObjectSpace", "Fiddle", "TracePoint", "RubyVM", "DL"];

/// The calls with no row that only print or stop: a path given to one is no
/// path a file is opened at.
const HARMLESS: [&str; 12] = [
    "puts", "print", "p", "pp", "printf", "sprintf", "format", "warn", "raise", "fail", "abort",
    "exit",
];

/// The calls of `File`, `Dir` and `Pathname` that work out a path, or ask
/// what is at one, and open nothing: a path given to one is no file read.
const NAMES_ONLY: [&str; 27] = [
    "join",
    "expand_path",
    "absolute_path",
    "absolute_path?",
    "basename",
    "dirname",
    "extname",
    "split",
    "exist?",
    "file?",
    "directory?",
    "symlink?",
    "readable?",
    "writable?",
    "executable?",
    "size",
    "size?",
    "zero?",
    "empty?",
    "mtime",
    "atime",
    "ctime",
    "ftype",
    "fnmatch",
    "fnmatch?",
    "home",
    "pwd",
];

/// The names that make a program the code starts run more than the code
/// says: `trap` with a string runs it as code.
const TRAP_WORDS: [&str; 6] = [
    "IGNORE",
    "SIG_IGN",
    "DEFAULT",
    "SIG_DFL",
    "EXIT",
    "SYSTEM_DEFAULT",
];

/// The most links of a chain of `Pathname` joins (`p / "a" / "b"`) the
/// reader works out: past it, the path is one it does not know.
const MAX_PATH_CHAIN: usize = 16;

/// What the receiver of a call is.
enum Receiver {
    /// None: a call of `Kernel` (also `self.x`, `Kernel.x`).
    Kernel,
    /// A constant, as written (`File`, `Net::HTTP`, `FileUtils`).
    Named(String),
    /// A `Pathname` of a path: `Pathname.new(p)`, `Pathname(p)`.
    Path(Parts),
    /// Any other value.
    Value,
}

struct Reader<'s, 'b> {
    src: &'s str,
    budget: &'b Budget,
    reading: Reading,
    /// The names the code sets to what it fetches from the network.
    fetched: HashSet<String>,
    /// Whether the code includes `FileUtils`, whose calls it then makes by
    /// their names alone.
    fileutils: bool,
    /// How deep the evaluation of a string is (see [`Reader::parts`]).
    nesting: usize,
}

/// The arguments of `call`, as the grammar gives them.
fn arguments(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(list) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = list.walk();
    let found: Vec<Node<'_>> = list
        .named_children(&mut cursor)
        .filter(|node| node.kind() != "comment")
        .collect();
    found
}

/// The name a hash's key gives (`chdir:`, `:chdir`, `"chdir"`).
fn key_name<'s>(key: Node<'_>, code: &'s str) -> &'s str {
    let text = unit::text(&key, code);
    text.trim_start_matches(':')
        .trim_end_matches(':')
        .trim_matches(['"', '\''])
}

impl<'s> Reader<'s, '_> {
    fn text(&self, node: Node<'_>) -> &'s str {
        unit::text(&node, self.src)
    }

    fn act(&mut self, act: Act) {
        self.reading.acts.push(act);
    }

    fn unread(&mut self, node: Node<'_>) {
        let text = self.text(node).to_string();
        self.reading.unread(&text);
    }

    /// Note what the walk needs ahead of it: the names set to a fetch from
    /// the network, and an `include FileUtils`.
    fn prepare(&mut self, root: Node<'_>) {
        let mut fetching = Vec::new();
        let mut includes = false;
        unit::for_each_node(self.budget, root, |node| match node.kind() {
            "assignment" => {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if left.kind() == "identifier" {
                        fetching.push((left, right));
                    }
                }
            }
            "call" => {
                let name = node
                    .child_by_field_name("method")
                    .map_or("", |method| unit::text(&method, self.src));
                if node.child_by_field_name("receiver").is_none()
                    && matches!(name, "include" | "extend")
                    && arguments(node)
                        .iter()
                        .any(|argument| unit::text(argument, self.src).ends_with("FileUtils"))
                {
                    includes = true;
                }
            }
            _ => {}
        });
        self.fileutils = includes;
        // A name set from another that holds a fetch fetches too, to a
        // few rounds.
        for _ in 0..4 {
            let mut more = false;
            for (left, right) in &fetching {
                let name = self.text(*left).to_string();
                if !self.fetched.contains(&name) && self.fetches(*right) {
                    self.fetched.insert(name);
                    more = true;
                }
            }
            if !more {
                break;
            }
        }
    }

    /// Whether `node` holds what fetches code from the network: `Net::HTTP`,
    /// `URI`, `OpenURI` and the HTTP clients, a URL of `http:`, `https:` or
    /// `ftp:`, or a name set to one of those.
    fn fetches(&self, node: Node<'_>) -> bool {
        let mut found = false;
        unit::for_each_node(self.budget, node, |inner| {
            let text = self.text(inner);
            found |= match inner.kind() {
                "scope_resolution" => text.trim_start_matches("::").starts_with("Net::"),
                "constant" => matches!(
                    text,
                    "URI" | "OpenURI" | "HTTParty" | "Faraday" | "RestClient" | "Excon" | "HTTP"
                ),
                "string_content" => {
                    let lower = text.trim_start().to_ascii_lowercase();
                    ["http://", "https://", "ftp://"]
                        .iter()
                        .any(|scheme| lower.starts_with(scheme))
                }
                "identifier" => self.fetched.contains(text),
                _ => false,
            };
        });
        found
    }

    /// The grammar ends the code at `__END__` wherever it starts a line's
    /// words; Ruby only at one alone on its line, at its start, and reads on
    /// past any other (`__END__ x`, `  __END__`, `__END__\r…`): the code after
    /// it is code Ruby runs, read again as a `Code` act.
    fn past_end(&mut self, root: Node<'_>) {
        let mut cursor = root.walk();
        let Some(rest) = root
            .named_children(&mut cursor)
            .find(|child| child.kind() == "uninterpreted")
        else {
            return;
        };
        let start = rest.start_byte();
        let text = self.text(rest);
        let keyword = start
            .checked_sub(7)
            .filter(|at| self.src.get(*at..start) == Some("__END__"));
        let alone = keyword.is_some_and(|at| {
            (at == 0 || self.src.as_bytes().get(at - 1) == Some(&b'\n'))
                && (text.is_empty() || text.starts_with('\n') || text.starts_with("\r\n"))
        });
        if !alone {
            self.act(Act::Code(Language::Ruby, text.to_string()));
        }
    }

    fn visit(&mut self, node: Node<'_>) {
        // A keyword (`alias`) is the business of the node it is in.
        if !node.is_named() {
            return;
        }
        match node.kind() {
            "call" => self.call(node),
            "subshell" => {
                let parts = self.literal(node, 0);
                let script = path(parts.value(), self.text(node));
                self.act(Act::Script(script));
            }
            // `alias s system` calls `system` by another name.
            "alias" | "undef" => self.unread(node),
            "assignment" | "operator_assignment" => {
                let Some(left) = node.child_by_field_name("left") else {
                    return;
                };
                match left.kind() {
                    "element_reference" => {
                        let object = left
                            .child_by_field_name("object")
                            .map_or("", |object| self.text(object));
                        if object.trim_start_matches("::") == "ENV" {
                            self.act(Act::Environment);
                        }
                    }
                    // `$LOAD_PATH = …`, `$: = …`: where a `require` looks.
                    "global_variable" if matches!(self.text(left), "$LOAD_PATH" | "$:" | "$-I") => {
                        self.unread(node);
                    }
                    _ => {}
                }
            }
            // `$LOAD_PATH << dir`: where a `require` looks.
            "binary"
                if node.child_by_field_name("left").is_some_and(|left| {
                    left.kind() == "global_variable"
                        && matches!(self.text(left), "$LOAD_PATH" | "$:" | "$-I")
                }) =>
            {
                self.unread(node);
            }
            _ => {}
        }
    }

    /// What the receiver of `call` is.
    fn receiver(&mut self, call: Node<'_>) -> Receiver {
        let Some(receiver) = call.child_by_field_name("receiver") else {
            return Receiver::Kernel;
        };
        match receiver.kind() {
            "self" => Receiver::Kernel,
            "constant" | "scope_resolution" => {
                let name = self.text(receiver).trim_start_matches("::");
                let name = match name {
                    "Kernel" => return Receiver::Kernel,
                    "FileUtils::Verbose" => "FileUtils",
                    other => other,
                };
                if name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':')
                {
                    Receiver::Named(name.to_string())
                } else {
                    Receiver::Value
                }
            }
            "call" => match self.pathname(receiver, 0) {
                Some(parts) => Receiver::Path(parts),
                None => Receiver::Value,
            },
            "parenthesized_statements" if receiver.named_child_count() == 1 => {
                match receiver
                    .named_child(0)
                    .and_then(|inner| self.pathname(inner, 0))
                {
                    Some(parts) => Receiver::Path(parts),
                    None => Receiver::Value,
                }
            }
            _ => Receiver::Value,
        }
    }

    /// The path a `Pathname` value names: `Pathname.new(p)`, `Pathname(p)`,
    /// and one joined to it (`/`, `+`, `join`).
    fn pathname(&mut self, node: Node<'_>, depth: usize) -> Option<Parts> {
        // A longer chain is a path the reader does not work out.
        if depth > MAX_PATH_CHAIN {
            return Some(Parts::unknown());
        }
        if !self.budget.walk(1) {
            return Some(Parts::unknown());
        }
        match node.kind() {
            "call" => {
                let method = node.child_by_field_name("method")?;
                let name = self.text(method);
                let receiver = node.child_by_field_name("receiver");
                let args = arguments(node);
                let constant = receiver
                    .filter(|receiver| matches!(receiver.kind(), "constant" | "scope_resolution"))
                    .map(|receiver| self.text(receiver).trim_start_matches("::"));
                match (constant, name) {
                    (Some("Pathname"), "new") | (None, "Pathname")
                        if constant.is_some() || receiver.is_none() =>
                    {
                        Some(
                            args.first()
                                .map_or_else(Parts::unknown, |first| self.parts(*first, 1)),
                        )
                    }
                    (_, "join") if receiver.is_some() => {
                        let base = self.pathname(receiver?, depth + 1)?;
                        Some(self.joined(base, &args))
                    }
                    _ => None,
                }
            }
            "binary" => {
                let operator = node.child_by_field_name("operator")?;
                if !matches!(self.text(operator), "/" | "+") {
                    return None;
                }
                let base = self.pathname(node.child_by_field_name("left")?, depth + 1)?;
                let right = node.child_by_field_name("right")?;
                Some(self.joined(base, &[right]))
            }
            "parenthesized_statements" if node.named_child_count() == 1 => {
                self.pathname(node.named_child(0)?, depth + 1)
            }
            _ => None,
        }
    }

    /// `base` with each of `nodes` joined to it as `Pathname#join` joins: an
    /// absolute part stands alone.
    fn joined(&mut self, base: Parts, nodes: &[Node<'_>]) -> Parts {
        let mut joined = base;
        for node in nodes {
            if !joined.whole {
                return joined;
            }
            let next = self.parts(*node, 1);
            let text = super::join(&joined.text, &next.text);
            joined = Parts {
                text,
                whole: next.whole,
            };
        }
        joined
    }

    /// What `node` is as a string, as far as the reader knows it. However
    /// the evaluation goes back into itself (a `#{…}`, a join, a call), it
    /// goes no deeper than [`MAX_TREE_DEPTH`], so no code overflows the
    /// stack.
    fn parts(&mut self, node: Node<'_>, level: usize) -> Parts {
        if level > MAX_TREE_DEPTH || self.nesting > MAX_TREE_DEPTH || !self.budget.walk(1) {
            return Parts::unknown();
        }
        self.nesting += 1;
        let parts = self.parts_of(node, level);
        self.nesting -= 1;
        parts
    }

    fn parts_of(&mut self, node: Node<'_>, level: usize) -> Parts {
        match node.kind() {
            "string" => self.literal(node, level),
            "chained_string" => {
                let mut cursor = node.walk();
                let pieces: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                let mut joined = Parts::whole(String::new());
                for piece in pieces {
                    let next = self.parts(piece, level + 1);
                    joined.text.push_str(&next.text);
                    if !next.whole {
                        joined.whole = false;
                        break;
                    }
                }
                joined
            }
            "parenthesized_statements" if node.named_child_count() == 1 => node
                .named_child(0)
                .map_or_else(Parts::unknown, |inner| self.parts(inner, level + 1)),
            "binary" => {
                let (Some(left), Some(operator), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("operator"),
                    node.child_by_field_name("right"),
                ) else {
                    return Parts::unknown();
                };
                if let Some(path) = self.pathname(node, 0) {
                    return path;
                }
                if self.text(operator) != "+" {
                    return Parts::unknown();
                }
                let mut joined = self.parts(left, level + 1);
                if !joined.whole {
                    return joined;
                }
                let next = self.parts(right, level + 1);
                joined.text.push_str(&next.text);
                joined.whole = next.whole;
                joined
            }
            "element_reference" => self
                .environment(node)
                .map_or_else(Parts::unknown, Parts::whole),
            "call" => self.parts_of_call(node, level),
            _ => Parts::unknown(),
        }
    }

    /// The directory `ENV["HOME"]` and the like name.
    fn environment(&mut self, node: Node<'_>) -> Option<String> {
        let object = node.child_by_field_name("object")?;
        if self.text(object).trim_start_matches("::") != "ENV" || node.named_child_count() != 2 {
            return None;
        }
        let key = node.named_child(1)?;
        let name = self.parts(key, 1).value()?;
        environment(&name)
    }

    /// What a call gives as a string, where it is one the reader knows.
    fn parts_of_call(&mut self, call: Node<'_>, level: usize) -> Parts {
        let Some(method) = call.child_by_field_name("method") else {
            return Parts::unknown();
        };
        let name = self.text(method).to_string();
        let args = arguments(call);
        if let Some(path) = self.pathname(call, 0) {
            return path;
        }
        let receiver = call.child_by_field_name("receiver");
        let constant = receiver
            .filter(|receiver| matches!(receiver.kind(), "constant" | "scope_resolution"))
            .map(|receiver| self.text(receiver).trim_start_matches("::"));
        match (constant, name.as_str()) {
            (Some("Dir"), "home") if args.is_empty() => Parts::whole("~".to_string()),
            (Some("Dir"), "pwd" | "getwd") => Parts::whole(".".to_string()),
            (Some("Dir"), "tmpdir") => Parts::whole("/tmp".to_string()),
            (Some("ENV"), "fetch") => {
                let name = args
                    .first()
                    .and_then(|first| self.parts(*first, level + 1).value());
                name.as_deref()
                    .and_then(environment)
                    .map_or_else(Parts::unknown, Parts::whole)
            }
            (Some("File"), "join") => {
                let mut joined = Parts::whole(String::new());
                for (at, arg) in args.iter().enumerate() {
                    let next = self.parts(*arg, level + 1);
                    if at > 0 && !joined.text.ends_with('/') && !next.text.starts_with('/') {
                        joined.text.push('/');
                    }
                    joined.text.push_str(
                        next.text.trim_start_matches(|c| {
                            c == '/' && at > 0 && joined.text.ends_with('/')
                        }),
                    );
                    if !next.whole {
                        joined.whole = false;
                        break;
                    }
                }
                joined
            }
            (Some("File"), "expand_path" | "absolute_path") => {
                let Some(first) = args.first() else {
                    return Parts::unknown();
                };
                let path = self.parts(*first, level + 1);
                match args.get(1) {
                    Some(dir) if path.whole && !path.text.starts_with(['/', '~']) => {
                        let base = self.parts(*dir, level + 1);
                        self.joined(base, &[*first])
                    }
                    _ => path,
                }
            }
            (Some(_), _) => Parts::unknown(),
            (None, "to_s" | "to_str" | "to_path" | "freeze" | "dup") if receiver.is_some() => {
                receiver.map_or_else(Parts::unknown, |receiver| self.parts(receiver, level + 1))
            }
            _ => Parts::unknown(),
        }
    }

    /// A literal string, or a command string (`` `…` ``, `%x(…)`), as the
    /// reader knows it: its text up to the first `#{…}` only known when it
    /// runs.
    fn literal(&mut self, node: Node<'_>, level: usize) -> Parts {
        let opening = node.child(0).map_or("", |open| self.text(open));
        let single = opening == "'" || opening.starts_with("%q");
        let mut text = String::new();
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        for child in children {
            match child.kind() {
                "string_content" => {
                    let content = self.text(child);
                    if single {
                        let open = opening.chars().last().unwrap_or('\'');
                        text.push_str(&unescape_single(content, open, closing(open)));
                    } else {
                        text.push_str(content);
                    }
                }
                "escape_sequence" => match unescape(self.text(child)) {
                    Some(Escape::Char(c)) => text.push(c),
                    // A backslash before a line's end is dropped with it.
                    Some(Escape::Dropped) => {}
                    None => return Parts::partial(text),
                },
                "interpolation" => {
                    let mut inner = child.walk();
                    let expressions: Vec<Node<'_>> = child.named_children(&mut inner).collect();
                    let [expression] = expressions.as_slice() else {
                        return Parts::partial(text);
                    };
                    let part = self.parts(*expression, level + 1);
                    text.push_str(&part.text);
                    if !part.whole {
                        return Parts::partial(text);
                    }
                }
                _ => return Parts::partial(text),
            }
        }
        Parts::whole(text)
    }

    /// The path `node` names, as a delete or a write takes it.
    fn arg(&mut self, node: Node<'_>) -> Arg {
        let parts = self.parts(node, 1);
        path(parts.value(), self.text(node))
    }

    /// The path `node` names, as a read takes it: a folder when only its
    /// start is known.
    fn read_arg(&mut self, node: Node<'_>) -> Arg {
        let parts = self.parts(node, 1);
        read_path(parts, self.text(node))
    }

    /// Each path `node` names: the elements of an array (`%w[a b]` too), or
    /// the one path.
    fn args(&mut self, node: Node<'_>, read: bool) -> Vec<Arg> {
        if node.kind() == "string_array" {
            let mut cursor = node.walk();
            let words: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
            return words
                .into_iter()
                .map(|word| {
                    let mut inner = word.walk();
                    let plain = word
                        .named_children(&mut inner)
                        .all(|part| part.kind() == "string_content");
                    let text = self.text(word);
                    if plain && !text.contains('\\') {
                        Arg::Known(text.to_string())
                    } else {
                        Arg::Unknown(super::shorten(text))
                    }
                })
                .collect();
        }
        if node.kind() == "array" {
            let mut cursor = node.walk();
            let elements: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
            return elements
                .into_iter()
                .map(|element| self.path_of(element, read))
                .collect();
        }
        vec![self.path_of(node, read)]
    }

    fn path_of(&mut self, node: Node<'_>, read: bool) -> Arg {
        if node.kind() == "splat_argument" {
            return Arg::Unknown(super::shorten(self.text(node)));
        }
        if read {
            self.read_arg(node)
        } else {
            self.arg(node)
        }
    }

    fn call(&mut self, call: Node<'_>) {
        let Some(method) = call.child_by_field_name("method") else {
            // `x.()`: a call of what the value holds.
            if call.child_by_field_name("receiver").is_some() {
                self.unread(call);
            }
            return;
        };
        let name = self.text(method).to_string();
        let args = arguments(call);
        let receiver = self.receiver(call);
        let named = match &receiver {
            Receiver::Kernel if self.fileutils && is_fileutils(&name) => "FileUtils".to_string(),
            Receiver::Kernel => String::new(),
            Receiver::Named(constant) => constant.clone(),
            Receiver::Path(_) | Receiver::Value => "?".to_string(),
        };
        if EVALS.contains(&name.as_str()) {
            self.eval(call, &args);
            return;
        }
        // A load path a `require` looks in, written (`$LOAD_PATH.unshift`).
        let load_path = call
            .child_by_field_name("receiver")
            .is_some_and(|receiver| {
                receiver.kind() == "global_variable"
                    && matches!(self.text(receiver), "$LOAD_PATH" | "$:" | "$-I")
            });
        // Code loaded from data: `YAML.unsafe_load`, `Marshal.load`.
        let unsafe_load = matches!(
            (named.as_str(), name.as_str()),
            ("YAML" | "Psych", "unsafe_load" | "unsafe_load_file")
                | ("Marshal", "load" | "restore")
        );
        if LOADS.contains(&name.as_str())
            || INDIRECT.contains(&name.as_str())
            || INDIRECT_RECEIVERS.contains(&named.as_str())
            || named.starts_with("RubyVM::")
            || load_path
            || unsafe_load
        {
            self.unread(call);
            return;
        }
        if let Receiver::Path(parts) = receiver {
            self.pathname_call(call, &name, parts, &args);
            return;
        }
        let acted = match (named.as_str(), name.as_str()) {
            ("" | "Process", run) if RUNS.contains(&run) => {
                self.spawn(call, &args);
                true
            }
            ("PTY", "spawn" | "getpty") => {
                self.spawn(call, &args);
                true
            }
            ("Open3", run) if OPEN3.contains(&run) => {
                self.spawn(call, &args);
                true
            }
            ("Open3", run) if PIPELINES.contains(&run) => {
                // Each command is a line, or an array of what `spawn` takes.
                for command in args
                    .iter()
                    .filter(|arg| !matches!(arg.kind(), "pair" | "hash"))
                {
                    if command.kind() == "array" {
                        let mut cursor = command.walk();
                        let words: Vec<Node<'_>> = command
                            .named_children(&mut cursor)
                            .filter(|word| !matches!(word.kind(), "pair" | "hash"))
                            .collect();
                        if let [program] = words.as_slice() {
                            let program = self.arg(*program);
                            self.act(Act::Program(vec![program]));
                        } else {
                            self.command(&words, call);
                        }
                    } else {
                        self.command(&[*command], call);
                    }
                }
                true
            }
            ("IO", "popen") => {
                self.popen(call, &args);
                true
            }
            ("Process", "kill") => {
                for pid in args.iter().skip(1) {
                    let text = self.text(*pid).to_string();
                    self.act(kill(&text));
                }
                true
            }
            ("" | "Signal", "trap") => {
                let command = args.get(1).map(|arg| self.parts(*arg, 1));
                if command.is_some_and(|command| !TRAP_WORDS.contains(&command.text.as_str())) {
                    self.unread(call);
                }
                true
            }
            ("File", "delete" | "unlink") => {
                for arg in &args {
                    let paths = self.args(*arg, false);
                    for path in paths {
                        self.act(Act::Remove(path));
                    }
                }
                true
            }
            ("FileUtils", remove) if FILEUTILS_REMOVE.contains(&remove) => {
                self.each(&args, 0, false, Act::Remove);
                true
            }
            ("Dir", "rmdir" | "delete" | "unlink") => {
                self.each(&args, 0, false, Act::Remove);
                true
            }
            ("File" | "IO", "write" | "binwrite") => {
                if !self.piped(call, &args, named == "IO") && !self.command_path(call, &args) {
                    self.each(&args, 0, false, Act::Write);
                }
                true
            }
            ("File" | "IO", "read" | "binread" | "readlines" | "foreach") => {
                if !self.piped(call, &args, named == "IO") && !self.command_path(call, &args) {
                    // They open the file with the mode they are given, which
                    // truncates it for one that writes.
                    if self.opens_for_write(&args) {
                        self.each(&args, 0, false, Act::Write);
                    } else {
                        self.each(&args, 0, true, Act::Read);
                    }
                }
                true
            }
            ("File", "open" | "new") => {
                self.open(call, &args, false);
                true
            }
            ("" | "URI", "open") => {
                self.open(call, &args, true);
                true
            }
            ("File", "truncate" | "mkfifo") | ("Dir", "mkdir") => {
                self.each(&args, 0, false, Act::Write);
                true
            }
            ("FileUtils", make) if FILEUTILS_MAKE.contains(&make) => {
                self.each(&args, 0, false, Act::Write);
                true
            }
            ("FileUtils", copy) if FILEUTILS_COPY.contains(&copy) => {
                let tree = matches!(copy, "cp_r" | "copy_entry" | "cp_lr");
                if let Some(from) = args.first() {
                    for source in self.args(*from, true) {
                        self.act(if tree {
                            Act::ReadTree(source)
                        } else {
                            Act::Read(source)
                        });
                    }
                }
                self.each(&args, 1, false, Act::Write);
                true
            }
            ("File" | "IO", "copy_stream") => {
                // Only paths: an `IO` given is no file the call opens.
                if let Some(from) = args.first().filter(|arg| arg.kind() == "string") {
                    let source = self.read_arg(*from);
                    self.act(Act::Read(source));
                }
                if let Some(to) = args.get(1).filter(|arg| arg.kind() == "string") {
                    let target = self.arg(*to);
                    self.act(Act::Write(target));
                }
                true
            }
            ("File", "rename") | ("FileUtils", "mv" | "move") => {
                if let (Some(from), Some(to)) = (args.first(), args.get(1)) {
                    let target = self.arg(*to);
                    for source in self.args(*from, false) {
                        self.act(Act::Move {
                            from: source,
                            to: target.clone(),
                        });
                    }
                }
                true
            }
            ("File", "symlink" | "link") => {
                if let (Some(target), Some(link)) = (args.first(), args.get(1)) {
                    let target = self.arg(*target);
                    let link = self.arg(*link);
                    self.act(Act::Link { target, link });
                }
                true
            }
            ("FileUtils", link) if FILEUTILS_LINK.contains(&link) => {
                if let (Some(targets), Some(link)) = (args.first(), args.get(1)) {
                    let link = self.arg(*link);
                    for target in self.args(*targets, false) {
                        self.act(Act::Link {
                            target,
                            link: link.clone(),
                        });
                    }
                }
                true
            }
            ("File" | "FileUtils", "chmod" | "lchmod" | "chmod_R") => {
                if let Some(given) = args.first() {
                    let given_mode = self.mode_of(*given);
                    for arg in args.iter().skip(1) {
                        for path in self.args(*arg, false) {
                            self.act(Act::Chmod {
                                path,
                                mode: given_mode.clone(),
                            });
                        }
                    }
                }
                true
            }
            ("File" | "FileUtils", "chown" | "lchown" | "chown_R") => {
                for arg in args.iter().skip(2) {
                    for path in self.args(*arg, false) {
                        self.act(Act::Chown(path));
                    }
                }
                true
            }
            ("Dir" | "FileUtils", "chdir" | "cd") => {
                let to = match args.first() {
                    Some(dir) => self.arg(*dir),
                    None => Arg::Known("~".to_string()),
                };
                self.act(Act::Chdir(to));
                true
            }
            ("ENV", _) => {
                if !matches!(
                    name.as_str(),
                    "[]" | "fetch"
                        | "key?"
                        | "has_key?"
                        | "include?"
                        | "keys"
                        | "values"
                        | "to_h"
                        | "each"
                        | "map"
                        | "select"
                        | "filter"
                        | "reject"
                        | "empty?"
                        | "size"
                        | "length"
                        | "dig"
                ) {
                    self.act(Act::Environment);
                }
                true
            }
            ("" | "?", harmless) if HARMLESS.contains(&harmless) => true,
            ("File" | "Dir", names) if NAMES_ONLY.contains(&names) => true,
            ("Pathname", "new") | ("", "Pathname") => true,
            _ => false,
        };
        if !acted {
            self.opaque(&args);
        }
    }

    /// A path given to a call the reader has no row for: it may open it.
    fn opaque(&mut self, args: &[Node<'_>]) {
        for arg in args {
            if arg.kind() != "string" {
                continue;
            }
            if let Some(found) = self.parts(*arg, 1).value().as_deref().and_then(named_path) {
                self.act(Act::Opaque(found));
            }
        }
    }

    /// The paths from the argument `at` on, each made into an act.
    fn each(&mut self, args: &[Node<'_>], at: usize, read: bool, act: fn(Arg) -> Act) {
        let Some(arg) = args.get(at) else {
            return;
        };
        for path in self.args(*arg, read) {
            self.act(act(path));
        }
    }

    /// `IO.read("|cmd")` and the other class methods of `IO` (`piped`) run a
    /// command when the path starts with `|`; one only known when it runs
    /// may. Whether `call` was such a run.
    fn piped(&mut self, call: Node<'_>, args: &[Node<'_>], piped: bool) -> bool {
        if !piped {
            return false;
        }
        let Some(first) = args.first() else {
            return false;
        };
        let parts = self.parts(*first, 1);
        if let Some(command) = parts.text.strip_prefix('|') {
            let command = if parts.whole {
                Arg::Known(command.to_string())
            } else {
                Arg::Unknown(super::shorten(self.text(call)))
            };
            self.act(Act::Script(command));
            return true;
        }
        if parts.text.is_empty() && !parts.whole {
            self.act(Act::Script(Arg::Unknown(super::shorten(self.text(call)))));
            return true;
        }
        false
    }

    /// A path of `File`'s class methods that starts with `|`, which Ruby 2.5
    /// and before, and `JRuby`, run as a command: whether `call` was such a run.
    fn command_path(&mut self, call: Node<'_>, args: &[Node<'_>]) -> bool {
        let Some(first) = args.first() else {
            return false;
        };
        let parts = self.parts(*first, 1);
        let Some(command) = parts.text.strip_prefix('|') else {
            return false;
        };
        let command = if parts.whole {
            Arg::Known(command.to_string())
        } else {
            Arg::Unknown(super::shorten(self.text(call)))
        };
        self.act(Act::Script(command));
        true
    }

    /// Whether the options a read (`File.read`, `readlines`, `foreach`) is
    /// given open the file for writing, or may: a `mode` that is not a string
    /// of a mode that only reads (a number is flags), `flags`, `open_args`,
    /// or a hash only known when it runs, wherever they are given (`mode:`,
    /// `:mode =>`, `{mode: …}`).
    fn opens_for_write(&mut self, args: &[Node<'_>]) -> bool {
        let mut pairs: Vec<Node<'_>> = Vec::new();
        for arg in args.iter().skip(1) {
            match arg.kind() {
                "pair" => pairs.push(*arg),
                "hash" => {
                    let mut cursor = arg.walk();
                    for child in arg.named_children(&mut cursor) {
                        if child.kind() == "pair" {
                            pairs.push(child);
                        } else {
                            return true;
                        }
                    }
                }
                // A literal that is no hash is a length, an offset or a
                // separator; any other value may be the hash of a mode.
                "string" | "integer" | "nil" | "block_argument" => {}
                _ => return true,
            }
        }
        pairs.into_iter().any(|pair| {
            let Some(key) = pair.child_by_field_name("key") else {
                return true;
            };
            match key_name(key, self.src) {
                "mode" => pair.child_by_field_name("value").is_none_or(|value| {
                    value.kind() != "string"
                        || self
                            .parts(value, 1)
                            .value()
                            .is_none_or(|text| writes(Some(&text)))
                }),
                "flags" | "open_args" => true,
                _ => false,
            }
        })
    }

    /// `open(path, mode)`: `File.open` (`piped` false) or `Kernel#open` and
    /// `URI.open`, which run a command when the path starts with `|`, and
    /// fetch a URL.
    fn open(&mut self, call: Node<'_>, args: &[Node<'_>], piped: bool) {
        let Some(first) = args.first() else {
            return;
        };
        if self.piped(call, args, piped) {
            return;
        }
        let parts = self.parts(*first, 1);
        let lower = parts.text.to_ascii_lowercase();
        if piped
            && ["http://", "https://", "ftp://"]
                .iter()
                .any(|scheme| lower.starts_with(scheme))
        {
            return;
        }
        let given = args.iter().skip(1).find_map(|arg| match arg.kind() {
            "pair" => arg
                .child_by_field_name("key")
                .filter(|key| key_name(*key, self.src) == "mode")
                .and_then(|_| arg.child_by_field_name("value")),
            "hash" | "block_argument" => None,
            _ => Some(*arg),
        });
        let write = match given {
            None => false,
            Some(given) => match self.parts(given, 1).value() {
                Some(text) => writes(Some(&text)),
                // A mode only known when it runs, or flags, may write.
                None => true,
            },
        };
        // `flags: File::TRUNC` and the like: flags that are not only
        // `RDONLY` may write.
        let mut pairs: Vec<Node<'_>> = Vec::new();
        for arg in args.iter().skip(1) {
            match arg.kind() {
                "pair" => pairs.push(*arg),
                "hash" => {
                    let mut cursor = arg.walk();
                    pairs.extend(
                        arg.named_children(&mut cursor)
                            .filter(|n| n.kind() == "pair"),
                    );
                }
                _ => {}
            }
        }
        let flagged = pairs.iter().any(|pair| {
            pair.child_by_field_name("key")
                .is_some_and(|key| key_name(key, self.src) == "flags")
                && pair.child_by_field_name("value").is_none_or(|value| {
                    !matches!(
                        self.text(value).trim_start_matches("::"),
                        "File::RDONLY" | "IO::RDONLY" | "0"
                    )
                })
        });
        let write = write || flagged;
        let source = self.text(*first).to_string();
        if write {
            self.act(Act::Write(path(parts.value(), &source)));
        } else {
            self.act(Act::Read(read_path(parts, &source)));
        }
    }

    /// The mode `chmod` is given: octal for a number.
    fn mode_of(&mut self, node: Node<'_>) -> Arg {
        let text = self.text(node).to_string();
        if node.kind() == "integer" {
            if let Some(octal) = mode(&text) {
                return Arg::Known(octal);
            }
        }
        match self.parts(node, 1).value() {
            Some(value) => Arg::Known(value),
            None => Arg::Unknown(super::shorten(&text)),
        }
    }

    /// A call of a `Pathname`'s method.
    fn pathname_call(&mut self, call: Node<'_>, name: &str, parts: Parts, args: &[Node<'_>]) {
        let source = self.text(call).to_string();
        match name {
            "delete" | "unlink" | "rmtree" | "rmdir" => {
                self.act(Act::Remove(path(parts.value(), &source)));
            }
            "write" | "binwrite" | "mkdir" | "mkpath" | "truncate" => {
                self.act(Act::Write(path(parts.value(), &source)));
            }
            "read" | "binread" | "readlines" | "each_line" => {
                self.act(Act::Read(read_path(parts, &source)));
            }
            "open" => {
                let write = args.first().is_some_and(|given| {
                    self.parts(*given, 1)
                        .value()
                        .is_none_or(|text| writes(Some(&text)))
                });
                if write {
                    self.act(Act::Write(path(parts.value(), &source)));
                } else {
                    self.act(Act::Read(read_path(parts, &source)));
                }
            }
            "rename" => {
                if let Some(to) = args.first() {
                    let to = self.arg(*to);
                    self.act(Act::Move {
                        from: path(parts.value(), &source),
                        to,
                    });
                }
            }
            "make_symlink" | "make_link" => {
                if let Some(target) = args.first() {
                    let target = self.arg(*target);
                    self.act(Act::Link {
                        target,
                        link: path(parts.value(), &source),
                    });
                }
            }
            "chmod" | "lchmod" => {
                if let Some(given) = args.first() {
                    let mode = self.mode_of(*given);
                    self.act(Act::Chmod {
                        path: path(parts.value(), &source),
                        mode,
                    });
                }
            }
            "chown" | "lchown" => self.act(Act::Chown(path(parts.value(), &source))),
            // What only works a path out, or asks what is there.
            "join" | "+" | "/" | "parent" | "dirname" | "basename" | "extname" | "to_s"
            | "to_path" | "expand_path" | "cleanpath" | "sub_ext" | "exist?" | "file?"
            | "directory?" | "absolute?" | "relative?" | "size" | "mtime" => {}
            _ => {
                // A path handed to a method the reader has no row for.
                if let Some(found) = parts.value().as_deref().and_then(named_path) {
                    self.act(Act::Opaque(found));
                }
            }
        }
    }

    /// `eval(code)` and the methods that evaluate a string: code of a
    /// literal is a `Code` act, read again; code fetched from the network
    /// is downloaded and run; any other is not read.
    fn eval(&mut self, call: Node<'_>, args: &[Node<'_>]) {
        let Some(first) = args.first() else {
            // `x.instance_eval { … }`: the block is read where it is.
            return;
        };
        if first.kind() == "string" {
            let parts = self.literal(*first, 1);
            if parts.whole {
                self.act(Act::Code(Language::Ruby, parts.text));
                return;
            }
        }
        if self.fetches(*first) {
            let shown = super::shorten(self.text(call));
            self.act(Act::Downloaded(shown));
            return;
        }
        self.unread(call);
    }

    /// `system`, `exec`, `spawn` and the calls that take their arguments.
    fn spawn(&mut self, call: Node<'_>, args: &[Node<'_>]) {
        let mut given = args;
        // An environment the program is given.
        let environed = given.first().is_some_and(|first| first.kind() == "hash");
        if environed {
            given = &given[1..];
        }
        let words: Vec<Node<'_>> = given
            .iter()
            .copied()
            .filter(|arg| !matches!(arg.kind(), "pair" | "hash" | "block_argument"))
            .collect();
        let before = self.reading.acts.len();
        self.command(&words, call);
        self.options(given, before, environed);
    }

    /// What a command a call starts is: one string is a line a shell reads,
    /// more are a program and its arguments, the first of them an array
    /// `[program, argv0]`.
    fn command(&mut self, words: &[Node<'_>], call: Node<'_>) {
        let shown = super::shorten(self.text(call));
        if words.iter().any(|word| word.kind() == "splat_argument") {
            self.act(Act::Script(Arg::Unknown(shown)));
            return;
        }
        match words {
            [] => {}
            [single] if single.kind() != "array" => {
                let script = self.arg(*single);
                self.act(Act::Script(script));
            }
            [first, rest @ ..] => {
                let program = if first.kind() == "array" {
                    let mut cursor = first.walk();
                    let elements: Vec<Node<'_>> = first.named_children(&mut cursor).collect();
                    match elements.first() {
                        Some(program) => self.arg(*program),
                        None => Arg::Unknown(shown),
                    }
                } else {
                    self.arg(*first)
                };
                let mut program_words = vec![program];
                for word in rest {
                    let word = self.arg(*word);
                    program_words.push(word);
                }
                self.act(Act::Program(program_words));
            }
        }
    }

    /// The options of a call that starts a program, for the acts it added
    /// from `before` on: `chdir:` runs them from that directory, a file the
    /// program's output or input is redirected to is written or read, and
    /// an environment given makes them a program started with one.
    fn options(&mut self, given: &[Node<'_>], before: usize, environed: bool) {
        let mut pairs: Vec<Node<'_>> = Vec::new();
        for arg in given {
            match arg.kind() {
                "pair" => pairs.push(*arg),
                "hash" => {
                    let mut cursor = arg.walk();
                    pairs.extend(
                        arg.named_children(&mut cursor)
                            .filter(|n| n.kind() == "pair"),
                    );
                }
                _ => {}
            }
        }
        let mut dir = None;
        let mut redirects = Vec::new();
        for pair in pairs {
            let (Some(key), Some(value)) = (
                pair.child_by_field_name("key"),
                pair.child_by_field_name("value"),
            ) else {
                continue;
            };
            let key = key_name(key, self.src).to_string();
            match key.as_str() {
                "chdir" => dir = Some(self.arg(value)),
                "unsetenv_others" | "pgroup" | "new_pgroup" | "umask" | "close_others"
                | "exception" | "binmode" | "external_encoding" | "internal_encoding"
                | "encoding" | "stdin_data" | "textmode" => {}
                key if key.starts_with("rlimit_") => {}
                _ => {
                    // A redirect: `out: "f"`, `[:out, :err] => "f"`, `2 => "f"`,
                    // `out: ["f", "w"]`; `in:` is read.
                    let target = match value.kind() {
                        "string" => Some(value),
                        "array" => value
                            .named_child(0)
                            .filter(|first| first.kind() == "string"),
                        _ => None,
                    };
                    if let Some(target) = target {
                        let input = key == "in" || key == "0" || key == "STDIN";
                        let path = if input {
                            Act::Read(self.read_arg(target))
                        } else {
                            Act::Write(self.arg(target))
                        };
                        redirects.push(path);
                    }
                }
            }
        }
        let mut acts: Vec<Act> = self.reading.acts.drain(before..).collect();
        acts.extend(redirects);
        if environed {
            acts = vec![Act::Started(acts)];
        }
        if let Some(dir) = dir {
            acts = vec![Act::In(dir, acts)];
        }
        self.reading.acts.extend(acts);
    }

    /// `IO.popen([env,] command, mode, options)`: a string is a line a shell
    /// reads (`"-"` forks the interpreter itself), an array a program and its
    /// arguments, an environment first and options last among them.
    fn popen(&mut self, call: Node<'_>, args: &[Node<'_>]) {
        let mut given = args;
        let environed = given.first().is_some_and(|first| first.kind() == "hash");
        if environed {
            given = &given[1..];
        }
        let before = self.reading.acts.len();
        let mut options: Vec<Node<'_>> = given.get(1..).unwrap_or_default().to_vec();
        let mut environed = environed;
        match given.first() {
            Some(command) if command.kind() == "array" => {
                let mut cursor = command.walk();
                let mut elements: Vec<Node<'_>> = command.named_children(&mut cursor).collect();
                if elements.first().is_some_and(|first| first.kind() == "hash") {
                    elements.remove(0);
                    environed = true;
                }
                let (inner, words): (Vec<Node<'_>>, Vec<Node<'_>>) = elements
                    .into_iter()
                    .partition(|element| matches!(element.kind(), "pair" | "hash"));
                options.extend(inner);
                if let [program] = words.as_slice() {
                    // `IO.popen(["ls"])` runs `ls` without a shell.
                    let program = self.arg(*program);
                    self.act(Act::Program(vec![program]));
                } else {
                    self.command(&words, call);
                }
            }
            // `IO.popen("-")` forks the interpreter itself.
            Some(command) if self.parts(*command, 1).value().as_deref() == Some("-") => {}
            Some(command) => self.command(&[*command], call),
            None => {}
        }
        self.options(&options, before, environed);
    }
}

/// Whether `name` is a call of `FileUtils` that acts on files.
fn is_fileutils(name: &str) -> bool {
    FILEUTILS_REMOVE.contains(&name)
        || FILEUTILS_MAKE.contains(&name)
        || FILEUTILS_COPY.contains(&name)
        || FILEUTILS_LINK.contains(&name)
        || matches!(
            name,
            "mv" | "move" | "chmod" | "chmod_R" | "chown" | "chown_R" | "cd" | "chdir"
        )
}

/// The byte that closes a `%` literal opened by `open`.
fn closing(open: char) -> char {
    match open {
        '(' => ')',
        '[' => ']',
        '{' => '}',
        '<' => '>',
        other => other,
    }
}

/// The text of a single-quoted string as Ruby reads it: `\\` is a backslash
/// and a backslash before its delimiters (the quote, or a `%q` literal's
/// opening and closing ones) is the delimiter; any other backslash is
/// itself.
fn unescape_single(content: &str, open: char, close: char) -> String {
    let mut text = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if next == '\\' || next == open || next == close {
                    text.push(next);
                    chars.next();
                    continue;
                }
            }
        }
        text.push(c);
    }
    text
}

/// What an escape of a double-quoted string stands for.
enum Escape {
    Char(char),
    Dropped,
}

/// The character an escape of a double-quoted string stands for, where it
/// is one character the reader knows, or none for a backslash before a
/// line's end, which Ruby drops with it; `None` for a code (`\x41`,
/// `\u{…}`, `\101`, `\C-a`), which the reader does not work out.
fn unescape(escape: &str) -> Option<Escape> {
    let mut chars = escape.chars();
    if chars.next() != Some('\\') {
        return None;
    }
    let c = chars.next()?;
    let rest = chars.as_str();
    if c == '\n' && rest.is_empty() || c == '\r' && rest == "\n" {
        return Some(Escape::Dropped);
    }
    if !rest.is_empty() {
        return None;
    }
    Some(Escape::Char(match c {
        'n' => '\n',
        't' => '\t',
        's' => ' ',
        'r' => '\r',
        'e' => '\u{1b}',
        'a' => '\u{7}',
        'b' => '\u{8}',
        'f' => '\u{c}',
        'v' => '\u{b}',
        'u' | 'x' | 'C' | 'M' | 'c' | '0'..='7' => return None,
        other => other,
    }))
}
