//! The one gate in front of the inline readers: whether a piece of code is
//! read whole, so that a line with nothing found in it is safe.
//!
//! The readers find the calls that delete, write, move and run, and the paths
//! they name. What they find is kept whatever the code looks like. But a line
//! whose code they find nothing in is only safe when the code is nothing else
//! than a few plain statements the guard reads in full: an allow-list of what
//! the grammar may hold, not a list of what is known to be dangerous. Code
//! that has anything else in it (a function, a class, a loop, an import off
//! the list, a call off the list, a name nothing bound) is `unknown`, because
//! the reader has no row for what it does.
//!
//! The subset, for Python and for JavaScript alike:
//!
//! - it parses, and holds at least one statement;
//! - its statements are expression statements, assignments to a plain name
//!   and `if`/`else`, so the code runs straight through;
//! - its calls are on a short list that only computes (`print`, `len`, `str`,
//!   `time.time`, `console.log`, `Math.max`, the methods of a string or a
//!   list), or `open` in Python, which the reader judges by its path and mode;
//! - its imports are the modules built into the interpreter binary (`sys`,
//!   `errno`, `itertools`, `time`) in Python 3, and `sys` and `errno` alone in
//!   Python 2, which no file in the folder the code runs in can stand in for,
//!   and it has no import, `require` or `eval` in JavaScript;
//! - it names nothing that is not a name it set, a call on the list or a
//!   module on the list that it imported (JavaScript's are always there), and
//!   sets none of those;
//! - it reaches into nothing: no attribute that starts with an underscore, and
//!   in JavaScript no member other than `length` and the methods on the list.

use std::collections::HashSet;

use tree_sitter::Node;

use super::{walk, Ancestor, Language};
use crate::unit::{Budget, Parsed, MAX_TREE_DEPTH};

/// Whether `code` is read whole: nothing in it is outside the subset above.
/// `None` when it is not; when it is, `Some(true)` if it may load a module,
/// which looks in the folder the code runs in first (all Python code does,
/// with or without an `import`).
/// The code is parsed within `budget`: code whose parse is stopped is not
/// read whole.
pub(super) fn reads_whole(language: Language, code: &str, budget: &Budget) -> Option<bool> {
    if has_odd_character(code) {
        return None;
    }
    match language {
        Language::Python => python(code, false, budget),
        Language::JavaScript => javascript(code, budget).then_some(false),
        #[cfg(feature = "ruby")]
        Language::Ruby => ruby(code, budget).then_some(false),
        #[cfg(not(feature = "ruby"))]
        Language::Ruby => None,
    }
}

/// [`reads_whole`] for Python 2, which has fewer modules built in.
pub(super) fn reads_whole_python2(code: &str, budget: &Budget) -> Option<bool> {
    if has_odd_character(code) {
        return None;
    }
    python(code, true, budget)
}

/// Whether a node with `above` over it is within [`MAX_TREE_DEPTH`]: the
/// readers stop walking past it (`deep`), so the acts of code nested deeper
/// are not all found, and such code is never read whole.
fn shallow(above: &[Ancestor<'_>]) -> bool {
    above.len() <= MAX_TREE_DEPTH
}

/// Whether `code` holds a control character other than a newline or a tab,
/// or a line separator the grammars and the interpreters read differently.
fn has_odd_character(code: &str) -> bool {
    code.chars().any(|c| {
        (c.is_control() && !matches!(c, '\n' | '\t')) || matches!(c, '\u{2028}' | '\u{2029}')
    })
}

/// The calls of a name alone that compute and touch nothing, and `open`,
/// whose path and mode the reader judges.
const PYTHON_CALLS: [&str; 40] = [
    "print",
    "len",
    "str",
    "int",
    "float",
    "bool",
    "repr",
    "abs",
    "min",
    "max",
    "sum",
    "round",
    "sorted",
    "reversed",
    "list",
    "tuple",
    "dict",
    "set",
    "frozenset",
    "range",
    "enumerate",
    "zip",
    "any",
    "all",
    "ord",
    "chr",
    "hex",
    "bin",
    "oct",
    "divmod",
    "pow",
    "bytes",
    "bytearray",
    "format",
    "ascii",
    "iter",
    "next",
    "open",
    "complex",
    "slice",
];

/// The modules an import may name in Python 3, and the names the code may not
/// set: the ones the `Modules/Setup.bootstrap` of `CPython` compiles into the
/// interpreter binary (`errno`, `itertools`, `time`) and `sys`, which is the
/// interpreter itself. The import system tries the built-in finder before it
/// looks at the import path, so no file in the folder the code runs in can
/// stand in for one of them, and importing one reads nothing from disk. Every
/// other module (`json`, `re`, `math`, which is a file on many builds, and the
/// modules each of them loads in turn) is looked up in that folder first, and
/// an import of one makes the code not read whole. `builtins` is not on the
/// list: it is `__builtin__` in Python 2, so a planted `./builtins.py` would
/// run there, and code may use none of its members anyway.
const PYTHON_MODULES: [&str; 4] = ["errno", "itertools", "sys", "time"];

/// The modules an import may name in Python 2, where only `sys` and `errno`
/// are built into the binary: `time` and `itertools` are shared files of
/// `lib-dynload`, which the import path reaches after the folder the code
/// runs in.
const PYTHON2_MODULES: [&str; 2] = ["errno", "sys"];

/// The modules an import may name, for Python 2 or Python 3.
fn python_modules(python2: bool) -> &'static [&'static str] {
    if python2 {
        &PYTHON2_MODULES
    } else {
        &PYTHON_MODULES
    }
}

/// Whether `module.name` is a member the code may use, as a call or not.
fn python_member(module: &str, name: &str, call: bool) -> bool {
    match module {
        "errno" => !call,
        "sys" => !call && matches!(name, "stdin" | "argv" | "version"),
        "time" => {
            call && matches!(
                name,
                "time" | "time_ns" | "monotonic" | "monotonic_ns" | "perf_counter"
            )
        }
        // `itertools` builds lazy iterators: importing it is read whole and
        // using it is not.
        _ => false,
    }
}

/// Whether a name is plain ASCII letters, digits, `_` and `$`: Python reads a
/// name in its NFKC form (a full-width `＿＿class＿＿` is `__class__`) and
/// JavaScript reads an escape in one (`console`), so a name written any
/// other way is not the name the checks above see.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
}

fn text<'a>(node: Node<'_>, code: &'a str) -> &'a str {
    code.get(node.byte_range()).unwrap_or_default()
}

/// Whether the tree holds a statement that is not a comment.
fn has_statement(root: Node<'_>) -> bool {
    let mut cursor = root.walk();
    let found = root
        .named_children(&mut cursor)
        .any(|child| child.kind() != "comment");
    found
}

/// Python code that is read whole, and whether it imports a module.
fn python(code: &str, python2: bool, budget: &Budget) -> Option<bool> {
    let Parsed::Tree(tree) = crate::python::parse(budget, code) else {
        return None;
    };
    let root = tree.root_node();
    if !has_statement(root) {
        return None;
    }
    // The names the code sets, none of which may be a name the reader gives a
    // meaning to, and the modules it imports: a member of a module is only
    // read once the code has named the module.
    let mut assigned = HashSet::new();
    let mut imported = HashSet::new();
    let mut clean = true;
    walk(budget, root, |node, _, _| {
        if node.kind() == "import_statement" {
            let mut cursor = node.walk();
            for name in node.named_children(&mut cursor) {
                imported.insert(text(name, code).to_string());
            }
        }
        let left = match node.kind() {
            "assignment" | "augmented_assignment" => node.child_by_field_name("left"),
            _ => None,
        };
        if let Some(left) = left {
            walk(budget, left, |name, _, _| {
                if name.kind() == "identifier" {
                    let name = text(name, code);
                    clean &= plain_name(name)
                        && !name.starts_with('_')
                        && !PYTHON_CALLS.contains(&name)
                        && !PYTHON_MODULES.contains(&name)
                        // Names of modules that were once importable.
                        && !matches!(name, "json" | "math" | "re");
                    assigned.insert(name.to_string());
                }
                true
            });
        }
        clean
    });
    if !clean {
        return None;
    }
    let mut whole = true;
    walk(budget, root, |node, field, above| {
        whole =
            shallow(above) && python_node(node, field, above, code, &assigned, &imported, python2);
        whole
    });
    // Python loads modules from the folder it runs in without an import
    // statement: an uncaught exception imports `traceback`, the `idna` codec
    // imports `stringprep` and `unicodedata`. So any Python code read whole
    // counts as importing.
    whole.then_some(true)
}

fn python_node(
    node: Node<'_>,
    field: Option<&str>,
    above: &[Ancestor<'_>],
    code: &str,
    assigned: &HashSet<String>,
    imported: &HashSet<String>,
    python2: bool,
) -> bool {
    // A token (`(`, `,`, an operator) is the business of the node it is in.
    if !node.is_named() {
        return true;
    }
    let modules = python_modules(python2);
    let parent = above.last().map(|ancestor| ancestor.node.kind());
    match node.kind() {
        "module"
        | "comment"
        | "expression_statement"
        | "if_statement"
        | "elif_clause"
        | "else_clause"
        | "integer"
        | "float"
        | "true"
        | "false"
        | "none"
        | "string"
        | "string_start"
        | "string_content"
        | "string_end"
        | "escape_sequence"
        | "escape_interpolation"
        | "interpolation"
        | "type_conversion"
        | "format_specifier"
        | "format_expression"
        | "concatenated_string"
        | "list"
        | "tuple"
        | "dictionary"
        | "set"
        | "pair"
        | "binary_operator"
        | "unary_operator"
        | "boolean_operator"
        | "comparison_operator"
        | "not_operator"
        | "parenthesized_expression"
        | "subscript"
        | "slice"
        | "conditional_expression"
        | "argument_list"
        | "keyword_argument"
        | "expression_list"
        | "pattern_list"
        | "tuple_pattern"
        | "list_pattern" => true,
        // A block holds a statement: the grammar lets `if 1:` end the code.
        "block" => {
            let mut cursor = node.walk();
            let filled = node
                .named_children(&mut cursor)
                .any(|child| child.kind() != "comment");
            filled
        }
        "assignment" => {
            node.child_by_field_name("type").is_none()
                && node.child_by_field_name("right").is_some()
                && node.child_by_field_name("left").is_some_and(|left| {
                    matches!(
                        left.kind(),
                        "identifier" | "pattern_list" | "tuple_pattern" | "list_pattern"
                    )
                })
        }
        "augmented_assignment" => node
            .child_by_field_name("left")
            .is_some_and(|left| left.kind() == "identifier"),
        "import_statement" => {
            let mut cursor = node.walk();
            let all = node
                .named_children(&mut cursor)
                .all(|name| name.kind() == "dotted_name" && modules.contains(&text(name, code)));
            all
        }
        "dotted_name" => parent == Some("import_statement"),
        "identifier" => {
            let name = text(node, code);
            plain_name(name)
                && match (parent, field) {
                    (Some("dotted_name"), _) => true,
                    (Some("call"), Some("function")) => {
                        PYTHON_CALLS.contains(&name) && !assigned.contains(name)
                    }
                    // A module is a name once the code imports it.
                    (Some("attribute"), Some("object")) => {
                        imported.contains(name) || assigned.contains(name)
                    }
                    (Some("attribute"), Some("attribute")) => !name.starts_with('_'),
                    (Some("keyword_argument"), Some("name")) => true,
                    _ => assigned.contains(name),
                }
        }
        "attribute" => {
            let (Some(object), Some(attribute)) = (
                node.child_by_field_name("object"),
                node.child_by_field_name("attribute"),
            ) else {
                return false;
            };
            let name = text(attribute, code);
            let call = parent == Some("call") && field == Some("function");
            if name.starts_with('_') {
                return false;
            }
            if object.kind() == "identifier" && modules.contains(&text(object, code)) {
                return python_member(text(object, code), name, call);
            }
            true
        }
        "call" => node
            .child_by_field_name("function")
            .is_some_and(|function| matches!(function.kind(), "identifier" | "attribute")),
        _ => false,
    }
}

/// The calls of a name alone that only compute and print, in Ruby.
#[cfg(feature = "ruby")]
const RUBY_CALLS: [&str; 8] = [
    "puts", "print", "p", "format", "sprintf", "Integer", "Float", "String",
];

/// The methods of a value Ruby code made (a string, a number, an array, a
/// hash) the code may call.
#[cfg(feature = "ruby")]
const RUBY_METHODS: [&str; 71] = [
    "to_s",
    "to_i",
    "to_f",
    "to_a",
    "inspect",
    "length",
    "size",
    "upcase",
    "downcase",
    "capitalize",
    "swapcase",
    "strip",
    "lstrip",
    "rstrip",
    "chomp",
    "chop",
    "chars",
    "bytes",
    "lines",
    "split",
    "join",
    "reverse",
    "include?",
    "start_with?",
    "end_with?",
    "index",
    "rindex",
    "count",
    "sub",
    "gsub",
    "tr",
    "center",
    "ljust",
    "rjust",
    "first",
    "last",
    "min",
    "max",
    "sum",
    "sort",
    "uniq",
    "zero?",
    "even?",
    "odd?",
    "abs",
    "round",
    "floor",
    "ceil",
    "push",
    "pop",
    "shift",
    "unshift",
    "empty?",
    "nil?",
    "succ",
    "pred",
    "ord",
    "chr",
    "keys",
    "values",
    "key?",
    "freeze",
    "frozen?",
    "between?",
    "divmod",
    "pow",
    "concat",
    "squeeze",
    "flatten",
    "compact",
    "hex",
];

/// The methods of `File` the code may call: the ones that read or write the
/// one file they are given.
#[cfg(feature = "ruby")]
const RUBY_FILE_METHODS: [&str; 5] = ["read", "readlines", "write", "exist?", "file?"];

/// Whether a call of `File`'s methods names the one file it opens by a string
/// written whole (no `#{`, no escape: `"\x7c"` is `|`) that does not start
/// with `|`, and gives it options that only read: `read` and `readlines` take
/// a hash of `chomp`, `encoding`, `external_encoding` and `binmode` only (any
/// other key may be a `mode` or `flags` that writes, and a hash splat or a
/// hash only known when it runs may hold them).
#[cfg(feature = "ruby")]
fn ruby_file_call(call: Node<'_>, code: &str) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    let mut args = arguments.named_children(&mut cursor);
    let Some(path) = args.next() else {
        return false;
    };
    let path_text = text(path, code);
    if path.kind() != "string"
        || path_text.contains(['\\', '#'])
        || path_text
            .get(1..)
            .is_some_and(|inner| inner.starts_with('|'))
    {
        return false;
    }
    let reads = call
        .child_by_field_name("method")
        .is_some_and(|method| matches!(text(method, code), "read" | "readlines"));
    let reading_key = |pair: Node<'_>| {
        pair.child_by_field_name("key").is_some_and(|key| {
            matches!(
                text(key, code)
                    .trim_start_matches(':')
                    .trim_end_matches(':')
                    .trim_matches(['"', '\'']),
                "chomp" | "encoding" | "external_encoding" | "binmode"
            )
        })
    };
    args.all(|arg| match arg.kind() {
        "pair" => !reads || reading_key(arg),
        "hash" => {
            let mut inner = arg.walk();
            let all = arg
                .named_children(&mut inner)
                .all(|pair| pair.kind() == "pair" && (!reads || reading_key(pair)));
            all
        }
        "hash_splat_argument" | "block_argument" => false,
        // A read is given its length, its offset, a separator and its options
        // only as literals: any other value (a local, a call, a conditional)
        // may be the hash of a mode that writes, which Ruby 2 takes for
        // keywords.
        "string" | "integer" | "nil" => true,
        _ => !reads,
    })
}

/// Whether `Math.name`, or `Math::name` (`constant`), is a member Ruby code
/// may use.
#[cfg(feature = "ruby")]
fn ruby_math(name: &str, constant: bool) -> bool {
    if constant {
        return matches!(name, "PI" | "E");
    }
    matches!(
        name,
        "sqrt"
            | "cbrt"
            | "sin"
            | "cos"
            | "tan"
            | "atan"
            | "atan2"
            | "exp"
            | "log"
            | "log2"
            | "log10"
            | "hypot"
    )
}

/// Ruby code that is read whole: the same subset as Python and JavaScript,
/// written for Ruby. Its text is ASCII, so no encoding reads it otherwise;
/// a name is a local only past an assignment to it, as Ruby reads one (any
/// other is a call of a method of that name); no constant but `Math`, no
/// global or instance variable, no block, no `%` literal, heredoc, regular
/// expression, command string or symbol with `#{…}`.
#[cfg(feature = "ruby")]
fn ruby(code: &str, budget: &Budget) -> bool {
    if !code.is_ascii() || crate::ruby::shebang_runs_more(code) {
        return false;
    }
    let Parsed::Tree(tree) = crate::ruby::parse(budget, code) else {
        return false;
    };
    let root = tree.root_node();
    if !has_statement(root) {
        return false;
    }
    // Where each name the code sets is first set: past it, the name is a
    // local.
    let mut assigned: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut clean = true;
    walk(budget, root, |node, field, above| {
        let target = matches!(
            (above.last().map(|a| a.node.kind()), field),
            (Some("assignment" | "operator_assignment"), Some("left"))
                | (Some("left_assignment_list"), _)
        );
        if target && node.kind() == "identifier" {
            let name = text(node, code);
            clean &= plain_name(name)
                && !name.starts_with('_')
                && !name.contains('$')
                && !RUBY_CALLS.contains(&name);
            assigned
                .entry(name.to_string())
                .or_insert(node.start_byte());
        }
        clean
    });
    if !clean {
        return false;
    }
    let mut whole = true;
    walk(budget, root, |node, field, above| {
        whole = shallow(above) && ruby_node(node, field, above, code, &assigned);
        whole
    });
    whole
}

/// Whether an escape of a double-quoted string is one the grammar and Ruby
/// read as long as each other: a backslash and a letter of the short list
/// (`\n`, `\s`, `\\`, `\"`, `\#`, …), an escaped line end, one to three octal
/// digits, `\x` and one or two hex digits, and `\u` and four. The grammar
/// reads a backslash and one character, but for the codes, so `\c`, `\C` and
/// `\M` end where the next character does; Ruby reads each with the character
/// after it (`\c"`, `\C-"`, `\M-"`: a quote too), so a string the grammar
/// closes at the next quote runs on in Ruby, and the code in between is part
/// of it to the grammar and is run by Ruby. Any other escape (`\z`, `\8`,
/// `\u{…}`) is left to Ruby.
#[cfg(feature = "ruby")]
fn ruby_escape(escape: &str) -> bool {
    let Some(rest) = escape.strip_prefix('\\') else {
        return false;
    };
    let digits = |digits: &str, most: usize, radix: u32, exactly: bool| {
        !digits.is_empty()
            && digits.len() <= most
            && (!exactly || digits.len() == most)
            && digits.chars().all(|c| c.is_digit(radix))
    };
    match rest {
        "n" | "t" | "s" | "r" | "e" | "a" | "b" | "f" | "v" | "\\" | "\"" | "'" | "#" | "\n"
        | "\r" => true,
        _ => {
            if let Some(hex) = rest.strip_prefix('x') {
                digits(hex, 2, 16, false)
            } else if let Some(hex) = rest.strip_prefix('u') {
                digits(hex, 4, 16, true)
            } else {
                digits(rest, 3, 8, false)
            }
        }
    }
}

/// Whether a comment is one Ruby reads as the grammar does: a `#` comment,
/// or an embedded document that starts at `=begin` and white space and ends
/// at its last line, which starts with `=end` and white space, with no
/// other `=end` in it (the grammar ends a document at the first, in a line
/// or at its start, which Ruby does not, and code Ruby runs is then a string
/// to the grammar).
#[cfg(feature = "ruby")]
fn ruby_comment(comment: &str) -> bool {
    if !comment.starts_with('=') {
        return true;
    }
    let space = |rest: &str| {
        rest.chars()
            .next()
            .is_none_or(|c| c.is_ascii_whitespace() || c == '\u{b}')
    };
    let (Some(first), Some(last)) = (comment.find('\n'), comment.rfind('\n')) else {
        return false;
    };
    comment.strip_prefix("=begin").is_some_and(space)
        && comment[last + 1..].strip_prefix("=end").is_some_and(space)
        && !comment[first + 1..=last].contains("=end")
}

#[cfg(feature = "ruby")]
fn ruby_node(
    node: Node<'_>,
    field: Option<&str>,
    above: &[Ancestor<'_>],
    code: &str,
    assigned: &std::collections::HashMap<String, usize>,
) -> bool {
    // A token (`(`, `,`, an operator) is the business of the node it is in.
    if !node.is_named() {
        return true;
    }
    let parent = above.last().map(|ancestor| ancestor.node.kind());
    match node.kind() {
        "comment" => ruby_comment(text(node, code)),
        "escape_sequence" => ruby_escape(text(node, code)),
        "program"
        | "integer"
        | "float"
        | "true"
        | "false"
        | "nil"
        | "string_content"
        | "interpolation"
        | "argument_list"
        | "array"
        | "hash"
        | "hash_key_symbol"
        | "simple_symbol"
        | "parenthesized_statements"
        | "conditional"
        | "if"
        | "unless"
        | "then"
        | "else"
        | "elsif"
        | "if_modifier"
        | "unless_modifier"
        | "left_assignment_list"
        | "right_assignment_list"
        | "element_reference"
        | "empty_statement" => true,
        // A key with its value: `{exit:}`, a key alone, calls the method of
        // its name when no local holds it.
        "pair" => node.child_by_field_name("value").is_some(),
        // A string between quotes: `%q(…)` and the like are not read whole.
        "string" => node
            .child(0)
            .is_some_and(|open| matches!(text(open, code), "\"" | "'")),
        "binary" => node
            .child_by_field_name("operator")
            .is_some_and(|operator| {
                matches!(
                    text(operator, code),
                    "+" | "-"
                        | "*"
                        | "/"
                        | "%"
                        | "**"
                        | "=="
                        | "!="
                        | "<"
                        | ">"
                        | "<="
                        | ">="
                        | "<=>"
                        | "&&"
                        | "||"
                        | "and"
                        | "or"
                        | "&"
                        | "|"
                        | "^"
                        | "<<"
                        | ">>"
                )
            }),
        "unary" => node
            .child_by_field_name("operator")
            .is_some_and(|operator| matches!(text(operator, code), "!" | "-" | "+" | "~" | "not")),
        "assignment" => {
            node.child_by_field_name("right").is_some()
                && node.child_by_field_name("left").is_some_and(|left| {
                    matches!(left.kind(), "identifier" | "left_assignment_list")
                })
        }
        "operator_assignment" => node
            .child_by_field_name("left")
            .is_some_and(|left| left.kind() == "identifier"),
        "identifier" => {
            let name = text(node, code);
            // A method's name may end in `?` (`zero?`); the call holds it to
            // the list.
            if (parent, field) == (Some("call"), Some("method")) {
                return plain_name(name.strip_suffix('?').unwrap_or(name));
            }
            plain_name(name)
                && match (parent, field) {
                    (Some("assignment" | "operator_assignment"), Some("left"))
                    | (Some("left_assignment_list"), _) => true,
                    // A local, past where the code first sets it.
                    _ => assigned
                        .get(name)
                        .is_some_and(|first| *first < node.start_byte()),
                }
        }
        "constant" => {
            let name = text(node, code);
            match (parent, field) {
                (Some("call"), Some("method")) => true,
                (Some("call"), Some("receiver")) => matches!(name, "Math" | "File"),
                (Some("scope_resolution"), Some("scope")) => name == "Math",
                (Some("scope_resolution"), Some("name")) => true,
                _ => false,
            }
        }
        "scope_resolution" => {
            node.child_by_field_name("scope")
                .is_some_and(|scope| text(scope, code) == "Math")
                && node
                    .child_by_field_name("name")
                    .is_some_and(|name| ruby_math(text(name, code), true))
        }
        "call" => {
            if node.child_by_field_name("block").is_some() {
                return false;
            }
            let Some(method) = node.child_by_field_name("method") else {
                return false;
            };
            let name = text(method, code);
            if node
                .child_by_field_name("operator")
                .is_some_and(|operator| text(operator, code) == "::")
            {
                return false;
            }
            match node.child_by_field_name("receiver") {
                None => RUBY_CALLS.contains(&name) && !assigned.contains_key(name),
                Some(receiver) if receiver.kind() == "constant" => match text(receiver, code) {
                    "Math" => ruby_math(name, false),
                    // The files it opens are the reader's acts, by a path
                    // written whole that is no command (Ruby 2.5 and before,
                    // and JRuby, run `File.read('|cmd')`), and by a mode that
                    // only reads.
                    "File" => RUBY_FILE_METHODS.contains(&name) && ruby_file_call(node, code),
                    _ => false,
                },
                Some(_) => RUBY_METHODS.contains(&name),
            }
        }
        _ => false,
    }
}

/// The calls of a name alone that only compute.
const JAVASCRIPT_CALLS: [&str; 7] = [
    "parseInt",
    "parseFloat",
    "String",
    "Number",
    "Boolean",
    "isNaN",
    "isFinite",
];

/// The objects whose members the code may use, and the names it may not set.
const JAVASCRIPT_MODULES: [&str; 3] = ["console", "JSON", "Math"];

/// The methods of a string, a list or a regular expression the code may call.
const JAVASCRIPT_METHODS: [&str; 33] = [
    "toString",
    "toUpperCase",
    "toLowerCase",
    "trim",
    "trimStart",
    "trimEnd",
    "split",
    "join",
    "slice",
    "substring",
    "indexOf",
    "lastIndexOf",
    "includes",
    "startsWith",
    "endsWith",
    "replace",
    "replaceAll",
    "repeat",
    "padStart",
    "padEnd",
    "concat",
    "charAt",
    "charCodeAt",
    "push",
    "pop",
    "shift",
    "unshift",
    "reverse",
    "sort",
    "at",
    "toFixed",
    "test",
    "match",
];

/// Whether `object.name` is a member of `console`, `JSON` or `Math` the code
/// may use.
fn javascript_member(object: &str, name: &str, call: bool) -> bool {
    match object {
        "console" => call && matches!(name, "log" | "error" | "warn" | "info" | "debug"),
        "JSON" => call && matches!(name, "stringify" | "parse"),
        "Math" => matches!(
            name,
            "abs"
                | "ceil"
                | "floor"
                | "round"
                | "max"
                | "min"
                | "pow"
                | "sqrt"
                | "trunc"
                | "sign"
                | "cbrt"
                | "hypot"
                | "log"
                | "log2"
                | "log10"
                | "exp"
                | "sin"
                | "cos"
                | "tan"
                | "atan"
                | "atan2"
                | "random"
                | "PI"
                | "E"
        ),
        _ => false,
    }
}

fn javascript(code: &str, budget: &Budget) -> bool {
    let Parsed::Tree(tree) = crate::javascript::parse(budget, code) else {
        return false;
    };
    let root = tree.root_node();
    if !has_statement(root) {
        return false;
    }
    let mut assigned = HashSet::new();
    let mut clean = true;
    walk(budget, root, |node, _, _| {
        let name = match node.kind() {
            "variable_declarator" => node.child_by_field_name("name"),
            "assignment_expression" | "augmented_assignment_expression" => {
                node.child_by_field_name("left")
            }
            "update_expression" => node.child_by_field_name("argument"),
            _ => None,
        };
        if let Some(name) = name.filter(|name| name.kind() == "identifier") {
            let name = text(name, code);
            clean &= plain_name(name)
                && !name.starts_with('_')
                && !JAVASCRIPT_CALLS.contains(&name)
                && !JAVASCRIPT_MODULES.contains(&name);
            assigned.insert(name.to_string());
        }
        clean
    });
    if !clean {
        return false;
    }
    let mut whole = true;
    walk(budget, root, |node, field, above| {
        whole = shallow(above) && javascript_node(node, field, above, code, &assigned);
        whole
    });
    whole
}

fn javascript_node(
    node: Node<'_>,
    field: Option<&str>,
    above: &[Ancestor<'_>],
    code: &str,
    assigned: &HashSet<String>,
) -> bool {
    // A token (`(`, `,`, an operator) is the business of the node it is in.
    if !node.is_named() {
        return true;
    }
    let parent = above.last().map(|ancestor| ancestor.node.kind());
    match node.kind() {
        "program"
        | "comment"
        | "expression_statement"
        | "lexical_declaration"
        | "variable_declaration"
        | "if_statement"
        | "else_clause"
        | "parenthesized_expression"
        | "sequence_expression"
        | "ternary_expression"
        | "binary_expression"
        | "number"
        | "string"
        | "string_fragment"
        | "escape_sequence"
        | "template_string"
        | "template_substitution"
        | "regex"
        | "regex_pattern"
        | "regex_flags"
        | "true"
        | "false"
        | "null"
        | "undefined"
        | "array"
        | "object"
        | "pair"
        | "arguments"
        | "optional_chain" => true,
        "statement_block" => {
            let mut cursor = node.walk();
            let filled = node
                .named_children(&mut cursor)
                .any(|child| child.kind() != "comment");
            filled && matches!(parent, Some("if_statement" | "else_clause"))
        }
        "variable_declarator" => node
            .child_by_field_name("name")
            .is_some_and(|name| name.kind() == "identifier"),
        "assignment_expression" | "augmented_assignment_expression" => node
            .child_by_field_name("left")
            .is_some_and(|left| left.kind() == "identifier"),
        "update_expression" => node
            .child_by_field_name("argument")
            .is_some_and(|argument| argument.kind() == "identifier"),
        "unary_expression" => node
            .child_by_field_name("operator")
            .is_some_and(|operator| {
                matches!(text(operator, code), "!" | "-" | "+" | "~" | "typeof")
            }),
        "property_identifier" => {
            let name = text(node, code);
            plain_name(name)
                && match (parent, field) {
                    (Some("member_expression"), Some("property")) => true,
                    (Some("pair"), Some("key")) => {
                        !name.starts_with('_') && !matches!(name, "constructor" | "prototype")
                    }
                    _ => false,
                }
        }
        "shorthand_property_identifier" => {
            let name = text(node, code);
            plain_name(name) && assigned.contains(name)
        }
        "identifier" => {
            let name = text(node, code);
            plain_name(name)
                && match (parent, field) {
                    (Some("call_expression"), Some("function")) => {
                        JAVASCRIPT_CALLS.contains(&name) && !assigned.contains(name)
                    }
                    (Some("member_expression"), Some("object")) => {
                        JAVASCRIPT_MODULES.contains(&name) || assigned.contains(name)
                    }
                    (Some("variable_declarator"), Some("name")) => true,
                    _ => assigned.contains(name),
                }
        }
        "member_expression" => {
            let (Some(object), Some(property)) = (
                node.child_by_field_name("object"),
                node.child_by_field_name("property"),
            ) else {
                return false;
            };
            let name = text(property, code);
            let call = parent == Some("call_expression") && field == Some("function");
            if property.kind() != "property_identifier" || name.starts_with('_') {
                return false;
            }
            if object.kind() == "identifier" && JAVASCRIPT_MODULES.contains(&text(object, code)) {
                return javascript_member(text(object, code), name, call);
            }
            if call {
                JAVASCRIPT_METHODS.contains(&name)
            } else {
                name == "length"
            }
        }
        "subscript_expression" => node
            .child_by_field_name("index")
            .is_some_and(|index| index.kind() == "number"),
        "call_expression" => node
            .child_by_field_name("function")
            .is_some_and(|function| matches!(function.kind(), "identifier" | "member_expression")),
        _ => false,
    }
}
