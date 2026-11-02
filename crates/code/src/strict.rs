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
//!   `json.dumps`, `console.log`, `Math.max`, the methods of a string or a
//!   list), or `open` in Python, which the reader judges by its path and mode;
//! - its imports are the modules built into the interpreter binary (`sys`,
//!   `builtins`, `errno`, `itertools`, `time`) in Python, which no file in
//!   the folder the code runs in can stand in for, and it has no import,
//!   `require` or `eval` in JavaScript;
//! - it names nothing that is not a name it set, a call on the list or a
//!   module on the list that it imported (JavaScript's are always there), and
//!   sets none of those;
//! - it reaches into nothing: no attribute that starts with an underscore, and
//!   in JavaScript no member other than `length` and the methods on the list.

use std::collections::HashSet;

use tree_sitter::Node;

use super::{walk, Ancestor, Language};

/// Whether `code` is read whole: nothing in it is outside the subset above.
/// `None` when it is not; when it is, `Some(true)` if it may load a module,
/// which looks in the folder the code runs in first (all Python code does,
/// with or without an `import`).
pub(super) fn reads_whole(language: Language, code: &str) -> Option<bool> {
    if code.chars().any(|c| {
        (c.is_control() && !matches!(c, '\n' | '\t')) || matches!(c, '\u{2028}' | '\u{2029}')
    }) {
        return None;
    }
    match language {
        Language::Python => python(code),
        Language::JavaScript => javascript(code).then_some(false),
    }
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

/// The modules an import may name, and the names the code may not set: the
/// ones built into every interpreter binary (the `Modules/Setup.bootstrap`
/// of `CPython` compiles `errno`, `itertools` and `time` in, `sys` and `builtins` are the
/// interpreter itself). The import system tries the built-in finder before it
/// looks at the import path, so no file in the folder the code runs in can
/// stand in for one of them, and importing one reads nothing from disk. Every
/// other module (`json`, `re`, `math`, which is a file on many builds, and the
/// modules each of them loads in turn) is looked up in that folder first, and
/// an import of one makes the code not read whole.
const PYTHON_MODULES: [&str; 5] = ["builtins", "errno", "itertools", "sys", "time"];

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
        // `builtins.exec` is `exec`, and `itertools` builds lazy iterators:
        // importing either is read whole and using either is not.
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
fn python(code: &str) -> Option<bool> {
    let mut parser = tree_sitter::Parser::new();
    let tree = parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()
        .and_then(|()| parser.parse(code, None))?;
    let root = tree.root_node();
    if root.has_error() || !has_statement(root) {
        return None;
    }
    // The names the code sets, none of which may be a name the reader gives a
    // meaning to, and the modules it imports: a member of a module is only
    // read once the code has named the module.
    let mut assigned = HashSet::new();
    let mut imported = HashSet::new();
    let mut clean = true;
    walk(root, |node, _, _| {
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
            walk(left, |name, _, _| {
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
    walk(root, |node, field, above| {
        whole = python_node(node, field, above, code, &assigned, &imported);
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
) -> bool {
    // A token (`(`, `,`, an operator) is the business of the node it is in.
    if !node.is_named() {
        return true;
    }
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
            let all = node.named_children(&mut cursor).all(|name| {
                name.kind() == "dotted_name" && PYTHON_MODULES.contains(&text(name, code))
            });
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
            if object.kind() == "identifier" && PYTHON_MODULES.contains(&text(object, code)) {
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

fn javascript(code: &str) -> bool {
    let mut parser = tree_sitter::Parser::new();
    let Some(tree) = parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .ok()
        .and_then(|()| parser.parse(code, None))
    else {
        return false;
    };
    let root = tree.root_node();
    if root.has_error() || !has_statement(root) {
        return false;
    }
    let mut assigned = HashSet::new();
    let mut clean = true;
    walk(root, |node, _, _| {
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
    walk(root, |node, field, above| {
        whole = javascript_node(node, field, above, code, &assigned);
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
