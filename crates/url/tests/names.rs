//! A rule's wire name never changes once a caller uses it, whatever the
//! variant is called in code; and `Rule::ALL` lists every rule once.

use std::collections::HashSet;

use milo_guards_core::RuleName;
use milo_guards_url::Rule;

/// The wire name each rule must have. The match has no fallback arm, so a
/// rule added to the enum fails to compile here until it is given its name.
fn expected(rule: Rule) -> &'static str {
    match rule {
        Rule::LocalAddress => "local_address",
        Rule::Metadata => "metadata",
        Rule::Credentials => "credentials",
        Rule::LocalFile => "local_file",
        Rule::Scheme => "scheme",
        Rule::Unreadable => "unreadable",
    }
}

#[test]
fn every_rule_has_its_wire_name() {
    for rule in Rule::ALL {
        assert_eq!(rule.name(), expected(rule), "{rule:?}");
    }
}

#[test]
fn the_trait_gives_the_same_name_as_the_method() {
    for rule in Rule::ALL {
        assert_eq!(RuleName::name(rule), rule.name(), "{rule:?}");
    }
}

#[test]
fn all_lists_each_rule_once() {
    let rules: HashSet<_> = Rule::ALL.iter().collect();
    assert_eq!(rules.len(), Rule::ALL.len(), "a rule is listed twice");
}

#[test]
fn wire_names_are_unique() {
    let names: HashSet<_> = Rule::ALL.iter().map(|rule| rule.name()).collect();
    assert_eq!(names.len(), Rule::ALL.len());
}
