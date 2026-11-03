//! `Resolver::picks_secret`: which keys and credentials a pattern can name.
//! A pattern is read by the folder before its first wildcard part and by what
//! its parts can match below, as a protected path is; a part is matched
//! against each secret place's names one for one. The cases are in
//! `tests/cases/picks.cases`.

mod common;

#[test]
fn a_pattern_picks_the_keys_its_parts_can_match() {
    common::cases::check("picks");
}
