//! A path the code builds from names is judged as the path it builds. The
//! cases are in `tests/cases/built_paths.cases`.

mod common;

#[test]
fn a_path_built_from_names_is_the_path_it_builds() {
    common::cases::check("built_paths");
}
