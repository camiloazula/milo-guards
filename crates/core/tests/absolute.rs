//! The absolute path a spelling names, as spelled: nothing read from the
//! disk, so a link is not followed and no case is folded. The cases, each a
//! spelling a review could try, are in `tests/cases/absolute.cases`.

mod common;

#[test]
fn every_spelling_names_the_absolute_path_its_dots_and_drive_give() {
    common::cases::check("absolute");
}
