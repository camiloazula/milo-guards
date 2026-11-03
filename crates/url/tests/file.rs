//! A `file:` URL is always a finding; where its path lands only sharpens the
//! words, and the path is placed through core's resolver like any other. The
//! cases are in `tests/cases/file.cases`.

mod common;

#[test]
fn every_case() {
    common::cases::check("file");
}
