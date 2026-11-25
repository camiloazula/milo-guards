//! Python's `open` and JavaScript's flags read or write by their mode. The
//! cases are in `tests/cases/open_modes.cases`.

mod common;

#[test]
fn a_file_opened_reads_or_writes_by_its_mode() {
    common::cases::check("open_modes");
}
