//! The settings of the machine on macOS and Linux: security switches, the
//! firewall, the services the system runs, Time Machine backups and
//! machine-wide preferences are `system_settings`; reading a setting, a
//! user's own services and an application's own preferences are not.
//!
//! The lines and their answers, one section per tool and then the reason a
//! prompt can show, are in `tests/cases/system_settings.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("system_settings");
}
