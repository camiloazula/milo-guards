//! The processes the system needs, stopped by a plain name, were safe when
//! the name was not on a short list: the remote login, the macOS preferences
//! and menu bar, the Linux display server, desktops and login session, and
//! the Windows compositor all ended the session or the machine. They are on
//! the list now, in every place it is read, and a service manager that stops
//! one (`systemctl`, `service`, `launchctl`) is read through it. A name that
//! is not one of them stays safe, and psmisc `killall`'s long options with one
//! dash are read with their values.

mod common;

use common::{check, macos, posix, windows};
use milo_guards_shell::{Rule, Shell};

#[test]
fn the_processes_the_system_needs_are_stop_system_by_name() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("pkill sshd", Rule::StopSystem),
            ("killall -9 sshd", Rule::StopSystem),
            ("sudo pkill sshd", Rule::StopSystem),
            ("killall cfprefsd", Rule::StopSystem),
            ("killall SystemUIServer", Rule::StopSystem),
            ("killall Xorg", Rule::StopSystem),
            ("pkill gnome-shell", Rule::StopSystem),
            ("killall plasmashell", Rule::StopSystem),
            ("killall -9 kwin_x11", Rule::StopSystem),
            ("killall kwin_wayland", Rule::StopSystem),
            ("pkill dbus-daemon", Rule::StopSystem),
            ("killall systemd-logind", Rule::StopSystem),
            // In any case, with a folder in front, and several names.
            ("killall SSHD", Rule::StopSystem),
            ("killall -I xorg", Rule::StopSystem),
            ("killall /usr/sbin/sshd", Rule::StopSystem),
            ("killall node sshd", Rule::StopSystem),
            ("pkill -i XORG", Rule::StopSystem),
            ("pkill -9 -x sshd", Rule::StopSystem),
            ("pkill -SIGTERM gnome-shell", Rule::StopSystem),
            ("pkill -u me sshd", Rule::StopSystem),
            // A regular expression that can match one, anchored or not.
            ("pkill '^sshd$'", Rule::StopSystem),
            ("pkill 's[s]hd'", Rule::StopSystem),
            ("pkill 'plasma.*'", Rule::StopSystem),
            ("pkill ssh", Rule::StopSystem),
            ("pkill dbus", Rule::StopSystem),
            ("pkill kwin", Rule::StopSystem),
            ("pkill -f gnome-shell", Rule::StopSystem),
            ("killall -r 'kwin_.*'", Rule::StopSystem),
            // `-f` searches the usual command line.
            ("pkill -f 'sshd -D'", Rule::StopSystem),
            ("pkill -f /usr/sbin/sshd", Rule::StopSystem),
            ("pkill -f 'dbus-daemon --session'", Rule::StopSystem),
            ("pkill -f /usr/bin/gnome-shell", Rule::StopSystem),
            ("pkill -f 'cfprefsd daemon'", Rule::StopSystem),
            ("pkill -f SystemUIServer.app", Rule::StopSystem),
            ("pkill -f 'systemd-logind'", Rule::StopSystem),
            ("pkill -f /usr/lib/xorg", Rule::StopSystem),
            // A name only known when it runs follows the existing rule.
            ("killall $NAME", Rule::StopUnknown),
            ("pkill \"$PATTERN\"", Rule::StopUnknown),
        ],
    );
}

#[test]
fn the_processes_the_system_needs_stay_stop_system_on_macos() {
    check(
        Shell::Posix,
        &macos(),
        &[],
        &[
            ("killall cfprefsd", Rule::StopSystem),
            ("killall SystemUIServer", Rule::StopSystem),
            ("sudo killall -9 sshd", Rule::StopSystem),
            ("killall WindowServer", Rule::StopSystem),
        ],
    );
}

#[test]
fn a_name_that_is_not_the_systems_stays_safe() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "pkill node",
            "killall node",
            "killall -9 node",
            "pkill -f \"node server.js\"",
            "pkill -f 'npm run dev'",
            "pkill -f vite",
            "pkill -f ./target/debug/myapp",
            "pkill -f 'node.*server'",
            "pkill -x node",
            "pkill -u me node",
            "killall -user me node",
            "killall -ignore-case node",
            "killall -u me node",
            "killall Finder",
            "killall Dock",
            "killall gnome-terminal",
            "killall ssh-agent",
            "pkill ssh-agent",
            "pkill -f 'ssh-agent -a /tmp/x'",
            "pkill gnome-calculator",
            "pkill -f /usr/bin/node",
            "pkill -f 'dwmbar'",
            "pgrep sshd",
            "pgrep -f gnome-shell",
        ],
        &[],
    );
}

#[test]
fn a_service_manager_that_stops_one_is_read_through_the_same_list() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("systemctl stop systemd-logind", Rule::StopSystem),
            ("systemctl stop systemd-logind.service", Rule::StopSystem),
            ("sudo systemctl stop systemd-logind", Rule::StopSystem),
            ("systemctl --system stop systemd-logind", Rule::StopSystem),
            ("systemctl kill systemd-logind", Rule::StopSystem),
            ("systemctl kill -s KILL systemd-logind", Rule::StopSystem),
            ("systemctl stop docker sshd", Rule::StopSystem),
            ("systemctl stop sshd", Rule::StopSystem),
            ("systemctl stop sshd.service", Rule::StopSystem),
            ("systemctl stop ssh", Rule::StopSystem),
            ("systemctl stop dbus", Rule::StopSystem),
            ("service sshd stop", Rule::StopSystem),
            ("service ssh stop", Rule::StopSystem),
            ("service systemd-logind stop", Rule::StopSystem),
            // An action only known when it runs may be `stop`.
            ("service sshd $action", Rule::StopSystem),
        ],
    );
    check(
        Shell::Posix,
        &macos(),
        &[],
        &[
            (
                "launchctl kill SIGTERM system/com.apple.WindowServer",
                Rule::StopSystem,
            ),
            (
                "sudo launchctl kill SIGTERM system/com.apple.WindowServer",
                Rule::StopSystem,
            ),
            (
                "launchctl kill 9 system/com.apple.WindowServer",
                Rule::StopSystem,
            ),
            (
                "launchctl kill TERM system/com.apple.cfprefsd.xpc.daemon",
                Rule::StopSystem,
            ),
            (
                "launchctl kill TERM gui/501/com.apple.SystemUIServer.agent",
                Rule::StopSystem,
            ),
            (
                "launchctl kill TERM system/com.apple.loginwindow.501",
                Rule::StopSystem,
            ),
            (
                "launchctl kill TERM system/com.openssh.sshd",
                Rule::StopSystem,
            ),
            ("launchctl stop com.apple.WindowServer", Rule::StopSystem),
            (
                "launchctl stop com.apple.cfprefsd.xpc.daemon",
                Rule::StopSystem,
            ),
            // A target only known when it runs follows the existing rule.
            ("launchctl kill TERM $target", Rule::StopUnknown),
            ("launchctl stop \"$label\"", Rule::StopUnknown),
        ],
    );
}

#[test]
fn a_service_manager_that_stops_anything_else_stays_safe() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "systemctl stop docker",
            "systemctl stop nginx",
            "systemctl stop postgresql.service",
            "systemctl kill docker",
            "systemctl restart sshd",
            "systemctl status systemd-logind",
            "systemctl start systemd-logind",
            "systemctl --user stop dbus",
            "service nginx stop",
            "service sshd status",
            "service nginx $action",
        ],
        &[],
    );
    check(
        Shell::Posix,
        &macos(),
        &[
            "launchctl kill TERM gui/501/com.me.worker",
            "launchctl kill 15 gui/501/com.example.server",
            "launchctl kill $sig gui/501/com.me.worker",
            "launchctl stop com.me.worker",
            "launchctl start com.apple.WindowServer",
            "launchctl list",
            "launchctl print system/com.apple.WindowServer",
        ],
        &[],
    );
}

#[test]
fn psmiscs_long_options_with_one_dash_are_read_with_their_values() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "killall -user me node",
            "killall -ignore-case node",
            "killall -older-than 1h node",
            "killall -signal HUP node",
            "killall -regexp 'node.*'",
        ],
        &[
            // The value is not a name, and with no name the filter picks
            // every process it matches.
            ("killall -user me", Rule::StopSystem),
            ("killall -context x", Rule::StopSystem),
            ("killall -context=x", Rule::StopSystem),
            // The long option is read as written, not as letters.
            ("killall -ignore-case -r WINDOW", Rule::StopSystem),
            ("killall -ignore-case -regexp window", Rule::StopSystem),
            ("killall -ignore-case -regexp SSH", Rule::StopSystem),
            // The value is a name to the BSD reading, and the riskier counts.
            ("killall -user sshd node", Rule::StopSystem),
            ("killall -user me sshd", Rule::StopSystem),
            ("killall -user me WindowServer", Rule::StopSystem),
        ],
    );
}

#[test]
fn the_windows_compositor_and_the_remote_login_are_stop_system() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Stop-Process -Name node",
            "Stop-Process -Name node -Force",
            "Get-Process node | Stop-Process",
            "taskkill /IM node.exe /F",
            "taskkill /IM node.exe",
            "tskill node",
        ],
        &[
            ("Stop-Process -Name dwm", Rule::StopSystem),
            ("Stop-Process -Name dwm -Force", Rule::StopSystem),
            ("Stop-Process -Name DWM.exe", Rule::StopSystem),
            ("Stop-Process -Name sshd", Rule::StopSystem),
            ("Stop-Process -Name node, dwm", Rule::StopSystem),
            ("Stop-Process -Name dw*", Rule::StopSystem),
            ("Get-Process dwm | Stop-Process", Rule::StopSystem),
            ("taskkill /IM dwm.exe /F", Rule::StopSystem),
            ("taskkill /IM sshd.exe", Rule::StopSystem),
            ("taskkill /FI \"IMAGENAME eq dwm.exe\"", Rule::StopSystem),
            ("tskill dwm", Rule::StopSystem),
            ("Stop-Process -Name $n", Rule::StopUnknown),
        ],
    );
}
