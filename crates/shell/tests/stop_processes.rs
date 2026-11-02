//! Stopping processes in a POSIX shell. A process stopped by a plain name
//! that is not the system's is safe; a name, a pattern, an option or a service
//! the system needs, every process of a user, a group or the caller's own
//! group (`kill 0`, a negative id), and a fork bomb are `stop_system`. An id,
//! a name, a listing or a substitution the guard cannot read for sure may be
//! any process and is `stop_unknown`; signal 0 sends nothing, but only in its
//! one plain shape.

mod common;

use common::{check, check_effect, macos, only, posix, reason, rules, took, windows};
use milo_guards_shell::{Effect, Paths, Rule, Shell};
use std::time::Duration;

#[test]
fn stopping_a_process_by_name_is_safe_unless_the_system_needs_it() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "killall node",
            "pkill node",
            "killall -9 node",
            "killall -s HUP nginx",
            "killall --signal HUP nginx",
            "killall Finder",
            "killall Dock",
            "pkill -f 'node server.js'",
            "pkill -9 -f vite",
            "pkill -HUP -f gunicorn",
            "pkill -TERM node",
            "pkill --signal KILL node",
            "pkill -x node",
            "pkill '^node$'",
            "pkill -f 'node.*server'",
            "pkill '(node|vite)'",
            "pkill -f \"python -m http.server\"",
            "pkill -u me node",
            "pkill -fu me node",
            "killall -u me node",
            "killall --user me node",
            "killall -r 'node.*'",
            "pkill --sig KILL node",
            "pkill --frobnicate node",
            "pkill -- node",
            "pkill '[n]ode'",
            "pkill '[]a]x'",
            "pkill 'a{x}'",
            "pkill 'a{0'",
            "pkill 'ab{2}'",
            "pkill -P 1234",
            "pgrep node",
            "pgrep -f .",
            "pgrep -u me",
            "killall",
            "pkill",
            "pkill -f \"node server.js\"",
            "pkill -f 'npm run dev'",
            "pkill -f vite",
            "pkill -f ./target/debug/myapp",
            "killall -user me node",
            "killall -ignore-case node",
            "killall gnome-terminal",
            "killall ssh-agent",
            "pkill ssh-agent",
            "pkill -f 'ssh-agent -a /tmp/x'",
            "pkill gnome-calculator",
            "pkill -f /usr/bin/node",
            "pkill -f 'dwmbar'",
            "pgrep sshd",
            "pgrep -f gnome-shell",
            // A name with a folder is the process of that file.
            "killall /usr/local/bin/node",
            "killall /opt/app/server",
            "killall /sbin/initd",
        ],
        &[
            ("killall -9 WindowServer", Rule::StopSystem),
            ("killall loginwindow", Rule::StopSystem),
            ("killall launchd", Rule::StopSystem),
            ("killall systemd", Rule::StopSystem),
            ("killall init", Rule::StopSystem),
            ("killall -u me launchd", Rule::StopSystem),
            ("killall node launchd", Rule::StopSystem),
            ("pkill launchd", Rule::StopSystem),
            ("pkill -9 -f launchd", Rule::StopSystem),
            ("pkill '^systemd$'", Rule::StopSystem),
            ("pkill -f /sbin/init", Rule::StopSystem),
            ("pkill 'node|systemd'", Rule::StopSystem),
            ("pkill Explorer", Rule::StopSystem),
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
            ("killall svchost", Rule::StopSystem),
            ("pkill -x svchost", Rule::StopSystem),
            // In any case, with a folder in front, and several names.
            ("killall SSHD", Rule::StopSystem),
            ("killall -I xorg", Rule::StopSystem),
            ("killall /usr/sbin/sshd", Rule::StopSystem),
            ("killall node sshd", Rule::StopSystem),
            ("pkill -i XORG", Rule::StopSystem),
            ("pkill -9 -x sshd", Rule::StopSystem),
            ("pkill -SIGTERM gnome-shell", Rule::StopSystem),
            ("pkill -u me sshd", Rule::StopSystem),
            ("killall /sbin/launchd", Rule::StopSystem),
            ("killall /usr/lib/systemd/systemd", Rule::StopSystem),
            (
                "killall /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
                Rule::StopSystem,
            ),
            ("sudo killall -9 /sbin/init", Rule::StopSystem),
            ("killall -9 /sbin/init", Rule::StopSystem),
            ("killall ./launchd", Rule::StopSystem),
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
            // A name only known when it runs.
            ("killall $NAME", Rule::StopUnknown),
            ("pkill \"$PATTERN\"", Rule::StopUnknown),
            ("pkill -f $(cat pattern)", Rule::StopUnknown),
            ("echo node | xargs pkill", Rule::StopUnknown),
            // Behind a wrapper or a nested script.
            ("sudo killall WindowServer", Rule::StopSystem),
            ("bash -c 'pkill -f .'", Rule::StopSystem),
            ("timeout 5 killall -u me", Rule::StopSystem),
        ],
    );
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

/// `pkill` and `killall -r` search their expression in each name; a plain
/// word is compared whole by `killall`, and `-x` wants the whole name.
#[test]
fn a_pattern_that_can_match_every_process_or_a_system_name_is_stop_system() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "killall login",
            "killall Window",
            "killall launch",
            // `pkill -f server` is not in `WindowServer` (the case counts).
            "pkill -x login",
            "pkill -x '^login$'",
            "pkill -f server",
            "pkill server",
            "pkill '^window'",
            "pkill 'ogin$'",
            "pkill 'login.x'",
            "killall -r server",
            "killall -r Servers",
            "pkill -f 'python -m http.server'",
            "pkill -x 'login.*x'",
            "pkill -x 'launch'",
            "pkill -x '.aunch'",
            "pkill 'launchdd'",
            "pkill '[^l]aunchd$'",
            "pkill '[[:upper:]]aunchd'",
            "pkill '\\bnode\\b'",
            "pkill '(node|vite)+'",
            "pkill 'a{2}b'",
            "pkill 'init.'",
            "pkill 'x(a|b)*y'",
            "killall -r 'node[0-9]+'",
            // `pkill` sees a program's folder end at a `/`, and its sets are
            // POSIX's.
            "pkill 'a/?node'",
            "pkill 'node[[:alpha:]]x'",
        ],
        &[
            // A pattern that matches every process.
            ("pkill -f .", Rule::StopSystem),
            ("pkill .", Rule::StopSystem),
            ("pkill ''", Rule::StopSystem),
            ("pkill '.*'", Rule::StopSystem),
            ("pkill '^'", Rule::StopSystem),
            ("pkill '$'", Rule::StopSystem),
            ("pkill 'a*'", Rule::StopSystem),
            ("pkill 'x?'", Rule::StopSystem),
            ("pkill '(a|)'", Rule::StopSystem),
            ("pkill 'node|.'", Rule::StopSystem),
            ("pkill '[a-z]*'", Rule::StopSystem),
            ("pkill '\\w'", Rule::StopSystem),
            ("pkill 'a{0,3}'", Rule::StopSystem),
            ("pkill '(unclosed'", Rule::StopSystem),
            ("pkill '[unclosed'", Rule::StopSystem),
            ("pkill -9 -f .", Rule::StopSystem),
            ("pkill -u me -f .", Rule::StopSystem),
            ("killall -r .", Rule::StopSystem),
            ("killall -r '.*'", Rule::StopSystem),
            ("killall -m .", Rule::StopSystem),
            ("killall --regexp .", Rule::StopSystem),
            ("killall5", Rule::StopSystem),
            ("killall5 -9", Rule::StopSystem),
            // Every process but the ones named.
            ("pkill -v node", Rule::StopSystem),
            ("pkill --inverse node", Rule::StopSystem),
            ("pkill --inv node", Rule::StopSystem),
            ("pkill '[[:alpha:]]*'", Rule::StopSystem),
            ("pkill '[^]a]*'", Rule::StopSystem),
            ("pkill '[[:alpha:]'", Rule::StopSystem),
            (
                "pkill '(((((((((((((((((((((((((((((((((a)))))))))))))))))))))))))))))))))'",
                Rule::StopSystem,
            ),
            ("pkill 'a*|b'", Rule::StopSystem),
            ("pkill -v -u me", Rule::StopSystem),
            // A part of a system process's name.
            ("pkill login", Rule::StopSystem),
            ("pkill ^login", Rule::StopSystem),
            ("pkill '^login'", Rule::StopSystem),
            ("pkill Window", Rule::StopSystem),
            ("pkill launch", Rule::StopSystem),
            ("pkill -f login", Rule::StopSystem),
            ("pkill -9 launch", Rule::StopSystem),
            ("pkill 'hd$'", Rule::StopSystem),
            ("pkill 'kernel_'", Rule::StopSystem),
            ("pkill '^kernel'", Rule::StopSystem),
            ("pkill 'login.*'", Rule::StopSystem),
            ("pkill '.*login.*'", Rule::StopSystem),
            ("pkill '^login.*$'", Rule::StopSystem),
            ("pkill -x 'login.*'", Rule::StopSystem),
            ("pkill 'node|login'", Rule::StopSystem),
            ("pkill '(login)'", Rule::StopSystem),
            (
                "pkill -f /System/Library/CoreServices/loginw",
                Rule::StopSystem,
            ),
            ("pkill -i server", Rule::StopSystem),
            ("pkill --ignore-case server", Rule::StopSystem),
            ("pkill Server", Rule::StopSystem),
            ("pkill -9 loginwin", Rule::StopSystem),
            ("killall -r login", Rule::StopSystem),
            ("killall -r '^launch'", Rule::StopSystem),
            ("killall -m launch", Rule::StopSystem),
            ("killall -r -I server", Rule::StopSystem),
            ("killall --regexp --ignore-case server", Rule::StopSystem),
            // A regular expression with syntax is still compared with the
            // system's names.
            ("pkill '[l]aunchd'", Rule::StopSystem),
            ("pkill 'log.n'", Rule::StopSystem),
            ("pkill 'W.ndowServer'", Rule::StopSystem),
            ("pkill 'launc.'", Rule::StopSystem),
            ("pkill -x 'launch.'", Rule::StopSystem),
            ("pkill -x '[l]aunchd'", Rule::StopSystem),
            ("pkill 'login(window)?'", Rule::StopSystem),
            ("pkill 'xyz|[l]aunchd'", Rule::StopSystem),
            ("killall -r 'systemd?'", Rule::StopSystem),
            ("killall -m '[l]aunchd'", Rule::StopSystem),
            ("killall -m 'Window.erver'", Rule::StopSystem),
            ("pkill 'a+'", Rule::StopSystem),
            ("pkill '[[:alpha:]]x'", Rule::StopSystem),
            ("pkill '\\blaunchd\\b'", Rule::StopSystem),
            ("pkill '(log|xyz)in'", Rule::StopSystem),
            ("pkill 'l(a|b)unchd'", Rule::StopSystem),
            ("pkill '[[:lower:]]aunchd'", Rule::StopSystem),
            ("pkill -i 'W.NDOWSERVER'", Rule::StopSystem),
            ("pkill -i '[W]indowserver'", Rule::StopSystem),
            ("pkill -f '/sbin/[i]nit'", Rule::StopSystem),
            ("pkill -f 'node /usr/lib/systemd/syst.md'", Rule::StopSystem),
            ("pkill -x '(launch|xyz)d'", Rule::StopSystem),
            ("pkill 'launch\\w'", Rule::StopSystem),
            ("pkill 'l{1}aunchd'", Rule::StopSystem),
            ("pkill 'k.*_task'", Rule::StopSystem),
            ("sudo pkill '[l]aunchd'", Rule::StopSystem),
            ("pkill '/sbin/[i]nit'", Rule::StopSystem),
            ("pkill '^*init'", Rule::StopSystem),
            ("pkill 'zz[[:alpha:]]|init'", Rule::StopSystem),
        ],
    );
}

/// `pkill -f` searches the whole command line, and a system process's is
/// the one it usually runs with; without `-f` only the name is searched.
#[test]
fn pkill_f_searches_the_whole_command_line_of_a_system_process() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "pkill -9 -f 'python -m http.server'",
            "pkill --full 'java -jar app.jar'",
            "pkill 'WindowServer -daemon'",
            "pkill 'systemd --user'",
        ],
        &[
            ("pkill -f /System/Library", Rule::StopSystem),
            ("pkill -f System", Rule::StopSystem),
            ("pkill -f 'WindowServer -daemon'", Rule::StopSystem),
            ("pkill -f 'loginwindow console'", Rule::StopSystem),
            ("pkill -f 'systemd --user'", Rule::StopSystem),
            ("pkill --full /lib/systemd", Rule::StopSystem),
            ("pkill -f '^/sbin/init'", Rule::StopSystem),
            ("pkill -fx '/sbin/launchd'", Rule::StopSystem),
            ("pkill -f 'launchd -x'", Rule::StopSystem),
            ("sudo pkill -f '/usr/lib/systemd'", Rule::StopSystem),
        ],
    );
    // launchd runs `loginwindow console` and `WindowServer -daemon`.
    check(
        Shell::Posix,
        &macos(),
        &[
            "pkill -f 'rails console'",
            "pkill -f 'node console.js'",
            "pkill -f 'node server.js'",
        ],
        &[
            ("pkill -f console", Rule::StopSystem),
            ("pkill -f -- -daemon", Rule::StopSystem),
            ("pkill -f daemon", Rule::StopSystem),
            ("pkill -f 'loginwindow console'", Rule::StopSystem),
            ("pkill -f 'WindowServer -daemon'", Rule::StopSystem),
            ("pkill -f 'WindowServer.*daemon'", Rule::StopSystem),
            ("pkill -f /System/Library", Rule::StopSystem),
        ],
    );
}

/// An option that selects by user, group, parent, terminal, session or
/// context, with no name, stops every process it picks; so does `-v` with
/// only a selection. Options are read with their values, by any prefix of a
/// long one that fits, and a capital option's attached value is no signal.
#[test]
fn pkill_and_killall_options_are_read_for_what_they_select() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "pkill -P $$",
            "pkill -F pids.txt",
            "pkill -P 1 node",
            "pkill -P 12,34",
            "pkill -t pts/1 node",
            "pkill -USR1 node",
            "pkill -USR2 node",
            "pkill -KILL node",
            "pkill -SIGHUP node",
            "pkill -RTMIN+3 node",
            "pkill -P1 node",
            "pkill -U501 node",
            "killall -USR1 node",
            "killall -SIGTERM node",
            "pkill --s KILL node",
            "pkill --pa 1234 node",
            "killall --u me node",
            "killall --us=me node",
            "killall --re 'node.*'",
            "pkill -q 1 node",
            "pkill --queue 1 node",
            "pkill -r R node",
            "pkill --runstates R node",
            "pkill -s 1234",
            "pkill -g 1234",
            "pkill --session 1234",
            "pkill -s 0 node",
            "pkill -g 0 node",
            "pkill -P \"$(pgrep -x launchd)\" node",
            "killall -Z ctx node",
            "killall --context ctx node",
            // psmisc `killall` reads a long option with one dash.
            "killall -older-than 1h node",
            "killall -signal HUP node",
            "killall -regexp 'node.*'",
        ],
        &[
            // Every process of a user or a group.
            ("pkill -u me", Rule::StopSystem),
            ("pkill -U me", Rule::StopSystem),
            ("pkill -G staff", Rule::StopSystem),
            ("pkill -HUP -u me", Rule::StopSystem),
            ("pkill -9 -u me", Rule::StopSystem),
            ("pkill -xu me", Rule::StopSystem),
            ("pkill -ume", Rule::StopSystem),
            ("pkill --uid me", Rule::StopSystem),
            ("pkill --euid=me", Rule::StopSystem),
            ("killall -u me", Rule::StopSystem),
            ("killall --user me", Rule::StopSystem),
            ("killall -9 -u me", Rule::StopSystem),
            // Only a selection: everything it picks.
            ("pkill -P 1", Rule::StopSystem),
            ("pkill -P 0", Rule::StopSystem),
            ("pkill -P 1,1234", Rule::StopSystem),
            ("pkill --parent 1", Rule::StopSystem),
            ("pkill --parent=1", Rule::StopSystem),
            ("pkill --older 1", Rule::StopSystem),
            ("pkill --runstates S", Rule::StopSystem),
            ("pkill --cgroup /user.slice", Rule::StopSystem),
            ("pkill --ns 1", Rule::StopSystem),
            ("pkill --env HOME", Rule::StopSystem),
            ("pkill -t ttys000", Rule::StopSystem),
            ("pkill -t pts/1", Rule::StopSystem),
            ("pkill --terminal pts/1", Rule::StopSystem),
            ("killall -Z ctx", Rule::StopSystem),
            ("killall --context ctx", Rule::StopSystem),
            ("killall --cont ctx", Rule::StopSystem),
            // A selection only known when it runs picks everything.
            ("pkill -P \"$(pgrep -x launchd)\"", Rule::StopSystem),
            ("pkill -P $(cat ppid)", Rule::StopSystem),
            ("pkill -P $PPID", Rule::StopSystem),
            ("pkill --parent $(cat ppid)", Rule::StopSystem),
            ("pkill -s 0", Rule::StopSystem),
            ("pkill -g 0", Rule::StopSystem),
            ("pkill --session 0", Rule::StopSystem),
            ("pkill --pgroup 0", Rule::StopSystem),
            ("pkill -s 1", Rule::StopSystem),
            ("pkill -g 1", Rule::StopSystem),
            ("pkill -s $SID", Rule::StopSystem),
            ("pkill -g $(ps -o pgid= -p 1)", Rule::StopSystem),
            // The inverse of only a selection: every other process.
            ("pkill -v -P 1234", Rule::StopSystem),
            ("pkill -v -P $$", Rule::StopSystem),
            ("pkill -v -F pids.txt", Rule::StopSystem),
            ("pkill --inverse -F pids.txt", Rule::StopSystem),
            ("pkill -v -t ttys000", Rule::StopSystem),
            ("pkill -v -s 1234", Rule::StopSystem),
            ("pkill -v -g 1234", Rule::StopSystem),
            ("pkill -v --older 1", Rule::StopSystem),
            ("pkill --inv -P 99", Rule::StopSystem),
            ("pkill -vP 1234", Rule::StopSystem),
            ("pkill -v", Rule::StopSystem),
            // An attached value on a capital option is not a signal.
            ("pkill -P1", Rule::StopSystem),
            ("pkill -P0", Rule::StopSystem),
            ("pkill -U0", Rule::StopSystem),
            ("pkill -U501", Rule::StopSystem),
            ("pkill -G0", Rule::StopSystem),
            ("pkill -Uno_such_user_zz", Rule::StopSystem),
            ("pkill -U 501", Rule::StopSystem),
            // A long option by any prefix that fits.
            ("pkill --pa 1", Rule::StopSystem),
            ("pkill --par 1", Rule::StopSystem),
            ("pkill --p 1", Rule::StopSystem),
            ("pkill --eu me", Rule::StopSystem),
            ("pkill --ui me", Rule::StopSystem),
            ("pkill --u me", Rule::StopSystem),
            ("pkill --te pts/1", Rule::StopSystem),
            ("pkill --i node", Rule::StopSystem),
            ("pkill --n 1", Rule::StopSystem),
            ("pkill --o 1", Rule::StopSystem),
            ("pkill --ru R", Rule::StopSystem),
            ("pkill --nslist ipc", Rule::StopSystem),
            ("killall --us me", Rule::StopSystem),
            ("killall --u me", Rule::StopSystem),
            ("killall --us=me", Rule::StopSystem),
            ("killall --re .", Rule::StopSystem),
            ("killall --r .", Rule::StopSystem),
            ("killall --reg .", Rule::StopSystem),
            // An option that takes a value hides no pattern.
            ("pkill -q 1 -u me", Rule::StopSystem),
            ("pkill --queue 1 -u me", Rule::StopSystem),
            ("pkill --q 1 -u me", Rule::StopSystem),
            ("pkill -q 1 -P 1", Rule::StopSystem),
            ("pkill -r R", Rule::StopSystem),
            ("pkill --runstates R", Rule::StopSystem),
            ("pkill -O 1", Rule::StopSystem),
            // psmisc's one-dash long options: the value is not a name, and
            // with no name the filter picks every process it matches.
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
    // macOS `killall` and `pkill` stop reading options at the first name, so
    // every later word is a name; GNU `pkill` reads on. Both are judged and
    // the riskier counts. `killall -c` takes a name and `-t` a terminal.
    check(
        Shell::Posix,
        &macos(),
        &[
            "killall node -s HUP",
            "killall -9 node nginx",
            "pkill node -f",
            "pkill vite -9",
            "pkill -f vite --signal HUP",
            "pkill -u me node",
            "pkill -fu me node",
            "killall -v node -u me",
            "killall -c node",
            "killall -t ttys000 node",
        ],
        &[
            ("killall node -u loginwindow", Rule::StopSystem),
            ("killall node -s WindowServer", Rule::StopSystem),
            ("killall node -t loginwindow", Rule::StopSystem),
            ("killall -v node -s loginwindow", Rule::StopSystem),
            ("pkill node -u launchd", Rule::StopSystem),
            ("pkill node -t loginwindow", Rule::StopSystem),
            ("pkill node -P loginwindow", Rule::StopSystem),
            ("pkill node -G launchd", Rule::StopSystem),
            ("pkill node -- launchd", Rule::StopSystem),
            ("pkill -- node launchd", Rule::StopSystem),
            ("killall -c loginwindow", Rule::StopSystem),
            ("killall -c WindowServer", Rule::StopSystem),
            ("killall -m -c .", Rule::StopSystem),
            ("killall -t ttys000", Rule::StopSystem),
            ("killall -cloginwindow", Rule::StopSystem),
            ("killall -c $NAME", Rule::StopUnknown),
        ],
    );
}

/// `systemctl`, `service` and `launchctl` that stop a process the system
/// needs are read through the same list of names; anything else stays safe.
#[test]
fn a_service_manager_that_stops_a_system_process_is_stop_system() {
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
        &[
            "launchctl kill TERM gui/501/com.me.worker",
            "launchctl kill 15 gui/501/com.example.server",
            "launchctl kill $sig gui/501/com.me.worker",
            "launchctl stop com.me.worker",
            "launchctl start com.apple.WindowServer",
            "launchctl list",
            "launchctl print system/com.apple.WindowServer",
        ],
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
            // A target only known when it runs.
            ("launchctl kill TERM $target", Rule::StopUnknown),
            ("launchctl stop \"$label\"", Rule::StopUnknown),
        ],
    );
}

/// A signal to process 0 goes to every process in the caller's own group,
/// the program that ran the line included, and one to a negative id goes to
/// a whole group: both are `stop_system`, as is process 1. An id it cannot
/// read for sure, and the ids a listing, a substitution or a file hands it,
/// may be any process. An ordinary process and a job are safe.
#[test]
fn kill_judges_the_ids_it_is_given() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "kill 1234",
            "kill 4242",
            "kill -9 4242",
            "kill -TERM 4242",
            "kill -s KILL 4242",
            "kill %1",
            "kill -9 %1",
            "kill -0 4242",
            "kill -0 $pid",
            "kill -s 0 $pid",
            "kill -l -s 9 -1",
            "kill -l",
            "kill -L",
            "kill $!",
            "kill \"$!\"",
            "kill $$",
            "pgrep -f vite | head -1",
            "lsof -ti:3000",
        ],
        &[
            ("kill -9 0", Rule::StopSystem),
            ("kill 0", Rule::StopSystem),
            ("kill -- -1234", Rule::StopSystem),
            ("kill -9 -- -1234", Rule::StopSystem),
            ("kill -s KILL 0", Rule::StopSystem),
            ("kill -n 9 0", Rule::StopSystem),
            ("kill -TERM 0", Rule::StopSystem),
            ("kill -SIGKILL 0", Rule::StopSystem),
            ("kill --signal=KILL 0", Rule::StopSystem),
            ("kill -s KILL -- -5", Rule::StopSystem),
            ("kill -1234", Rule::StopSystem),
            ("kill 4242 0", Rule::StopSystem),
            ("kill 00", Rule::StopSystem),
            ("kill +0", Rule::StopSystem),
            ("sudo kill -9 0", Rule::StopSystem),
            ("trap 'kill 0' INT", Rule::StopSystem),
            ("bash -c 'kill -9 0'", Rule::StopSystem),
            ("xargs kill", Rule::StopUnknown),
            ("kill $pid", Rule::StopUnknown),
            ("kill -9 $(pgrep node)", Rule::StopUnknown),
            ("kill 99999999999999999999", Rule::StopUnknown),
            ("kill 4294967296", Rule::StopUnknown),
            ("kill '*'", Rule::StopUnknown),
            ("kill -- -$$", Rule::StopUnknown),
            ("kill -9 -- -$$", Rule::StopUnknown),
            ("kill -$$", Rule::StopUnknown),
            ("kill -9 -$$", Rule::StopUnknown),
            ("kill -TERM -$$", Rule::StopUnknown),
            ("kill -s TERM -$$", Rule::StopUnknown),
            ("sh -c 'kill -- -$$'", Rule::StopUnknown),
            ("bash -c 'kill -9 -$$'", Rule::StopUnknown),
            ("trap 'kill -- -$$' EXIT", Rule::StopUnknown),
            ("trap 'kill -TERM -$$' EXIT", Rule::StopUnknown),
            ("set -m; kill -- -$$", Rule::StopUnknown),
            ("kill $PPID", Rule::StopUnknown),
            ("kill -9 $PPID", Rule::StopUnknown),
            ("kill -9 \"$PPID\"", Rule::StopUnknown),
            ("kill -9 ${PPID}", Rule::StopUnknown),
            // A listing, a substitution or a file.
            ("kill $(pgrep node)", Rule::StopUnknown),
            ("kill -9 $(pgrep -f vite)", Rule::StopUnknown),
            ("kill `pgrep node`", Rule::StopUnknown),
            ("kill $(lsof -ti:3000)", Rule::StopUnknown),
            ("kill -9 $(lsof -t -i tcp:3000)", Rule::StopUnknown),
            ("kill \"$(cat app.pid)\"", Rule::StopUnknown),
            ("kill $(< app.pid)", Rule::StopUnknown),
            ("kill $(jobs -p)", Rule::StopUnknown),
            ("kill $(pidof node)", Rule::StopUnknown),
            ("kill ${pids[@]}", Rule::StopUnknown),
            ("pgrep node | xargs kill", Rule::StopUnknown),
            ("pgrep node | xargs -r kill -9", Rule::StopUnknown),
            ("pgrep node | xargs -I{} kill {}", Rule::StopUnknown),
            ("lsof -t -i :3000 | xargs kill", Rule::StopUnknown),
            (
                "ps aux | grep node | awk '{print $2}' | xargs kill",
                Rule::StopUnknown,
            ),
            ("cat pids.txt | xargs kill", Rule::StopUnknown),
            ("xargs -a pids.txt kill", Rule::StopUnknown),
            ("xargs kill < pids.txt", Rule::StopUnknown),
            ("jobs -p | xargs kill", Rule::StopUnknown),
            (
                "for p in $(pgrep node); do kill $p; done",
                Rule::StopUnknown,
            ),
            (
                "pgrep node | while read p; do kill $p; done",
                Rule::StopUnknown,
            ),
            (
                "while read p; do kill $p; done < pids.txt",
                Rule::StopUnknown,
            ),
            ("xargs pkill", Rule::StopUnknown),
        ],
    );
}

/// A line is signal 0 only when the first word after `kill` is exactly
/// `-0`, `-s 0`, `-n 0` or `--signal=0`, and every later word is a literal
/// positive id, a job, `$!`, `$$`, `$PPID` or a plain variable. Otherwise the
/// shell and the `kill` program may still send a real signal, and the ids are
/// judged.
#[test]
fn kill_is_signal_0_only_in_the_one_plain_shape() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "kill --list",
            "kill -l 9",
            // A word after `--` is an id, and `-s` is not a number.
            "kill -0 4242 -- -s",
            "kill -0 \"$pid\"",
            "kill -0 4242 4343",
            "kill -0 1",
            "kill -0 %1",
            "kill -0 %%",
            "kill -0 %vim",
            "kill -0 $!",
            "kill -0 $$",
            "kill -0 $PPID",
            "kill -0 \"$PPID\"",
            "kill -0 ${pid}",
            "kill -0 $pid $other",
            "kill -0 4242 $pid %1",
            "kill -s 0 4242",
            "kill -n 0 4242",
            "kill -n 0 $pid",
            "kill --signal=0 4242",
            "kill --signal=0 $pid",
            "env kill -0 4242",
        ],
        &[
            // The shell keeps reading signal options after the first, the
            // last one winning.
            ("kill -s 0 -s KILL -1", Rule::StopSystem),
            ("kill -s 0 -s KILL 1", Rule::StopSystem),
            ("kill -s 0 -s KILL -- -1", Rule::StopSystem),
            ("kill -s 0 -sKILL -1", Rule::StopSystem),
            ("kill -n 0 -n 9 -1", Rule::StopSystem),
            ("kill -0 -s KILL -1", Rule::StopSystem),
            ("kill -0 -s KILL 1", Rule::StopSystem),
            ("kill -s 0 -s KILL 0", Rule::StopSystem),
            ("kill -n 0 -n 9 0", Rule::StopSystem),
            ("kill -0 -s KILL 0", Rule::StopSystem),
            ("kill -0 -sKILL 0", Rule::StopSystem),
            ("kill -0 -n 9 0", Rule::StopSystem),
            ("kill -0 -n9 0", Rule::StopSystem),
            ("kill -00 -s 9 0", Rule::StopSystem),
            ("kill -s 0 -s 9 -- -1234", Rule::StopSystem),
            ("kill -s 0 -s $SIG 0", Rule::StopSystem),
            // The shells and the BSD program read only the first word as a
            // listing option; later it is an id they skip (zsh warns and goes
            // on), so the ids after it are still killed.
            ("kill -9 -l -1", Rule::StopSystem),
            ("kill -s 9 -l -1", Rule::StopSystem),
            ("kill -9 -L -1", Rule::StopSystem),
            ("kill -9 --list -1", Rule::StopSystem),
            ("kill -s KILL --list -- -1", Rule::StopSystem),
            ("kill -9 -l 0", Rule::StopSystem),
            ("kill -TERM -l -1234", Rule::StopSystem),
            ("sudo kill -9 -l -1", Rule::StopSystem),
            // `--signal` is read anywhere among the options, the last one
            // winning.
            ("kill -0 --signal 9 -1", Rule::StopSystem),
            ("kill -0 --signal=KILL -1", Rule::StopSystem),
            ("kill -0 --timeout 1000 KILL -1", Rule::StopSystem),
            ("sudo kill -0 --signal KILL -1", Rule::StopSystem),
            // The `kill` program reorders its words and reads `-s SIG` and
            // `--signal SIG` after an id, and a later `-1` as the id -1.
            ("kill -0 -$$ 1", Rule::StopSystem),
            ("kill -0 -1 -s 9", Rule::StopSystem),
            ("kill -0 4242 -s 9 -1", Rule::StopSystem),
            ("/bin/kill -0 4242 -s 9 -1", Rule::StopSystem),
            ("env kill -0 4242 -s 9 -1", Rule::StopSystem),
            ("xargs kill -0 4242 -s 9 -1", Rule::StopSystem),
            ("sudo kill -0 4242 -s 9 -1", Rule::StopSystem),
            ("sudo kill -0 4242 --signal 9 -1", Rule::StopSystem),
            ("/usr/bin/kill -0 4242 -s KILL 0", Rule::StopSystem),
            ("nohup kill -0 4242 -s 9 -- -1234", Rule::StopSystem),
            ("kill -0 4242 -sKILL -1", Rule::StopSystem),
            ("kill -0 4242 --signal=KILL -1", Rule::StopSystem),
            ("kill -0 %1 -s 9 -1", Rule::StopSystem),
            ("kill -0 $! -s 9 -1", Rule::StopSystem),
            ("kill -0 $$ -s 9 -1", Rule::StopSystem),
            ("kill -0 -$$ -s 9 -1", Rule::StopSystem),
            ("kill -0 4242 $more -1", Rule::StopSystem),
            // An expansion may hold `-s` and a name, read as an option.
            ("kill -0 $X KILL -1", Rule::StopSystem),
            ("kill -0 \"$S\" -1", Rule::StopSystem),
            ("kill -s 0 $more -- -1", Rule::StopSystem),
            // A substitution is not a plain word.
            ("kill -0 \"$(cat app.pid)\"", Rule::StopUnknown),
            ("kill -0 $(cat app.pid)", Rule::StopUnknown),
            ("kill -0 `cat app.pid`", Rule::StopUnknown),
            // Not the plain shape.
            ("kill -0 0", Rule::StopSystem),
            ("kill -0 00", Rule::StopSystem),
            ("kill -0 -1", Rule::StopSystem),
            ("kill -0 -4242", Rule::StopSystem),
            ("kill -0 -- 4242 -1", Rule::StopSystem),
            ("kill -0 -- -1", Rule::StopSystem),
            ("kill -s 0 -- -1", Rule::StopSystem),
            ("kill -0 -9 0", Rule::StopSystem),
            ("kill -0 -1234", Rule::StopSystem),
            ("kill -s 0 -$$ -1", Rule::StopSystem),
            ("kill -00 -1", Rule::StopSystem),
            ("kill -s 00 -1", Rule::StopSystem),
            ("kill -0 99999999999999999999", Rule::StopUnknown),
            ("kill -0 +5 0", Rule::StopSystem),
            // A signal option, a brace list, a wildcard or another option
            // around an id the line signals.
            ("kill -0 -q 1 -s 9 -1", Rule::StopSystem),
            ("kill -0 {-s,KILL} -1", Rule::StopSystem),
            ("kill -0 -{s,}KILL -1", Rule::StopSystem),
            ("kill -0 * -1", Rule::StopSystem),
            ("kill -0 * 1", Rule::StopSystem),
            ("kill -0 {-s,KILL} 1", Rule::StopSystem),
            ("kill -0 ? -1", Rule::StopSystem),
            ("kill -0 [-s]* -1", Rule::StopSystem),
            ("kill -0 4242 -q -s 9 -1", Rule::StopSystem),
            ("kill -0 4242 -s 9 0", Rule::StopSystem),
            ("kill -0 4242 -- -1", Rule::StopSystem),
            ("kill -0 4242 -s9 -1", Rule::StopSystem),
            ("kill -0 4242 --signal 9 -1", Rule::StopSystem),
            ("kill -0 --signal=9 -1", Rule::StopSystem),
            ("kill --signal=0 -s 9 -1", Rule::StopSystem),
            ("kill --signal=0 -1", Rule::StopSystem),
            ("kill --signal=0 {-s,9} -1", Rule::StopSystem),
            ("kill -s 0 {-s,9} -1", Rule::StopSystem),
            ("kill -n 0 * -1", Rule::StopSystem),
            ("kill -n 0 -s 9 0", Rule::StopSystem),
            ("kill -0 ~ -1", Rule::StopSystem),
            ("kill -0 $(echo -s 9 -1)", Rule::StopUnknown),
            ("kill -0 $((1)) -1", Rule::StopSystem),
            ("kill -0 $@", Rule::StopUnknown),
            ("kill -0 \"$@\"", Rule::StopUnknown),
            ("kill -0 $*", Rule::StopUnknown),
            ("kill -0 ${pid:-0}", Rule::StopUnknown),
            ("kill -0 ${pid-0}", Rule::StopUnknown),
            ("kill -0 $pid-1", Rule::StopUnknown),
            ("kill -0 $pid ; kill -9 -1", Rule::StopSystem),
            ("sudo kill -0 -q 1 -s 9 -1", Rule::StopSystem),
        ],
    );
}

#[test]
fn inline_code_that_signals_process_0_or_a_group_is_stop_system() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("python3 -c 'import os; os.kill(0, 9)'", Rule::StopSystem),
            ("python3 -c 'import os; os.killpg(0, 9)'", Rule::StopSystem),
            (
                "python3 -c 'import os; os.kill(-1234, 9)'",
                Rule::StopSystem,
            ),
            ("node -e 'process.kill(0, 9)'", Rule::StopSystem),
            ("node -e 'process.kill(-1234, 9)'", Rule::StopSystem),
            ("deno eval 'Deno.kill(0, \"SIGKILL\")'", Rule::StopSystem),
        ],
    );
}

/// A function that starts copies of itself without end, read through quotes
/// and escapes, in a nested function judged on its own.
#[test]
fn a_fork_bomb_is_stop_system() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "f() { echo hi; }; f",
            "build() { make & }; build",
            "build() { make | tee log; }; build",
            "f() { g & }; g() { echo hi; }; f",
            "greet() { echo hi; }; greet & greet",
            ":(){ :; }; :",
            "f() { echo hi; g() { echo hi; }; }; f",
            "f() { g() { h & }; }; f",
            "f() { 'g' & }; f",
            "f() { \\g & }; f",
            "f() { echo \"f\" & }; f",
        ],
        &[
            (":(){ :|:& };:", Rule::StopSystem),
            (":(){ :|:&};:", Rule::StopSystem),
            (": () { : | : & } ; :", Rule::StopSystem),
            ("bomb() { bomb | bomb & }; bomb", Rule::StopSystem),
            ("f() { f & }; f", Rule::StopSystem),
            ("f() { f|f& }", Rule::StopSystem),
            ("f() { f | f; }; f", Rule::StopSystem),
            ("f() { echo x | f; }", Rule::StopSystem),
            ("function f { f | f & }; f", Rule::StopSystem),
            ("function f() { f & f & }; f", Rule::StopSystem),
            ("f() { ( f ) & }; f", Rule::StopSystem),
            ("f() { if true; then f & fi; }; f", Rule::StopSystem),
            ("bash -c ':(){ :|:& };:'", Rule::StopSystem),
            ("eval ':(){ :|:& };:'", Rule::StopSystem),
            // In a nested function.
            ("f() { g() { g & }; }", Rule::StopSystem),
            ("f() { echo x; f() { f | f; }; }", Rule::StopSystem),
            ("f() { f & g() { echo hi; }; }", Rule::StopSystem),
            // Through quotes and escapes.
            (":(){ \\:|\\:& };:", Rule::StopSystem),
            ("f() { \"f\" | \"f\" & }; f", Rule::StopSystem),
            ("f() { 'f' & }; f", Rule::StopSystem),
            ("bomb() { b\\omb & }; bomb", Rule::StopSystem),
            ("bomb() { b\"om\"b | b'omb' & }; bomb", Rule::StopSystem),
            ("f() { \\f & }; f", Rule::StopSystem),
        ],
    );
}

/// Every `lines` row breaks both `stop_system` and `stop_unknown`; the rows
/// that do not are named together.
fn both(shell: Shell, paths: &Paths, lines: &[&str]) {
    let wrong: Vec<String> = lines
        .iter()
        .filter_map(|line| {
            let found = rules(line, shell, paths);
            (!found.contains(&Rule::StopSystem) || !found.contains(&Rule::StopUnknown))
                .then(|| format!("expected both rules: {line}\n    got {found:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn stop_unknown_is_named_beside_stop_system() {
    assert_eq!(Rule::StopUnknown.name(), "stop_unknown");
    let at = |rule: Rule| Rule::ALL.iter().position(|&listed| listed == rule);
    assert_eq!(
        at(Rule::StopUnknown),
        at(Rule::StopSystem).map(|position| position + 1)
    );
}

/// An id, a name, a listing or a substitution the guard cannot read is
/// `stop_unknown` and never `stop_system`.
#[test]
fn a_stop_the_guard_cannot_read_is_stop_unknown() {
    only(
        Shell::Posix,
        &posix(),
        Rule::StopUnknown,
        Rule::StopSystem,
        &[
            "kill $pid",
            "kill $(lsof -ti:3000)",
            "pgrep node | xargs kill",
            "lsof -ti:3000 | xargs kill -9",
            "xargs kill",
            "kill -9 $(pgrep node)",
            "kill \"$(cat app.pid)\"",
            "sudo kill $pid",
            "kill 99999999999999999999",
            "kill 4294967296",
            "kill '*'",
            "kill 12*",
            "kill {1,2}",
            "kill -s KILL $pid",
            "kill -9 $pid",
            // The group of a process the line names with a variable: the
            // guard cannot say it is the caller's own.
            "kill -- -$$",
            "kill -9 -$$",
            "kill -- -$PPID",
            "killall $NAME",
            "pkill \"$PATTERN\"",
            "xargs pkill",
            "launchctl stop $label",
            "launchctl kill TERM $target",
        ],
    );
}

/// A stop that is certain (process 0, a group, process 1, a system process
/// by name, every process, a shutdown) is `stop_system` and never
/// `stop_unknown`.
#[test]
fn a_certain_stop_is_stop_system_and_never_stop_unknown() {
    only(
        Shell::Posix,
        &posix(),
        Rule::StopSystem,
        Rule::StopUnknown,
        &[
            "kill 0",
            "kill -9 0",
            "kill -9 -1234",
            "kill -- -1",
            "kill -- -1234",
            "kill -s KILL -1",
            "kill 1",
            "kill -9 1",
            "trap 'kill 0' INT",
            "bash -c 'kill -9 0'",
            "sudo kill -9 0",
            "pkill loginwindow",
            "killall loginwindow",
            "killall WindowServer",
            "pkill -v node",
            "pkill -u me",
            "pkill -f .",
            "pkill '.*'",
            "killall5",
            "shutdown now",
            "systemctl stop systemd-logind",
            "launchctl kill TERM system/com.apple.WindowServer",
            ":(){ :|:& };:",
        ],
    );
}

#[test]
fn a_line_with_a_certain_stop_and_an_unknown_one_has_both_rules() {
    both(
        Shell::Posix,
        &posix(),
        &[
            "kill 0; kill $pid",
            "kill $pid 0",
            "kill $pid -1",
            "pkill loginwindow; pkill $NAME",
            "kill $(pgrep node) 1",
        ],
    );
    both(
        Shell::PowerShell,
        &windows(),
        &[
            "Stop-Process -Id 0; Stop-Process -Id $id",
            "Stop-Process -Name explorer; Stop-Process -Id $id",
        ],
    );
}

#[test]
fn a_stop_the_guard_cannot_read_still_changes_the_machine() {
    check_effect(
        Shell::Posix,
        &posix(),
        Effect::Changes,
        &[
            "kill $pid",
            "kill $(lsof -ti:3000)",
            "pgrep node | xargs kill",
            "lsof -ti:3000 | xargs kill -9",
        ],
    );
}

#[test]
fn the_rules_give_a_reason_a_prompt_can_show() {
    for (line, rule, reason_text) in [
        ("pkill -f .", Rule::StopSystem, "stops every process"),
        (
            "pkill -u me",
            Rule::StopSystem,
            "stops every process of a user",
        ),
        (
            "killall WindowServer",
            Rule::StopSystem,
            "stops a process the system needs",
        ),
        (
            ":(){ :|:& };:",
            Rule::StopSystem,
            "starts copies of itself without end",
        ),
    ] {
        assert_eq!(
            reason(line, Shell::Posix, &posix(), rule).as_deref(),
            Some(reason_text),
            "{line}"
        );
    }
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn the_process_rules_read_long_patterns_quickly() {
    let linux = posix();
    for line in [
        format!("pkill '{}}}'", "x{".repeat(31_000)),
        format!("pkill 'x{}'", "{1".repeat(31_000)),
        format!("pkill '{}'", "(".repeat(60_000)),
        format!("pkill '{}'", "a|".repeat(30_000)),
        format!("pkill '{}'", "^(.*".repeat(15_000)),
        format!("pkill '{}'", "[a-z]x?(a|b)+".repeat(4_000)),
        format!("pkill '{}'", "(a|b|c)".repeat(8_000)),
        format!("pkill '{}x'", "[a]*".repeat(15_000)),
    ] {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let took = took(&line, Shell::Posix, &linux);
        assert!(
            took < Duration::from_millis(500),
            "{} bytes took {took:?}",
            line.len()
        );
    }
}

/// `f(){ OPEN×depth f; ×calls CLOSE×depth }`: a body nested `depth` deep.
fn nested(open: &str, close: &str, depth: usize, calls: usize) -> String {
    format!(
        "f(){{ {}{}{} }}",
        open.repeat(depth),
        "f; ".repeat(calls),
        close.repeat(depth)
    )
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn the_fork_bomb_scan_reads_nested_functions_quickly() {
    let linux = posix();
    let slow = Duration::from_millis(500);
    let lines = [
        format!("{}f & {}", "f(){ ".repeat(390), "; }".repeat(390)),
        format!("{}{}", "f(){ f & ".repeat(390), "}; ".repeat(390)),
        format!("{}f; {}", "f(){ ".repeat(1_000), "; }".repeat(1_000)),
        format!(
            "f() {{ {}f & {}; }}",
            "{ ".repeat(1_500),
            "echo x; ".repeat(2_500)
        ),
        format!("f() {{ {}{}f & }}", "{ ".repeat(1_500), "f; ".repeat(5_000)),
    ];
    // A body of balanced `if`, `while` and `( )` nested near the depth limit,
    // with thousands of calls to the function inside it. A read that climbs
    // from each call takes minutes; the limit is loose so that a slow or
    // busy machine does not trip it.
    let deep = [
        nested("if true; then ", "fi; ", 390, 15_000),
        nested("while true; do ", "done; ", 390, 15_000),
        nested("( ", ") ", 390, 15_000),
    ];
    let limits = lines
        .iter()
        .map(|line| (line, slow))
        .chain(deep.iter().map(|line| (line, slow * 8)));
    for (line, limit) in limits {
        let took = took(line, Shell::Posix, &linux);
        assert!(took < limit, "{} bytes took {took:?}", line.len());
    }
}
