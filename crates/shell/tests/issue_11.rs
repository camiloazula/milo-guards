//! The settings of the machine on macOS and Linux (issue 11): security
//! switches, the firewall, the services the system runs, Time Machine
//! backups and machine-wide preferences are `system_settings`; reading a
//! setting, a user's own services and an application's own preferences are
//! not.

mod common;

use common::{check, posix};
use milo_guards_shell::{classify, Rule, Shell};

/// Each line is `system_settings` with exactly this reason.
fn assert_reasons(rows: &[(&str, &str)]) {
    let paths = posix();
    let wrong: Vec<String> = rows
        .iter()
        .filter_map(|(line, reason)| {
            let found: Vec<_> = classify(line, Shell::Posix, &paths)
                .findings()
                .iter()
                .filter(|finding| finding.rule == Rule::SystemSettings)
                .map(|finding| finding.reason.clone())
                .collect();
            (found != [(*reason).to_string()]).then(|| format!("{line:?}: {found:?}"))
        })
        .collect();
    assert!(wrong.is_empty(), "wrong reasons:\n{}", wrong.join("\n"));
}

fn risky(lines: &[&str]) {
    let rows: Vec<(&str, Rule)> = lines
        .iter()
        .map(|line| (*line, Rule::SystemSettings))
        .collect();
    check(Shell::Posix, &posix(), &[], &rows);
}

#[test]
fn security_switches_are_risky() {
    risky(&[
        "spctl --master-disable",
        "spctl --global-disable",
        "spctl --disable --label x",
        "spctl --master-d",
        "spctl --global-d",
        "spctl --di --label x",
        "csrutil disable",
        "csrutil authenticated-root disable",
        "csrutil enable --without debug",
        "csrutil $mode",
        "setenforce 0",
        "setenforce Permissive",
        "setenforce permissive",
        "setenforce PERMISSIVE",
        "setenforce $mode",
        "echo SELINUX=disabled > /etc/selinux/config",
        "echo SELINUX=disabled >> /etc/selinux/config",
        "sed -i s/enforcing/disabled/ /etc/selinux/config",
        "sudo tee /etc/selinux/config",
        "cp selinux.conf /etc/selinux/config",
        "cd /etc/selinux && echo x > config",
        "echo x > /etc/../etc/selinux/config",
        "echo SELINUX=disabled > /etc/sysconfig/selinux",
        "sudo nvram boot-args=-v",
        "nvram boot-args=-v",
        "nvram -d boot-args",
        "nvram -c",
        "nvram -f vars.txt",
        "nvram $var",
    ]);
    assert_reasons(&[
        ("spctl --master-disable", "turns off Gatekeeper"),
        ("csrutil disable", "turns off System Integrity Protection"),
        ("setenforce 0", "turns off SELinux enforcement"),
        ("echo x > /etc/selinux/config", "changes SELinux settings"),
        (
            "nvram boot-args=-v",
            "changes the computer's startup settings",
        ),
    ]);
}

#[test]
fn reading_security_switches_is_safe() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "spctl --master-enable",
            "spctl --global-enable",
            "spctl --status",
            "spctl --assess --type execute x.app",
            "spctl --add --label x /Applications/x.app",
            "csrutil status",
            "csrutil enable",
            "csrutil authenticated-root status",
            "setenforce 1",
            "setenforce Enforcing",
            "setenforce --help",
            "getenforce",
            "sestatus",
            "cat /etc/selinux/config",
            "grep SELINUX= /etc/selinux/config",
            "cp /etc/selinux/config selinux.conf",
            "echo x > selinux/config",
            "nvram -p",
            "nvram -x -p",
            "nvram boot-args",
            "nvram -p | grep boot-args",
        ],
        &[],
    );
}

#[test]
fn the_firewall_is_risky_to_turn_off_or_empty() {
    risky(&[
        "iptables -F",
        "iptables -t nat -F",
        "iptables -F INPUT",
        "iptables -nF",
        "iptables --flush",
        "iptables --fl",
        "iptables -X",
        "iptables -t nat -X",
        "iptables --delete-chain",
        "iptables --delete-c",
        "iptables -P INPUT ACCEPT",
        "iptables -P FORWARD accept",
        "iptables -t mangle -P OUTPUT ACCEPT",
        "iptables --policy INPUT ACCEPT",
        "iptables --po INPUT ACCEPT",
        "iptables -P INPUT $policy",
        "ip6tables -F",
        "ip6tables -X",
        "ip6tables -P INPUT ACCEPT",
        "iptables-legacy -F",
        "iptables-nft -F",
        "ip6tables-legacy -P INPUT ACCEPT",
        "/usr/sbin/iptables -F",
        "sudo iptables -F",
        "bash -c 'iptables -F'",
        "nft flush ruleset",
        "nft flush table inet filter",
        "nft flush chain inet filter input",
        "nft delete table inet filter",
        "nft delete chain inet filter input",
        "nft destroy table inet filter",
        "nft $cmd",
        "ufw disable",
        "ufw reset",
        "ufw --force reset",
        "ufw --force disable",
        "ufw default allow incoming",
        "ufw default allow",
        "ufw $cmd",
        "firewall-cmd --panic-on",
        "firewall-cmd --set-default-zone=trusted",
        "firewall-cmd --set-default-zone trusted",
        "pfctl -d",
        "pfctl -dq",
        "pfctl -F all",
        "pfctl -F rules",
        "pfctl -F nat",
        "pfctl -F $what",
        "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off",
        "socketfilterfw --setglobalstate off",
        "socketfilterfw --setglobalstate 0",
        "socketfilterfw --setglobalstate $state",
    ]);
    assert_reasons(&[
        ("iptables -F", "changes the firewall"),
        ("ip6tables -P INPUT ACCEPT", "changes the firewall"),
        ("nft flush ruleset", "changes the firewall"),
        ("ufw disable", "turns the firewall off"),
        ("ufw reset", "resets the firewall's rules"),
        (
            "ufw default allow incoming",
            "lets everything through the firewall",
        ),
        ("firewall-cmd --panic-on", "changes the firewall"),
        ("pfctl -d", "changes the firewall"),
        (
            "socketfilterfw --setglobalstate off",
            "turns the firewall off",
        ),
    ]);
}

#[test]
fn everyday_firewall_work_is_safe() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "iptables -L",
            "iptables -nvL",
            "iptables -L -n --line-numbers",
            "iptables -S",
            "iptables -C INPUT -j DROP",
            "iptables -Z",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "iptables -A INPUT -s $ip -j DROP",
            "iptables -I INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT",
            "iptables -D INPUT 1",
            "iptables -P INPUT DROP",
            "iptables -P INPUT",
            "iptables-save",
            "ip6tables -L",
            "nft list ruleset",
            "nft add rule inet filter input tcp dport 22 accept",
            "nft flush set inet filter blocked",
            "ufw status",
            "ufw status verbose",
            "ufw allow 22",
            "ufw deny 23",
            "ufw default deny incoming",
            "ufw enable",
            "firewall-cmd --list-all",
            "firewall-cmd --add-port=80/tcp",
            "firewall-cmd --panic-off",
            "firewall-cmd --get-default-zone",
            "pfctl -sr",
            "pfctl -e",
            "pfctl -s rules",
            "pfctl -F states",
            "pfctl -f /etc/pf.conf",
            "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
            "socketfilterfw --getglobalstate",
        ],
        &[],
    );
}

#[test]
fn system_services_are_risky_to_disable_or_remove() {
    risky(&[
        "systemctl mask systemd-resolved",
        "systemctl disable nginx",
        "systemctl disable --now nginx",
        "systemctl --now disable nginx",
        "systemctl -t service mask x",
        "systemctl --system mask x",
        "systemctl --user --system mask x",
        "systemctl --global disable x",
        "systemctl --root /mnt disable x",
        "systemctl $verb nginx",
        "sudo systemctl mask x",
        "systemctl stop firewalld",
        "systemctl stop firewalld.service",
        "systemctl stop ufw",
        "systemctl stop nftables",
        "systemctl stop apparmor",
        "systemctl stop auditd",
        "systemctl stop fail2ban",
        "systemctl stop docker ufw",
        "systemctl stop $unit",
        "service ufw stop",
        "service firewalld stop",
        "launchctl bootout gui/501/com.x",
        "launchctl bootout system/com.x",
        "launchctl bootout system ./x.plist",
        "launchctl bootout user/501",
        "launchctl bootout $domain ./x.plist",
        "launchctl bootout gui/501 /Library/LaunchDaemons/x.plist",
        "launchctl bootout gui/501 ./x.plist /Library/LaunchDaemons/x.plist",
        "launchctl unload /Library/LaunchDaemons/x.plist",
        "launchctl unload -w /Library/LaunchDaemons/x.plist",
        "launchctl unload /System/Library/LaunchDaemons/x.plist",
        "launchctl unload ~/Library/LaunchAgents/x.plist",
        "launchctl unload $plist",
        "launchctl disable gui/501/com.x",
        "launchctl disable system/com.x",
        "launchctl remove com.x",
        "launchctl $verb gui/501/com.x",
        "sudo launchctl bootout system/com.x",
    ]);
    assert_reasons(&[
        ("systemctl mask x", "masks a system service"),
        ("systemctl disable x", "disables a system service"),
        (
            "systemctl $verb x",
            "changes a system service only known when it runs",
        ),
        (
            "systemctl stop ufw",
            "stops a service that protects the system",
        ),
        (
            "service ufw stop",
            "stops a service that protects the system",
        ),
        (
            "launchctl bootout gui/501/com.x",
            "removes a service the system runs",
        ),
        (
            "launchctl unload /Library/LaunchDaemons/x.plist",
            "removes a service the system runs",
        ),
        (
            "launchctl disable gui/501/com.x",
            "removes a service the system runs",
        ),
    ]);
}

#[test]
fn a_users_own_services_and_everyday_service_work_are_safe() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "systemctl --user restart web",
            "systemctl --user stop web",
            "systemctl --user disable web",
            "systemctl --user mask web",
            "systemctl disable --user web",
            "systemctl --system --user mask web",
            "systemctl --us mask web",
            "systemctl restart nginx",
            "systemctl reload nginx",
            "systemctl start docker",
            "systemctl enable nginx",
            "systemctl unmask nginx",
            "systemctl status nginx",
            "systemctl is-active nginx",
            "systemctl list-units",
            "systemctl daemon-reload",
            "systemctl -t service list-units",
            "systemctl",
            "systemctl stop docker",
            "systemctl stop postgresql.service",
            "systemctl stop nginx",
            "service docker stop",
            "service nginx restart",
            "service nginx status",
            "service --status-all",
            "launchctl list",
            "launchctl print gui/501",
            "launchctl print system",
            "launchctl list com.x",
            "launchctl load ./x.plist",
            "launchctl bootstrap gui/501 ./x.plist",
            "launchctl enable gui/501/com.x",
            "launchctl kickstart -k gui/501/com.x",
            "launchctl start com.x",
            "launchctl stop com.x",
            "launchctl unload ./x.plist",
            "launchctl unload -w ./x.plist",
            "launchctl unload ./a.plist ./b.plist",
            "launchctl bootout gui/501 ./x.plist",
            "launchctl bootout gui/501 ~/work/repo/x.plist",
            "launchctl bootout gui/501 /tmp/scratch/x.plist",
            "launchctl",
        ],
        &[],
    );
}

#[test]
fn time_machine_backups_are_risky_to_delete_or_turn_off() {
    risky(&[
        "tmutil delete /Volumes/TM/Backups.backupdb/x",
        "tmutil deletelocalsnapshots 2024-01-01-000000",
        "tmutil deleteinprogress /Volumes/TM/x",
        "tmutil thinlocalsnapshots / 1000 1",
        "tmutil disable",
        "tmutil disablelocal",
        "tmutil removedestination 1234",
        "sudo tmutil delete -p /Volumes/TM/x",
        "tmutil $verb",
    ]);
    assert_reasons(&[
        ("tmutil delete x", "deletes Time Machine backups"),
        (
            "tmutil deletelocalsnapshots 1",
            "deletes Time Machine backups",
        ),
        ("tmutil disable", "turns Time Machine off"),
    ]);
    check(
        Shell::Posix,
        &posix(),
        &[
            "tmutil listbackups",
            "tmutil latestbackup",
            "tmutil status",
            "tmutil startbackup",
            "tmutil enable",
            "tmutil localsnapshot",
            "tmutil listlocalsnapshots /",
            "tmutil destinationinfo",
            "tmutil",
        ],
        &[],
    );
}

#[test]
fn machine_wide_preferences_are_risky_to_change() {
    risky(&[
        "defaults delete com.apple.dock",
        "defaults delete -g",
        "defaults delete NSGlobalDomain",
        "defaults delete -globalDomain",
        "defaults delete -app Safari",
        "defaults -currentHost delete com.apple.dock",
        "defaults import com.x settings.plist",
        "defaults import -g settings.plist",
        "defaults write /Library/Preferences/com.apple.loginwindow x -bool true",
        "defaults write /Library/Preferences/com.apple.loginwindow",
        "defaults delete /Library/Preferences/com.apple.loginwindow x",
        "defaults write /Library/LaunchDaemons/x.plist Disabled -bool true",
        "defaults rename /Library/Preferences/x a b",
        "defaults write $domain x -bool true",
        "defaults $verb com.x",
        "sudo defaults write /Library/Preferences/x k v",
        "pmset -a sleep 0",
        "pmset -b displaysleep 5",
        "pmset -c sleep 0",
        "pmset -u haltlevel 5",
        "pmset schedule wake '01/01/30 00:00:00'",
        "pmset repeat shutdown MTWRF 23:00:00",
        "pmset restoredefaults",
        "sudo pmset -a disablesleep 1",
        "networksetup -setdnsservers Wi-Fi 1.1.1.1",
        "networksetup -setwebproxy Wi-Fi 127.0.0.1 8080",
        "networksetup -setairportpower en0 off",
        "networksetup -addpreferredwirelessnetworkatindex en0 x 0 WPA2",
        "networksetup -removenetworkservice x",
        "networksetup -createnetworkservice x en1",
        "networksetup -SETDNSSERVERS Wi-Fi empty",
        "scutil --set HostName x",
        "scutil --set ComputerName x",
        "systemsetup -setremotelogin on",
        "systemsetup -settimezone UTC",
        "systemsetup -setcomputersleep Never",
        "hostnamectl set-hostname x",
        "hostnamectl --static set-hostname x",
        "hostnamectl -H me@host set-hostname x",
        "hostnamectl set-icon-name x",
        "timedatectl set-timezone UTC",
        "timedatectl set-time '2030-01-01 00:00:00'",
        "timedatectl set-ntp false",
        "timedatectl set-local-rtc 1",
        "hostname newname",
        "hostname -F /etc/hostname",
        "hostname --file /etc/hostname",
        "hostname $name",
    ]);
    assert_reasons(&[
        (
            "defaults delete com.apple.dock",
            "replaces all of an application's preferences",
        ),
        (
            "defaults write /Library/Preferences/x k v",
            "changes machine-wide preferences",
        ),
        ("pmset -a sleep 0", "changes power settings"),
        (
            "networksetup -setdnsservers Wi-Fi 1.1.1.1",
            "changes system or network settings",
        ),
        (
            "scutil --set HostName x",
            "changes the computer's name or network settings",
        ),
        (
            "systemsetup -setremotelogin on",
            "changes system or network settings",
        ),
        ("hostnamectl set-hostname x", "changes the computer's name"),
        (
            "timedatectl set-timezone UTC",
            "changes the computer's clock settings",
        ),
        ("hostname newname", "changes the computer's name"),
    ]);
}

#[test]
fn reading_settings_and_an_applications_own_preferences_are_safe() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "defaults read com.apple.dock",
            "defaults read",
            "defaults read -g",
            "defaults read NSGlobalDomain AppleLocale",
            "defaults read-type com.apple.dock autohide",
            "defaults export com.apple.dock -",
            "defaults domains",
            "defaults find dock",
            "defaults write com.apple.dock autohide -bool true",
            "defaults write com.example.app key value",
            "defaults write -g ApplePressAndHoldEnabled -bool false",
            "defaults write -app Safari key value",
            "defaults -currentHost write com.apple.x k v",
            "defaults write ~/Library/Preferences/com.example.app.plist k v",
            "defaults write ./app.plist k v",
            "defaults write app.plist k v",
            "defaults delete com.apple.dock persistent-apps",
            "defaults delete -g ApplePressAndHoldEnabled",
            "defaults delete -app Safari key",
            "defaults delete ./app.plist key",
            "defaults rename com.example.app old new",
            "defaults",
            "pmset -g",
            "pmset -g batt",
            "pmset -g assertions",
            "pmset -g log",
            "pmset displaysleepnow",
            "pmset sleepnow",
            "pmset",
            "networksetup -getdnsservers Wi-Fi",
            "networksetup -listallnetworkservices",
            "networksetup -listallhardwareports",
            "networksetup -getinfo Wi-Fi",
            "systemsetup -getremotelogin",
            "systemsetup -gettimezone",
            "systemsetup -listtimezones",
            "scutil --dns",
            "scutil --proxy",
            "scutil --get HostName",
            "hostnamectl",
            "hostnamectl status",
            "hostnamectl --json=pretty status",
            "timedatectl",
            "timedatectl status",
            "timedatectl list-timezones",
            "hostname",
            "hostname -s",
            "hostname -f",
            "hostname -I",
        ],
        &[],
    );
}

#[test]
fn the_same_names_in_powershell_and_cmd_stay_as_they_were() {
    let windows = common::windows();
    for shell in [Shell::PowerShell, Shell::Cmd] {
        check(
            shell,
            &windows,
            &["hostname", "hostname -s", "service stop"],
            &[],
        );
    }
}
