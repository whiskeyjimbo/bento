package main

import "testing"

// The per-user private group is the case this exists for: a 0775 directory owned by a group
// with one member grants write to nobody but its owner, and warning about it fires on every
// command of every Debian-style host, where umask 002 leaves that mode everywhere.
func TestGroupHoldsOnly(t *testing.T) {
	const group = `root:x:0:
adm:x:4:syslog,jrose,alloy
sudo:x:27:jrose
jrose:x:1000:
shared:x:1200:
wheel:x:1300:ghost
`
	const passwd = `root:x:0:0::/root:/bin/sh
syslog:x:104:110::/nonexistent:/usr/sbin/nologin
alloy:x:105:112::/nonexistent:/usr/sbin/nologin
jrose:x:1000:1000::/home/jrose:/bin/zsh
peer:x:1001:1200::/home/peer:/bin/zsh
`
	db := parseAccounts(group, passwd)
	const me = 1000
	for name, tc := range map[string]struct {
		gid  uint32
		want bool
	}{
		"private group holds only its owner":            {1000, true},
		"a named member who is us is not somebody else": {27, true},
		"a group naming other people is shared":         {4, false},
		"a login group somebody else holds is shared":   {1200, false},
		"a member passwd cannot resolve is not proof":   {1300, false},
		"a gid the database does not name is not proof": {4242, false},
		"root can write anywhere, so its group is ours": {0, true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := db.holdsOnly(tc.gid, me); got != tc.want {
				t.Errorf("holdsOnly(%d, %d) = %v, want %v", tc.gid, me, got, tc.want)
			}
		})
	}

	// Nothing read means nothing proven, which is the answer that warns.
	var unread *accounts
	if unread.holdsOnly(1000, me) {
		t.Error("a database that could not be read proves nothing")
	}

	// glibc reads membership from every line naming a gid, so a second line for one adds
	// members rather than replacing them.
	twice := parseAccounts("jrose:x:1000:peer\njrose:x:1000:\n", passwd)
	if twice.holdsOnly(1000, me) {
		t.Error("a member named on an earlier line for the same gid is still in the group")
	}

	// A compat entry makes the files a base something else is merged onto, so nothing in
	// them is the whole story about any group.
	for name, tc := range map[string]struct{ group, passwd string }{
		"a merged group": {"jrose:x:1000:\n+:::\n", passwd},
		"a merged user":  {group, passwd + "+@staff\n"},
		"an exclusion":   {group, passwd + "-ghost\n"},
	} {
		t.Run(name, func(t *testing.T) {
			if parseAccounts(tc.group, tc.passwd).holdsOnly(1000, me) {
				t.Error("files a directory service is merged into prove nothing on their own")
			}
		})
	}
}

// A directory service merges its own members into a local group, so a local entry naming
// nobody proves nothing there. nss-systemd is not such a source: it serves transient users
// and groups of its own rather than adding people to an existing one.
func TestNsswitchIsLocal(t *testing.T) {
	for name, tc := range map[string]struct {
		conf string
		want bool
	}{
		"files alone":            {"passwd: files\ngroup: files\n", true},
		"debian default":         {"passwd:         files systemd\ngroup:          files systemd\n", true},
		"an action qualifier":    {"group: files [SUCCESS=merge] systemd\n", true},
		"ldap merges members":    {"passwd: files\ngroup: files ldap\n", false},
		"initgroups is its own":  {"passwd: files\ngroup: files\ninitgroups: ldap\n", false},
		"sssd merges members":    {"group: sss files\n", false},
		"another database":       {"hosts: files dns myhostname\n", true},
		"a commented-out source": {"group: files # ldap\n", true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := nsswitchIsLocal(tc.conf); got != tc.want {
				t.Errorf("nsswitchIsLocal(%q) = %v, want %v", tc.conf, got, tc.want)
			}
		})
	}
}
