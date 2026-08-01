package main

import (
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// groupHoldsOnly reports whether the account database proves that a group holds nobody but
// uid - the case a group-write bit grants no one anything. It is the ordinary state on a
// distro with per-user private groups, where a umask of 002 leaves every directory the user
// creates 0775 owned by a group with a single member, and reading that as shared warns
// about a reader nobody can be.
//
// Proof, not absence of evidence: a gid the database does not name, a member it names but
// cannot resolve, or files it cannot read all answer false, and the caller warns. Root is
// not counted, for the reason foreignOwner does not count it - it can write anywhere
// regardless, so its membership describes no widening.
func groupHoldsOnly(gid, uid uint32) bool {
	return accountDB().holdsOnly(gid, uid)
}

func (db *accounts) holdsOnly(gid, uid uint32) bool {
	if db == nil {
		return false
	}
	members, named := db.members[gid]
	if !named {
		return false
	}
	for _, name := range members {
		member, known := db.uidByName[name]
		if !known || (member != uid && member != 0) {
			return false
		}
	}
	for _, member := range db.primary[gid] {
		if member != uid && member != 0 {
			return false
		}
	}
	return true
}

// accounts is /etc/passwd and /etc/group in the two shapes the membership question asks
// for: who a group names, and who holds it as their login group without being named.
type accounts struct {
	members   map[uint32][]string
	primary   map[uint32][]uint32
	uidByName map[string]uint32
}

// accountDB reads the files once. Every directory on the path to a manifest asks the same
// question, and the answer cannot change within a single command.
var accountDB = sync.OnceValue(func() *accounts {
	// Only where the files are the whole database. A directory service merges its own
	// members into a local group, so a local entry that names nobody proves nothing there,
	// and the one wrong answer this can give is to call such a group private. nss-systemd is
	// no such source: it serves transient service users and groups of its own and adds
	// nobody to an existing one.
	if !localAccountsOnly() {
		return nil
	}
	group, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil
	}
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	return parseAccounts(string(group), string(passwd))
})

// parseAccounts reads the two files into the shapes the membership question asks for, or
// nil where they cannot answer it at all: a compat `+` or `-` entry merges a directory
// service's users and groups into the local ones, so what the files say about a gid is no
// longer the whole of it. That routing is nsswitch's `compat`, which nsswitchIsLocal
// already rejects - the entries are honoured here too, since glibc's built-in default when
// there is no nsswitch.conf is compat rather than files.
func parseAccounts(group, passwd string) *accounts {
	if hasCompatEntry(group) || hasCompatEntry(passwd) {
		return nil
	}
	db := &accounts{
		members:   map[uint32][]string{},
		primary:   map[uint32][]uint32{},
		uidByName: map[string]uint32{},
	}
	for _, line := range strings.Split(group, "\n") {
		// name:passwd:gid:member,member
		f := strings.Split(line, ":")
		if len(f) < 4 {
			continue
		}
		gid, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			continue
		}
		var named []string
		for _, member := range strings.Split(f[3], ",") {
			if member != "" {
				named = append(named, member)
			}
		}
		// Appended, not assigned: glibc reads membership from every line naming a gid, so a
		// second line for one already seen adds members rather than replacing them, and
		// letting it replace them is how a group with a member would read as private.
		db.members[uint32(gid)] = append(db.members[uint32(gid)], named...)
	}
	for _, line := range strings.Split(passwd, "\n") {
		// name:passwd:uid:gid:...
		f := strings.Split(line, ":")
		if len(f) < 4 {
			continue
		}
		uid, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			continue
		}
		gid, err := strconv.ParseUint(f[3], 10, 32)
		if err != nil {
			continue
		}
		db.uidByName[f[0]] = uint32(uid)
		db.primary[uint32(gid)] = append(db.primary[uint32(gid)], uint32(uid))
	}
	return db
}

// hasCompatEntry reports the NIS merge lines of the compat routing - `+`, `+name`, `-name`
// at the start of a line - whose presence means the file is a base the rest is merged onto
// rather than the whole database.
func hasCompatEntry(file string) bool {
	for _, line := range strings.Split(file, "\n") {
		if strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			return true
		}
	}
	return false
}

// localAccountsOnly reports whether nsswitch routes users, groups and membership to the
// files alone. A missing nsswitch.conf leaves glibc's built-in default, which is compat -
// merged, not local - but compat with no `+` or `-` entry in either file merges nothing,
// and parseAccounts is what refuses the ones that do.
func localAccountsOnly() bool {
	conf, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		return os.IsNotExist(err)
	}
	return nsswitchIsLocal(string(conf))
}

func nsswitchIsLocal(conf string) bool {
	for _, line := range strings.Split(conf, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		db, sources, ok := strings.Cut(line, ":")
		// initgroups as well as group: it routes supplementary membership on its own, and a
		// host that keeps groups local while resolving membership over LDAP - which is the
		// point of splitting them, since enumerating a directory's groups is expensive - would
		// otherwise read as local while people are joined to local gids from elsewhere.
		if !ok || !slices.Contains([]string{"passwd", "group", "initgroups"}, strings.TrimSpace(db)) {
			continue
		}
		for _, source := range strings.Fields(sources) {
			// The action after a source - [NOTFOUND=return] - qualifies the one before it
			// rather than naming another database.
			if strings.HasPrefix(source, "[") {
				continue
			}
			if source != "files" && source != "systemd" {
				return false
			}
		}
	}
	return true
}
