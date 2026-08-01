package main

import (
	"os"
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

func parseAccounts(group, passwd string) *accounts {
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
		db.members[uint32(gid)] = named
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

// localAccountsOnly reports whether nsswitch routes users and groups to the files alone.
// A missing nsswitch.conf is glibc's own default of files, and is read that way.
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
		if !ok || (strings.TrimSpace(db) != "passwd" && strings.TrimSpace(db) != "group") {
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
