package trust

import (
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// groupReach is what the account database could establish about a group: whether its
// write bit reaches anybody besides uid. Three-valued because the question is - a group
// PROVEN to hold other people is a different fact from one nothing could be learned
// about, and collapsing them leaves a caller unable to refuse the first without also
// refusing every host where the second is the only answer available.
type groupReach uint8

const (
	// groupUnknown is the zero value on purpose: facts assembled without a lookup must
	// read as nothing established rather than as a group proven to hold nobody.
	groupUnknown groupReach = iota
	groupPrivate
	groupShared
)

// groupReachOf answers the membership question from the account database. groupPrivate is
// the ordinary state on a distro with per-user private groups, where a umask of 002 leaves
// every directory the user creates 0775 owned by a group with a single member, and reading
// that as shared warns about a reader nobody can be.
//
// Proof either way, never absence of evidence: a gid the database does not name, a member
// it names but cannot resolve, or files it cannot read all answer groupUnknown. Root is not
// counted, for the reason foreignOwner does not count it - it can write anywhere regardless,
// so its membership describes no widening.
func groupReachOf(gid, uid uint32) groupReach {
	return accountDB().reach(gid, uid)
}

func (db *accounts) reach(gid, uid uint32) groupReach {
	if db == nil {
		return groupUnknown
	}
	members, named := db.members[gid]
	if !named {
		return groupUnknown
	}
	// A resolvable other member is proof and ends it; an unresolvable name only withholds
	// proof, so the scan finishes before settling for that - a group naming both holds
	// somebody whatever the one it could not resolve turns out to be.
	unresolved := false
	for _, name := range members {
		member, known := db.uidByName[name]
		switch {
		case !known:
			unresolved = true
		case member != uid && member != 0:
			return groupShared
		}
	}
	for _, member := range db.primary[gid] {
		if member != uid && member != 0 {
			return groupShared
		}
	}
	if unresolved {
		return groupUnknown
	}
	return groupPrivate
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
	for line := range strings.SplitSeq(group, "\n") {
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
		for member := range strings.SplitSeq(f[3], ",") {
			if member != "" {
				named = append(named, member)
			}
		}
		// Appended, not assigned: glibc reads membership from every line naming a gid, so a
		// second line for one already seen adds members rather than replacing them, and
		// letting it replace them is how a group with a member would read as private.
		db.members[uint32(gid)] = append(db.members[uint32(gid)], named...)
	}
	for line := range strings.SplitSeq(passwd, "\n") {
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
	for line := range strings.SplitSeq(file, "\n") {
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
	for line := range strings.SplitSeq(conf, "\n") {
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
		for source := range strings.FieldsSeq(sources) {
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
