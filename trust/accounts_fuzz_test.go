package trust

import (
	"slices"
	"strings"
	"testing"
)

// FuzzParseAccountsRefusesCompat holds the compat refusal to the whole input rather
// than to the spellings a table thought of. A `+` or `-` at the start of any line of
// either file means a directory service is merged onto these entries, so what the
// files say about a gid is no longer the whole of it and the database cannot answer
// the membership question at all. Answering anyway is the failure that matters: it
// calls a group with remote members private, and approve refuses on that.
func FuzzParseAccountsRefusesCompat(f *testing.F) {
	f.Add("root:x:0:\njrose:x:1000:\n", "jrose:x:1000:1000::/home/jrose:/bin/sh\n")
	f.Add("+:::\n", "jrose:x:1000:1000::/home/jrose:/bin/sh\n")
	f.Add("root:x:0:\n", "+jrose\n")
	f.Add("root:x:0:\n", "-nobody\n")
	f.Add("shared:x:1200:a,b\n+@netgroup\n", "")
	// The marker inside a line rather than at its start, which merges nothing.
	f.Add("shared:x:1200:a,+b\n", "jrose:x:1000:1000::/h:/bin/sh\n")

	f.Fuzz(func(t *testing.T, group, passwd string) {
		db := parseAccounts(group, passwd)
		compat := false
		for _, line := range append(strings.Split(group, "\n"), strings.Split(passwd, "\n")...) {
			if strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
				compat = true
			}
		}
		if compat && db != nil {
			t.Fatalf("answered a merged database:\ngroup %q\npasswd %q", group, passwd)
		}
		if !compat && db == nil {
			t.Fatalf("refused a database with no compat entry:\ngroup %q\npasswd %q", group, passwd)
		}
	})
}

// FuzzParseAccountsMembershipIsMonotone pins the append-not-assign the parser's own
// comment records: glibc reads membership from every line naming a gid, so a later
// line for a gid already seen ADDS members. Letting it replace them is how a group
// that has a member reads as private - the one wrong answer this file can give -
// and nothing catches its reintroduction today, because the table only ever poses
// two lines for one gid in a single spelling.
//
// The oracle is that appending a line may only extend a gid's membership: with lines
// parsed in order, the members the base alone yields must remain a prefix of what
// base-plus-line yields, for every gid. An assignment would truncate or replace it.
func FuzzParseAccountsMembershipIsMonotone(f *testing.F) {
	f.Add("root:x:0:\njrose:x:1000:\n", "jrose:x:1000:peer\n")
	f.Add("shared:x:1200:a,b\n", "shared:x:1200:c\n")
	f.Add("shared:x:1200:a,b\n", "other:x:1200:\n")
	f.Add("", "shared:x:1200:a\n")
	f.Add("shared:x:1200:a\n", "")
	f.Add("shared:x:1200:a\n", "not a group line")

	f.Fuzz(func(t *testing.T, group, extra string) {
		base := parseAccounts(group, "")
		grown := parseAccounts(group+"\n"+extra, "")
		// A compat entry in either body makes both sides unanswerable; the refusal is
		// the other target's subject, and there is nothing to compare here.
		if base == nil || grown == nil {
			return
		}
		for gid, was := range base.members {
			now := grown.members[gid]
			if len(now) < len(was) || !slices.Equal(now[:len(was)], was) {
				t.Fatalf("appending %q to gid %d: members went from %q to %q - a later line replaced rather than added",
					extra, gid, was, now)
			}
		}
	})
}
