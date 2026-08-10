package main

import (
	"fmt"
	"io"
	"os"

	"github.com/whiskeyjimbo/bento/manifest"
	"github.com/whiskeyjimbo/bento/trust"
)

// warnStampAtRisk reports who besides this user can change the manifest - but only for a
// manifest carrying an approval stamp, which is the only thing the warning is about. An
// unstamped one is the profile-then-run inner loop, run with --allow-unapproved, where
// there is nothing yet to devalue and the warning is inapplicable; left unconditional it
// fired on every command of that loop, twice, on any host whose umask is 002. A reader
// learns within a day that [bento] lines are noise, which is the same shape as the lines
// they will someday need read - an accepted alias, a shielded-grant opt-in, a degraded
// layer. approve does not go through here: there a human is establishing the trust, so
// the state of the location is the decision being made.
func warnStampAtRisk(w io.Writer, doc *manifest.Document, mt trust.Manifest) {
	if doc.Provenance.Approves == "" {
		return
	}
	warnUntrusted(w, mt.Flaws(uint32(os.Geteuid())))
}

// warnUntrusted reports every flaw as advisory. The read commands do not refuse on one:
// a permissive umask or a shared checkout is ordinary, and failing run and validate over
// it would break working setups to describe a risk the user may already accept. approve,
// where a human is establishing the trust, does refuse.
func warnUntrusted(w io.Writer, flaws []trust.Flaw) {
	for _, f := range flaws {
		fmt.Fprintf(w, "[bento] %s - its approval stamp attests only what whoever can write it leaves there.\n", f.Reason)
		if f.Hint != "" {
			fmt.Fprintf(w, "[bento] %s\n", f.Hint)
		}
	}
}
