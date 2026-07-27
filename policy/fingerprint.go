package policy

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
)

// Fingerprint is a stable hash of the policy's permission fields. It is what a
// manifest's approval attests: if the fingerprint changes, the permissions
// changed and the manifest must be re-approved.
//
// It covers the fields that define what the sandbox permits - not the manifest's
// formatting, comments, or its own provenance block, so reformatting a manifest
// does not invalidate its approval. Set-like fields (env, read, write, network)
// are sorted so reordering them is not a change; args are kept in order because
// their order is meaningful to the program.
//
// Exec is hashed in canonical form: the zero value hashes as "none", because the
// enforcer treats the two identically. Two policies that permit the same thing but
// spell it differently would otherwise need separate approvals.
//
// The fingerprint says nothing about the *contents* of the entrypoint file: it
// attests the policy, not the code. Swapping the script body under an approved
// manifest still matches - by design, since the manifest governs permissions,
// not code identity.
//
// A nil policy fingerprints as the empty string rather than panicking. That is not a
// sentinel to compare against: it is not valid hex, so it can never equal a real
// fingerprint or a stored approval. Hashing the zero Policy instead would make nil
// collide with an empty-but-real policy, which is the one answer a fingerprint must
// never give.
func (p *Policy) Fingerprint() string {
	if p == nil {
		return ""
	}
	h := sha256.New()
	line := func(format string, args ...any) { fmt.Fprintf(h, format+"\n", args...) }

	line("entrypoint\x00%s", p.Entrypoint)
	line("interpreter\x00%s", p.Interpreter)
	for _, a := range p.Args {
		line("arg\x00%s", a)
	}
	for _, e := range sortedCopy(p.Env) {
		line("env\x00%s", e)
	}
	for _, r := range sortedCopy(p.Read) {
		line("read\x00%s", r)
	}
	for _, w := range sortedCopy(p.Write) {
		line("write\x00%s", w)
	}
	for _, r := range sortedRules(p.Network) {
		line("net\x00%s\x00%s", r.Host, r.Port)
	}
	line("exec\x00%s", p.Exec.canonical())
	line("limits\x00%s\x00%s\x00%d", p.Limits.Memory, p.Limits.CPU, p.Limits.PIDs)

	return hex.EncodeToString(h.Sum(nil))
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

func sortedRules(rules []NetworkRule) []NetworkRule {
	out := slices.Clone(rules)
	slices.SortFunc(out, func(a, b NetworkRule) int {
		return cmp.Or(cmp.Compare(a.Host, b.Host), cmp.Compare(a.Port, b.Port))
	})
	return out
}
