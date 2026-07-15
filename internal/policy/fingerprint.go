package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
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
// The fingerprint says nothing about the *contents* of the entrypoint file: it
// attests the policy, not the code. Swapping the script body under an approved
// manifest still matches - by design, since the manifest governs permissions,
// not code identity.
func (p *Policy) Fingerprint() string {
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
	line("exec\x00%s", p.Exec)
	line("limits\x00%s\x00%s\x00%d", p.Limits.Memory, p.Limits.CPU, p.Limits.PIDs)

	return hex.EncodeToString(h.Sum(nil))
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func sortedRules(rules []NetworkRule) []NetworkRule {
	out := append([]NetworkRule(nil), rules...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out
}
