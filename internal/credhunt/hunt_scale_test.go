package credhunt

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
)

// buildHome plants a tree shaped like a developer home: many ordinary files in nested
// project dirs, a scattering of home-root dotfiles, and a few credential-shaped files.
//
// The root dotfiles are what put the content sniff in the measurement. Nothing under
// proj*/ reaches contentShapes - those files trip no name, suffix or mode signal - so a
// tree of only those measures the walk and the coverage index while leaving the read path
// dark. Their names carry no signal on purpose: at the root the sniff runs on contents
// alone, which is the branch a size-gate regression would land in. Two of them run well
// past MaxFileSize so the bound on the head read is exercised rather than assumed.
func buildHome(tb testing.TB, dirs, filesPerDir int) string {
	tb.Helper()
	home := tb.TempDir()
	for i := 0; i < dirs; i++ {
		d := filepath.Join(home, fmt.Sprintf("proj%02d", i%20), fmt.Sprintf("src/pkg%03d", i))
		if err := os.MkdirAll(d, 0o755); err != nil {
			tb.Fatal(err)
		}
		for j := 0; j < filesPerDir; j++ {
			if err := os.WriteFile(filepath.Join(d, fmt.Sprintf("file%03d.go", j)), []byte("package x\n"), 0o644); err != nil {
				tb.Fatal(err)
			}
		}
	}
	write := func(name string, body []byte) {
		if err := os.WriteFile(filepath.Join(home, name), body, 0o644); err != nil {
			tb.Fatal(err)
		}
	}
	for i := 0; i < 40; i++ {
		write(fmt.Sprintf(".tool%02dconf", i), []byte("theme = dark\nverbose = true\n"))
	}
	// A shell history and an editor session are the realistic large root dotfiles, and
	// they are what makes reading a bounded head rather than the whole file matter.
	big := bytes.Repeat([]byte("cd ~/src/proj && make test\n"), 12000) // ~316 KB
	write(".shell_history", big)
	write(".editor_session", big)
	// The lead the sniff alone can reach: no name token, no suffix, world-readable.
	write(".envfile", []byte("theme = dark\napi_token = sk-0123456789abcdefghijklmnop\n"))
	return home
}

func benchOpts(home string) Options {
	return Options{Home: home, Rules: append(denylist.Home(home), denylist.Runtime("", home)...), MaxFileSize: 1 << 16}
}

// The hunt walks a whole home asking about every entry, so its cost is the walk's
// syscalls plus one coverage question per entry. This is what justifies preparing a
// denylist.Index instead of rescanning the rule set each time: with ~445 rules the
// linear scan measured as the majority of this benchmark, and indexing it took a real
// home from 5.9s to 1.8s with byte-identical output.
func BenchmarkHunt(b *testing.B) {
	home := buildHome(b, 200, 50) // ~10k files
	opts := benchOpts(home)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := Hunt(opts); err != nil {
			b.Fatal(err)
		}
	}
}

// The benchmark can only measure the sniff if the tree it walks reaches it, and it
// reports the same number either way - a tree that plants nothing sniffable reads as a
// clean benchmark rather than a broken one. Pin the reachability here: .envfile trips no
// name, suffix or mode signal, so a token finding on it means contentShapes ran on a
// home-root file, which is the path the benchmark exists to cover.
func TestBuildHomeReachesTheContentSniff(t *testing.T) {
	home := buildHome(t, 2, 2)
	found, _, err := Hunt(benchOpts(home))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(found, func(f Finding) bool {
		return f.Path == filepath.Join(home, ".envfile") && slices.Contains(f.Signals, SignalToken)
	}) {
		t.Errorf("the benchmark tree does not reach the content sniff; found %v", found)
	}
}

// A wrong index looks like a fast one: missing a match makes the hunt stop pruning and
// walk MORE, or descend where it should not. Pin the observable output against the
// linear reference on the same tree.
func TestIndexedHuntMatchesLinear(t *testing.T) {
	home := buildHome(t, 40, 10)
	// Plant something the hunt must find, and something under a shielded store it must
	// prune rather than report.
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh/id_rsa"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "proj00/secret_token.pem"), []byte("-----BEGIN PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := benchOpts(home)

	found, pruned, err := Hunt(opts)
	if err != nil {
		t.Fatal(err)
	}
	// The linear answer, computed the way Hunt used to: same rules, same walk.
	wantCovered := 0
	for _, f := range found {
		if r, ok := denylist.Covers(f.Path, opts.Rules); ok && r.Deny == denylist.DenyAll {
			wantCovered++
		}
	}
	if wantCovered != 0 {
		t.Errorf("%d findings sit under a DenyAll shield; the index missed a prune the linear scan would have made", wantCovered)
	}
	var names []string
	for _, f := range found {
		names = append(names, f.Path)
	}
	if len(found) == 0 {
		t.Fatal("the planted credential was not found at all")
	}
	t.Logf("findings: %d, pruned: %d", len(found), pruned)
	for _, f := range found {
		if strings.Contains(f.Path, "/.ssh/") {
			t.Errorf("a file under the shielded ~/.ssh was reported: %v", names)
		}
	}
	if !slices.ContainsFunc(found, func(f Finding) bool { return strings.HasSuffix(f.Path, "secret_token.pem") }) {
		t.Errorf("the planted unshielded credential was not reported: %v", names)
	}
}
