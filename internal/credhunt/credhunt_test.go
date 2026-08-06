package credhunt

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/whiskeyjimbo/bento/internal/denylist"
)

// plant writes a file at home/rel, creating its parents.
func plant(t *testing.T, home, rel string, mode os.FileMode, content string) string {
	t.Helper()
	p := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile honors the umask, which on a developer host would turn a 0600 plant into
	// something else and make the mode signal untestable.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func hunt(t *testing.T, home string) []Finding {
	t.Helper()
	found, _, _, err := Hunt(Options{Home: home, Rules: denylist.Home(home), MaxFileSize: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func paths(found []Finding) []string {
	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, f.Path)
	}
	return out
}

// The hunt's whole value is finding what the deny-list does not already cover, so a path
// inside a shielded store must stay silent no matter how credential-shaped it is - it is
// already unreachable in the sandbox, and reporting it would bury the leads that matter.
// The complement is the reason the tool exists: the developer token stores neither
// upstream corpus lists.
func TestHuntReportsOnlyUnshieldedShapes(t *testing.T) {
	home := t.TempDir()
	plant(t, home, ".ssh/id_ed25519", 0o600, "-----BEGIN OPENSSH PRIVATE KEY-----\n")
	plant(t, home, ".aws/credentials", 0o600, "aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n")
	uncovered := plant(t, home, ".config/some-new-tool/api-token", 0o600, "token: sk-0123456789abcdefghijklmnop\n")
	plant(t, home, "notes.txt", 0o644, "nothing to see\n")

	got := paths(hunt(t, home))
	if !slices.Contains(got, uncovered) {
		t.Errorf("an unshielded credential-shaped file must surface; got %v", got)
	}
	for _, p := range []string{filepath.Join(home, ".ssh/id_ed25519"), filepath.Join(home, ".aws/credentials")} {
		if slices.Contains(got, p) {
			t.Errorf("%s is inside a shielded store and must not be reported; got %v", p, got)
		}
	}
	if slices.Contains(got, filepath.Join(home, "notes.txt")) {
		t.Errorf("an ordinary world-readable file must not be a finding; got %v", got)
	}
}

// An editor leaving of a dotfile at the home root holds the same secret as the original
// under a name the deny-list cannot enumerate - the class audit.ReviewedGlobs records as
// an accepted residual precisely because it is not expressible as a concrete path. This
// tool is what makes it enumerable, so it must report the concrete path rather than
// suppressing it for matching a recorded glob.
func TestHuntSurfacesEditorLeavingsAtTheHomeRoot(t *testing.T) {
	home := t.TempDir()
	swap := plant(t, home, ".ssh_config.swp", 0o600, "IdentityFile ~/.ssh/id_rsa\n")
	backup := plant(t, home, ".netrc.bak", 0o600, "password = correct-horse-battery-staple\n")
	emacs := plant(t, home, ".pgpass~3~", 0o600, "localhost:5432:db:user:hunter2\n")
	tilde := plant(t, home, ".boto~", 0o600, "nothing token-shaped in here\n")

	got := paths(hunt(t, home))
	for _, p := range []string{swap, backup, emacs, tilde} {
		if !slices.Contains(got, p) {
			t.Errorf("%s is the enumerable form of a recorded residual and must be reported; got %v", p, got)
		}
	}
}

// The signals are what a reader triages on, so each has to fire for its own reason and
// not stand in for another. A private-mode file with no credential name is still a lead;
// a credential-named file that is world-readable is a weaker one; and content is only
// consulted for a file a cheap signal already flagged.
func TestSignalsFireIndependently(t *testing.T) {
	home := t.TempDir()
	plant(t, home, "opaque", 0o600, "nothing shaped like a secret\n")
	plant(t, home, "deploy-key.txt", 0o644, "-----BEGIN RSA PRIVATE KEY-----\n")
	plant(t, home, "settings.toml", 0o600, "api_token = \"abcdefghijklmnopqrstuvwxyz0123\"\n")

	bySignals := map[string][]string{}
	for _, f := range hunt(t, home) {
		bySignals[filepath.Base(f.Path)] = f.Signals
	}
	for name, want := range map[string][]string{
		// A private mode with nothing else is not a finding at all: measured on a real
		// home it fires on tens of thousands of package-cache artifacts.
		"opaque":         nil,
		"deploy-key.txt": {SignalName, SignalPEM},
		"settings.toml":  {SignalPrivateMode, SignalToken},
	} {
		if got := bySignals[name]; !slices.Equal(got, want) {
			t.Errorf("%s fired %v, want %v", name, got, want)
		}
	}
}

// A token assignment is what separates a stored secret from an ordinary setting, so the
// value shape has to carry that weight: a short value is a mode or a boolean, and a path
// or URL under a key-named setting points AT a secret rather than being one - that file
// is hunted on its own shape.
func TestTokenAssignmentDistinguishesSecretsFromSettings(t *testing.T) {
	for _, line := range []string{
		"password = correcthorsebatterystaple",
		"  _authToken: ghp_0123456789abcdefghijklmnop",
		"\"api_key\" = \"AKIAIOSFODNN7EXAMPLEabcd\"",
	} {
		if !tokenAssignment(line) {
			t.Errorf("tokenAssignment(%q) = false, want true", line)
		}
	}
	for _, line := range []string{
		"password = short",                            // a value too short to be a token
		"IdentityFile /home/u/.ssh/id_rsa",            // no assignment operator
		"certificate = /etc/ssl/certs/my-long-ca.pem", // a path to a secret, not the secret
		"key_url = https://example.invalid/keys/mine", // likewise a pointer
		"verbose = true",                              // not a secret-named key
		"passphrase = this is a long human sentence",  // whitespace: prose, not an opaque token
	} {
		if tokenAssignment(line) {
			t.Errorf("tokenAssignment(%q) = true, want false", line)
		}
	}
}

// Only the FIRST separator on a line is tested, so a secret-named key later on the same
// line is not reached. That is a measured choice rather than an oversight: scanning every
// separator was tried three ways against the population a real hunt sniffs on a developer
// home, and each added thousands of hits on telemetry JSON, agent transcripts and minified
// JS while reaching not one config that holds a secret this way. Bounding the key to the
// text just before the separator, which is what stops the whole line's prefix from
// counting as the key, also dropped real matches the single-separator form already makes.
// This pins the shape so the next person to notice it sees the trade before retrying it.
func TestTokenAssignmentReadsOnlyTheFirstSeparator(t *testing.T) {
	line := `{"model":"opus","createdAt":"2026-08-04","apiToken":"sk-0123456789abcdefghijklmnop"}`
	if tokenAssignment(line) {
		t.Errorf("tokenAssignment(%q) = true; widening past the first separator costs more than it finds", line)
	}
}

// The sniff bound is a bound on the READ, not a size a file has to be under to be opened.
// A real ~/.claude.json measured 96 KB with a token-shaped assignment in its first few KB;
// gating on the whole file's size discarded it unread, and the name trips nothing else, so
// the store this most wants to surface was reported nowhere.
func TestHuntSniffsTheHeadOfAFileLargerThanTheBound(t *testing.T) {
	home := t.TempDir()
	big := plant(t, home, ".sometool.json", 0o600,
		"{\n  \"apiToken\": \"0123456789abcdefghijklmnop\",\n  \"history\": [\n"+
			strings.Repeat("    \"a line of ordinary recorded history\",\n", 4000)+"  ]\n}\n")

	if info, err := os.Stat(big); err != nil {
		t.Fatal(err)
	} else if info.Size() <= 64<<10 {
		t.Fatalf("the fixture is %d bytes, which does not exceed the bound it must outgrow", info.Size())
	}
	for _, f := range hunt(t, home) {
		if f.Path == big {
			if !slices.Contains(f.Signals, SignalToken) {
				t.Errorf("%s surfaced without the content signal: %v", big, f.Signals)
			}
			return
		}
	}
	t.Errorf("a 96 KB token store was never opened; the bound gated the file rather than the read")
}

// A config written as one long line is ordinary, and a bufio.Scanner reports a line past
// its buffer through an Err() a Scan loop never consults - so the sniff returned "no
// shapes", which is byte-identical to a clean file. A silent give-up is the failure this
// tool exists to avoid, so the head is read and split rather than scanned.
func TestHuntSniffsPastAVeryLongLine(t *testing.T) {
	home := t.TempDir()
	// A leading line past bufio.Scanner's 64 KiB default buffer, with the assignment after
	// it and the bound set well clear of both - a scanner gives up on the first line and
	// never reaches the second, where a plain read of the head has both in hand.
	long := plant(t, home, ".longline.conf", 0o600,
		"# "+strings.Repeat("y", 100<<10)+"\napi_token = 0123456789abcdefghijklmnop\n")

	found, _, _, err := Hunt(Options{Home: home, Rules: denylist.Home(home), MaxFileSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		if f.Path == long {
			if !slices.Contains(f.Signals, SignalToken) {
				t.Errorf("the sniff stopped at the long line and reported no shapes: %v", f.Signals)
			}
			return
		}
	}
	t.Errorf("%s was not reported at all", long)
}

// A mode-0644 ~/.env holding an AWS secret trips no name token, no suffix, no editor
// leaving and no private mode, so nothing but its contents can reach it - and the sniff
// used to run only for a file some cheap signal had already flagged. The home root is
// where the files no vocabulary enumerates live, which is the class this tool is most for,
// so it is sniffed on position; the thousands of files below it still are not.
func TestHuntSniffsTheHomeRootOnPosition(t *testing.T) {
	home := t.TempDir()
	env := plant(t, home, ".env", 0o644, "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n")
	deep := plant(t, home, "notes/scratch/jotting", 0o644, "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n")

	got := paths(hunt(t, home))
	if !slices.Contains(got, env) {
		t.Errorf("a world-readable .env at the home root reaches no signal but its contents; got %v", got)
	}
	if slices.Contains(got, deep) {
		t.Errorf("%s is not at the home root, and sniffing on position there would be a full-tree read; got %v", deep, got)
	}
}

// The walk asks whether an entry is the root and whether its parent is, and filepath.Dir
// answers with a cleaned path. A caller that spells Home with a trailing separator would
// match neither test, turning the home-root sniff off and reporting a clean home - so the
// root is cleaned once and every comparison is against that.
func TestHuntAcceptsAnUncleanHome(t *testing.T) {
	home := t.TempDir()
	env := plant(t, home, ".env", 0o644, "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n")

	found, _, _, err := Hunt(Options{Home: home + string(filepath.Separator), Rules: denylist.Home(home), MaxFileSize: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(paths(found), env) {
		t.Errorf("a trailing separator on Home silently switched off the home-root sniff; got %v", paths(found))
	}
}

// A source checkout is workspace surface - bento governs it through a write grant and
// denylist.Workspace, never through a home shield - and on a developer home it is where
// essentially every hit comes from, which makes the report unreadable. But the home
// itself is commonly a dotfiles checkout, and pruning THAT scans nothing and reports a
// clean home: a silent wrong answer, which is the failure this tool exists to avoid.
func TestHuntPrunesCheckoutsButNeverTheScanRoot(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	atRoot := plant(t, home, ".some-tool-token", 0o600, "token = 0123456789abcdefghijklmnop\n")
	if err := os.MkdirAll(filepath.Join(home, "src/proj/.git"), 0o755); err != nil {
		t.Fatal(err)
	}
	inCheckout := plant(t, home, "src/proj/config/auth.go", 0o600, "const apiKey = \"0123456789abcdefghijklmnop\"\n")

	got := paths(hunt(t, home))
	if !slices.Contains(got, atRoot) {
		t.Errorf("the home is a dotfiles checkout, but its own entries must still be scanned; got %v", got)
	}
	if slices.Contains(got, inCheckout) {
		t.Errorf("%s is inside a nested checkout and must be pruned as workspace surface; got %v", inCheckout, got)
	}
}

// A machine store is pruned as content-addressed artifacts rather than the user's own
// files, but the prune must be visible: an operator who cannot see that the tool narrowed
// cannot tell a clean home from a scan that skipped the interesting part.
func TestMachineStoresArePrunedAndCounted(t *testing.T) {
	home := t.TempDir()
	cache := filepath.Join(home, ".cache")
	plant(t, home, ".cache/pkg/some-token", 0o600, "token = 0123456789abcdefghijklmnop\n")
	kept := plant(t, home, ".some-tool/api-token", 0o600, "token = 0123456789abcdefghijklmnop\n")

	found, pruned, _, err := Hunt(Options{Home: home, Rules: denylist.Home(home), MachineStores: []string{cache}, MaxFileSize: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := paths(found); !slices.Equal(got, []string{kept}) {
		t.Errorf("findings = %v, want only %s - the machine store must be pruned", got, kept)
	}
	if pruned != 1 {
		t.Errorf("pruned = %d, want 1; a prune the operator cannot see is a suppression", pruned)
	}
}

// DenyWrite leaves a path READABLE - it stops a plant, it does not hide a secret - so it
// must not read as coverage. The agent config trees are DenyWrite exactly so the agent can
// read its own settings, and each carries a separate DenyAll rule on the credential file
// inside; treating the tree as covered would prune the very files this hunts.
func TestDenyWriteIsNotCoverage(t *testing.T) {
	home := t.TempDir()
	inWriteShield := plant(t, home, ".claude/some-tool-token", 0o600, "token = 0123456789abcdefghijklmnop\n")
	hidden := plant(t, home, ".claude/.credentials.json", 0o600, "token = 0123456789abcdefghijklmnop\n")

	got := paths(hunt(t, home))
	if !slices.Contains(got, inWriteShield) {
		t.Errorf("%s sits under a DenyWrite tree, which leaves it readable, so it must surface; got %v", inWriteShield, got)
	}
	if slices.Contains(got, hidden) {
		t.Errorf("%s has its own DenyAll rule and must not be reported; got %v", hidden, got)
	}
}

// A home that cannot be walked yields zero findings, which reads as a clean home - the
// silent wrong answer this tool exists to avoid. Every other error is skipped and the walk
// continues, but the root is worth refusing over.
func TestHuntRefusesAnUnwalkableRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-home")
	found, _, _, err := Hunt(Options{Home: missing, Rules: nil, MaxFileSize: 64 << 10})
	if err == nil {
		t.Errorf("Hunt over a nonexistent home returned %d findings and no error; a clean report over a scan that never happened is the failure this refuses", len(found))
	}
}

// A relocated or bind-mounted home reaches Hunt as a symlink - HomeAnchors resolves
// neither anchor - and the walk Lstats its root, so the scan ends on the first entry and
// reports the same clean home as a nonexistent one. Refusing must name the target, because
// the shields are lexical: the operator's fix is to re-anchor on the resolved path, where
// the walk and the deny-list finally agree.
func TestHuntRefusesASymlinkedHome(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real-home")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	plant(t, real, ".some-tool-token", 0o600, "token = 0123456789abcdefghijklmnop\n")
	link := filepath.Join(root, "home")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	found, _, _, err := Hunt(Options{Home: link, Rules: denylist.Home(link), MaxFileSize: 64 << 10})
	if err == nil {
		t.Fatalf("Hunt over a symlinked home returned %d findings and no error; the walk never entered it", len(found))
	}
	if !strings.Contains(err.Error(), real) {
		t.Errorf("the refusal must name the path to re-anchor on; got %v", err)
	}
}

// A directory the scan cannot list narrows it exactly as a prune does - it reports zero
// findings under a subtree it never saw - so it has to be counted for the same reason.
func TestUnreadableDirectoryIsCounted(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 directory")
	}
	home := t.TempDir()
	plant(t, home, "closed/api-token", 0o600, "token = 0123456789abcdefghijklmnop\n")
	closed := filepath.Join(home, "closed")
	if err := os.Chmod(closed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(closed, 0o700) })

	found, _, unreadable, err := Hunt(Options{Home: home, Rules: denylist.Home(home), MaxFileSize: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("findings = %v, want none - the subtree is unreadable", paths(found))
	}
	if unreadable != 1 {
		t.Errorf("unreadable = %d, want 1; a scan that could not look must not read as a clean home", unreadable)
	}
}
