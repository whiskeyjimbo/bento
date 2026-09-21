package main

import (
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/whiskeyjimbo/bento/backend"
	"github.com/whiskeyjimbo/bento/enforce"
	"github.com/whiskeyjimbo/bento/internal/denylist"
	"github.com/whiskeyjimbo/bento/policy"
)

func newDoctorCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Report what this host can actually enforce",
		Long: "doctor is the single place that tells the whole truth about this host.\n\n" +
			"Each layer is reported as enforced, degraded, or unavailable, with the reason.\n" +
			"Core layers are the guarantees bento makes everywhere; a core layer that falls\n" +
			"short refuses a run by default. Hardening layers have no equivalent on every\n" +
			"platform - a run that needs one proceeds and says so, except where the platform\n" +
			"cannot install it at all: a manifest that asked to block subprocess execution is\n" +
			"refused there rather than run without the fence, and --allow-degraded waives it.",
		Args: noArgs(),
		RunE: func(cmd *cobra.Command, args []string) error {
			// A host with no backend has no layers to report, which is doctor's own
			// answer rather than a foreign refusal envelope: a CI gate reading `ready`
			// gets false because doctor said so, not because the key went missing.
			if err := checkPlatform(); err != nil {
				// The envelope is written first so a machine consumer still gets a
				// parseable answer on stdout, and the refusal then goes to stderr and
				// the same exit as the human mode's, exactly as validate's does.
				if asJSON {
					envelope := doctorJSON{
						reportJSON:       noReport,
						Platform:         platformName(),
						PlatformVerified: platformVerified(),
						Reason:           err.Error(),
					}
					if err := writeJSON(os.Stdout, envelope); err != nil {
						return err
					}
				}
				return err
			}
			e, err := backend.New()
			if err != nil {
				return err
			}
			report := e.Probe(cmd.Context())

			// A host that cannot anchor its shields refuses every run, and no layer status
			// carries that: newSandbox fails before any tier is chosen, so Probe never sees
			// it. Asked here so the machine surface and the exit code say what the human
			// output on the same invocation already does.
			anchors, anchorErr := denylist.HomeAnchors()

			// doctor exits non-zero for a shortfall that refuses a run nobody had to ask
			// for: a guarantee EVERY run needs, or the exec block the DEFAULT manifest
			// asks for by saying nothing (policy's Exec zero value is ExecNone). So a CI
			// wrapper can gate on host readiness without parsing output and without the
			// verdict disagreeing with what the next `bento run` does. A
			// conditionally-required core layer (network egress control) and a hardening
			// layer a manifest has to name still let runs proceed, so they are reported
			// but stay exit 0.
			//
			// Not because a run needing one is refused at run time: enforce.Run refuses a
			// non-degraded run on an Unavailable network layer whether or not the manifest
			// declared any egress (run.go's "no network namespace to fence egress into"),
			// so a ready verdict here would be a ready verdict for a host that runs
			// nothing. What actually holds it is the Linux probe: it ties LayerNetwork
			// Unavailable to the same missing namespace that makes filesystemLayer report
			// Degraded or Unavailable, and filesystem IS in the baseline, so the gate below
			// fires anyway. That is one fact in another package, and nothing here would stop
			// compiling if it moved, so it is pinned where it lives - internal/linux's
			// TestAnUnavailableNetworkLayerNeverLeavesFilesystemEnforced.
			shortfall := len(gatedShortfall(report)) > 0
			refusedByDefault := undeliverableDefaultExecBlock(report)

			if asJSON {
				if err := writeJSON(os.Stdout, toDoctorJSON(report, anchors, anchorErr)); err != nil {
					return err
				}
				if shortfall || len(refusedByDefault) > 0 || anchorErr != nil {
					return &exitError{code: doctorCoreShortfall}
				}
				return nil
			}

			writePlatform(os.Stdout)
			writeReportTable(os.Stdout, report)
			fmt.Println()
			writeShieldAnchors(os.Stdout)
			// Before the layer verdict, because this refuses every run whatever the layers
			// say, and unlike a core-layer shortfall there is no flag that opts into it.
			if anchorErr != nil {
				fmt.Println("Runs are refused here until the shields can be anchored. --allow-degraded")
				fmt.Println("does not help: the anchors decide where the shields land, not how they hold.")
				return &exitError{code: doctorCoreShortfall}
			}
			if shortfall {
				fmt.Println("A core guarantee every run needs is not fully enforced here. Runs are refused")
				fmt.Println("by default; --allow-degraded opts into a weaker sandbox, knowingly.")
				return &exitError{code: doctorCoreShortfall}
			}
			if len(refusedByDefault) > 0 {
				fmt.Println("This platform cannot install the subprocess exec block at all, so the default")
				fmt.Println("manifest - which asks for it by saying nothing about exec - is refused here.")
				fmt.Println("Pass --allow-degraded to run without the block, knowingly.")
				return &exitError{code: doctorCoreShortfall}
			}
			if short := report.Degradations(); len(short) > 0 {
				writeDegradedSummary(os.Stdout, short)
				return nil
			}
			fmt.Println("This host enforces every layer.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the enforcement matrix as JSON")
	return cmd
}

// gatedShortfall returns the shortfalls doctor fails its exit code on: the guarantees
// every manifest needs regardless of its contents. It derives that set from
// enforce.BaselineLayers rather than naming a layer here, so the gate cannot drift from
// what admission actually requires - a conditionally-required layer like network egress
// (needed only by a manifest that declares egress) is reported in the table but does not
// gate.
//
// A host whose network layer is Unavailable does NOT still run the manifests that never
// asked for egress: enforce.Run refuses those too, because there is no namespace to fence
// egress into and only the degraded tier substitutes anything for one. This gate stays in
// sync with it through the Linux probe's coupling rather than through the predicate - see
// the exit-code comment in newDoctorCmd.
// undeliverableDefaultExecBlock returns the layers the DEFAULT manifest asks for and
// this host cannot provide at all. It is the other half of doctor's gate: BaselineLayers
// is derived over an `exec: all` policy, so the exec layers are never in it, and a host
// that has never had the filter - every arm64 one, since the foreign-arch guard it rests
// on is amd64-only - would otherwise report ready while admission refuses the manifest a
// caller gets by writing no exec: line at all.
//
// The set comes from enforce.RequiredLayers over the zero policy rather than from naming
// exec here, so it stays what the default manifest really needs. The bar is Unavailable,
// matching enforce's undeliverableExecBlock: a Degraded exec-strict layer still blocks
// execve, which is a weaker fence rather than no fence, and admission does not refuse it.
// That agreement is one fact in another package and nothing here stops compiling if it
// moves, so it is pinned by TestDoctorGatesOnTheSameExecBarAdmissionRefusesOn.
func undeliverableDefaultExecBlock(r enforce.Report) []enforce.LayerStatus {
	needed := enforce.RequiredLayers(&policy.Policy{}, enforce.Options{})
	var out []enforce.LayerStatus
	for _, l := range r.Layers {
		if l.State >= enforce.Unavailable && l.Layer.Tier() == enforce.TierHardening && slices.Contains(needed, l.Layer) {
			out = append(out, l)
		}
	}
	return out
}

func gatedShortfall(r enforce.Report) []enforce.LayerStatus {
	gate := make(map[enforce.Layer]bool)
	for _, l := range enforce.BaselineLayers() {
		gate[l] = true
	}
	var out []enforce.LayerStatus
	for _, l := range r.Degradations() {
		if gate[l.Layer] {
			out = append(out, l)
		}
	}
	return out
}

// doctorOutputJSON is doctor's envelope on a probed host: the matrix and verdict, and the
// facts writeShieldAnchors prints about where the credential shields land, each under
// the key validate or run already gives the same fact.
type doctorOutputJSON struct {
	doctorJSON
	// ShieldAnchorHomes are the homes the shields anchor on, absent where they cannot be.
	ShieldAnchorHomes []string `json:"shield_anchor_homes,omitempty"`
	// NoUsablePasswdHome says $HOME is the only anchor, so whoever sets the environment
	// decides where the shields land.
	NoUsablePasswdHome bool `json:"no_usable_passwd_home,omitempty"`
	// LibcNSSPasswdLookup says the passwd lookup behind the anchors runs through the
	// host's NSS modules, which a caller can steer.
	LibcNSSPasswdLookup     bool              `json:"libc_nss_passwd_lookup,omitempty"`
	UnshieldableRuntimeDir  string            `json:"unshieldable_runtime_dir,omitempty"`
	UnshieldableRelocations map[string]string `json:"unshieldable_relocations,omitempty"`
	NestedAnchors           []anchorNesting   `json:"nested_anchors,omitempty"`
	// RelocatedShields maps each variable that moved a built-in shield to its new paths.
	RelocatedShields map[string][]string `json:"relocated_shields,omitempty"`
	// TruncatedStores names the credential stores the symlink expansion did not walk
	// whole, so whatever they link out to below that point is unshielded. Two causes on
	// one key: the store nests deeper than the walk bound, or a directory inside it could
	// not be read.
	TruncatedStores []string `json:"truncated_stores,omitempty"`
}

// toDoctorJSON builds the doctor JSON output. Ready derives from the same two gates and
// anchor error as the exit code, so the field a JSON consumer reads and the process
// status a shell caller reads can never disagree.
func toDoctorJSON(r enforce.Report, anchors []string, anchorErr error) doctorOutputJSON {
	out := doctorOutputJSON{
		doctorJSON: doctorJSON{
			reportJSON:       toReportJSON(r),
			Ready:            len(gatedShortfall(r)) == 0 && len(undeliverableDefaultExecBlock(r)) == 0 && anchorErr == nil,
			Platform:         platformName(),
			PlatformVerified: platformVerified(),
		},
		// Said in both branches, as the human output does: a passwd lookup made to fail is
		// how an NSS build loses its anchor.
		LibcNSSPasswdLookup: !pureUserLookup,
	}
	if anchorErr != nil {
		out.ShieldAnchors = anchorErr.Error()
		return out
	}
	out.ShieldAnchorHomes = anchors
	if pw := denylist.PasswdHome(); pw == "" || pw == "/" {
		out.NoUsablePasswdHome = true
	}
	out.UnshieldableRuntimeDir = denylist.UnshieldableRuntimeDir(anchors)
	out.UnshieldableRelocations = denylist.UnshieldableRelocations(anchors)
	out.NestedAnchors = nestedAnchors(anchors)
	out.RelocatedShields = relocatedShields()
	out.TruncatedStores = truncatedStores()
	return out
}
