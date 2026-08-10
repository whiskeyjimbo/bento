package trust

import "github.com/whiskeyjimbo/bento/manifest"

// ApprovalState describes how a manifest's stored approval relates to its current
// policy. It is unkeyed local drift detection, not authentication: it records that the
// permissions match what was stamped, never who stamped them. What the location vouches
// for is the separate question Flaws answers.
type ApprovalState int

const (
	ApprovalUnstamped ApprovalState = iota // no provenance approval recorded
	ApprovalCurrent                        // stored fingerprint matches the policy
	ApprovalStale                          // policy changed since it was approved
)

func CheckApproval(doc *manifest.Document) ApprovalState {
	switch doc.Provenance.Approves {
	case "":
		return ApprovalUnstamped
	case doc.Policy.Fingerprint():
		return ApprovalCurrent
	default:
		return ApprovalStale
	}
}
