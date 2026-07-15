package observe

// ReportStart is the first line the launcher writes to the observation report,
// once the observer has run to completion. Its presence is how a reader tells a
// real (possibly empty) observation apart from a report the launcher never wrote
// — because the sandbox failed to start, or tracing failed — which would
// otherwise be mistaken for a run that touched nothing.
const ReportStart = "#bento-observe"
