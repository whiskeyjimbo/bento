package observe

// ReportStart is the marker the launcher writes to the observation report as its
// last line, once the observer has run and every record is serialized. Its
// presence means the report is complete, so a reader tells a real (possibly
// empty) observation apart from one the launcher never finished — the sandbox
// failed to start, tracing failed, or the write was truncated — which would
// otherwise be mistaken for a run that touched nothing.
const ReportStart = "#bento-observe"
