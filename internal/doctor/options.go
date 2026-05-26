package doctor

// Option configures a Run invocation.
type Option func(*config)

// Check is a caller-supplied health check. The function returns a
// CheckResult; the Name field should describe what was checked.
type Check func() CheckResult

// Category groups checks for selective filtering. WithSkipNetwork, for
// example, omits all checks tagged CategoryNetwork.
type Category string

const (
	CategoryCore        Category = "core"        // tools bento can't run without
	CategoryNetwork     Category = "network"     // affects network filtering
	CategoryLimits      Category = "limits"      // affects resource enforcement
	CategoryInterpreter Category = "interpreter" // a script runtime
	CategoryCustom      Category = "custom"      // caller-supplied via WithCheck
)

// registeredCheck pairs a check function with its category for
// filtering. Built-ins and WithCheck values both flow through this
// type so the execution path is uniform.
type registeredCheck struct {
	run      Check
	category Category
}

// config holds the resolved option set.
type config struct {
	skipNetwork  bool
	failFast     bool
	extra        []registeredCheck
	interpreters []string
}

func applyOptions(opts []Option) *config {
	c := &config{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// WithSkipNetwork omits network-dependent checks (libproxychains,
// Landlock TCP support). Useful in CI where these aren't relevant.
func WithSkipNetwork() Option {
	return func(c *config) { c.skipNetwork = true }
}

// WithFailFast stops at the first FAIL. Subsequent checks are not run.
func WithFailFast() Option {
	return func(c *config) { c.failFast = true }
}

// WithCheck appends a caller-supplied check to the built-in set. Run
// after the built-ins; affected by WithFailFast. The check is tagged
// CategoryCustom (not subject to WithSkipNetwork).
func WithCheck(check Check) Option {
	return func(c *config) {
		c.extra = append(c.extra, registeredCheck{run: check, category: CategoryCustom})
	}
}

// WithInterpreters dynamically configures which target runtimes the doctor
// checks for. If empty, the default set (python3, bash, node) is verified.
func WithInterpreters(runtimes ...string) Option {
	return func(c *config) {
		c.interpreters = runtimes
	}
}
