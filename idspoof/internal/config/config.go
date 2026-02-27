package config

// Version variables set via ldflags at build time.
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// Config holds global runtime configuration passed down from CLI flags.
type Config struct {
	Quiet    bool
	Debug    bool
	LogFile  string
	StateDir string
}

// DefaultStateDir is the default location for state persistence.
const DefaultStateDir = "/var/log/idspoof"
