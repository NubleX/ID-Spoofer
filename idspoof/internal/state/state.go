package state

// Manager is the interface for persistent key/value state.
type Manager interface {
	Get(key string) (string, bool)
	Set(key, value string) error
	Delete(key string) error
	All() (map[string]string, error)
}
