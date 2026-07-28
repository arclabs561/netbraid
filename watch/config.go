package watch

// Config holds configuration for Triggers.
type Config struct {
	Triggers map[string]TriggerSpec `toml:"triggers"`
}

// TriggerSpec describes specification for one trigger.
type TriggerSpec struct {
	Disabled       bool        `toml:"disabled"`
	OnEvents       []EventType `toml:"onEvents"`
	OnEventsExcept []EventType `toml:"onEventsExcept"`
	OnAny          bool        `toml:"onAny"`
	OnShell        string      `toml:"onShell"`
	DoBuiltin      string      `toml:"doBuiltin"`
	DoShell        string      `toml:"doShell"`
}
