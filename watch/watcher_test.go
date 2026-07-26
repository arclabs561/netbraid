package watch

import (
	"strings"
	"testing"
)

func TestTriggerConfigRejectsShellExecution(t *testing.T) {
	for name, spec := range map[string]TriggerSpec{
		"action":    {OnAny: true, DoShell: "echo {{.Description}}"},
		"predicate": {OnShell: "test {{.Host.IPv4}}", DoBuiltin: "log"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newTriggerFromConfig(spec)
			if err == nil || !strings.Contains(err.Error(), "shell triggers are disabled") {
				t.Fatalf("expected shell trigger rejection, got %v", err)
			}
		})
	}
}

func TestTriggerConfigAcceptsBuiltin(t *testing.T) {
	trigger, err := newTriggerFromConfig(TriggerSpec{
		OnAny:     true,
		DoBuiltin: "null",
	})
	if err != nil {
		t.Fatalf("expected built-in trigger, got %v", err)
	}
	if !trigger.ShouldDo(Event{}) {
		t.Fatal("expected onAny trigger to accept event")
	}
}
