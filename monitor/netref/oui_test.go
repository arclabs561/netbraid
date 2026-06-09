package netref_test

import (
	"bufio"
	"bytes"
	_ "embed"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/henrywallace/netmon/monitor/netref"
)

//go:embed oui.txt
var ouiBytes []byte

// 00-16-F6   (hex)
var reHexOUI = regexp.MustCompile(`^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)`)

func TestParsing(t *testing.T) {
	// Compare the number of parsed entries to the number of entries in the file
	// file, err := os.Open("oui.txt")
	// if err != nil {
	// 	t.Fatalf("unable to open file: %v", err)
	// }
	// defer file.Close()

	ouis := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(ouiBytes))
	for scanner.Scan() {
		line := scanner.Text()
		match := reHexOUI.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		oui := strings.ToUpper(strings.Replace(match[1], "-", "", -1))
		ouis[oui] = struct{}{}
	}
	if len(ouis) != len(netref.OUIs) {
		t.Errorf("expected to parse %d entries, but got %d", len(ouis), len(netref.OUIs))
	}
	var missing []string
	for oui := range ouis {
		if _, ok := netref.OUIs[oui]; !ok {
			missing = append(missing, oui)
		}
	}
	sort.Strings(missing)
	var extra []string
	for out := range netref.OUIs {
		if _, ok := ouis[out]; !ok {
			extra = append(extra, out)
		}
	}
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("missing %d entries from parsed: %v", len(missing), missing)
	}
	if len(extra) > 0 {
		t.Errorf("parsed %d extra entries: %v", len(extra), extra)
	}
}
