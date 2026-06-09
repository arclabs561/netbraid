package netref

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"strings"
)

//go:generate ./regen-oui

//go:embed oui.txt
var ouiBytes []byte

// Vendor represents a network equipment manufacturer, often a company,
// that owns a unique Organizationally Unique Identifier (OUI).
//
// An OUI is a 24-bit number that is purchased from the IEEE and is unique to every company
// that purchases one. The OUI often forms the first 3 bytes of the MAC address of their equipment.
type Vendor struct {
	// HexPrefix is the hexadecimal representation of the vendor's unique OUI.
	// It forms the first 3 bytes of a MAC address for the network hardware produced by the vendor.
	HexPrefix string

	// Company is the name of the company or organization that owns the OUI.
	// This is often the name of the network equipment manufacturer.
	Company string

	// Address is the physical address of the company or organization that owns the OUI.
	// This is typically the head office or primary location of the
	// organization. The last element will always be
	// a 2-letter ISO 3166-1 alpha-2 country code, representing the country
	// where the organization is located.
	Address []string
}

// OUIs is a map where the keys are OUIs represented as hexadecimal strings and the values
// are Vendor struct instances. Each Vendor instance corresponds to a network equipment
// manufacturer that owns the OUI.
//
// This map provides a quick lookup from OUI to Vendor, allowing efficient determination
// of the vendor details based on the first 3 bytes of a MAC address.
var OUIs map[string]Vendor

var reBase16 = regexp.MustCompile(`^([0-9a-fA-F]{6})\s+\(base 16\)\s+(.*)$`)
var reHex = regexp.MustCompile(`^([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})\s+\(hex\)\s+(.*)$`)

func init() {
	OUIs = make(map[string]Vendor)
	// OUI/MA-L                                                    Organization
	// company_id                                                  Organization
	//                                                             Address
	//
	// 1A-2B-3C   (hex)                Acme
	// 1A2B3C     (base 16)            Acme
	//                                 123 Corporation Road
	//                                 Corpville    12345
	//                                 US
	//
	// 2B-3C-4D   (hex)                Private
	// 2B3C4D     (base 16)            Private
	//
	// 3C-4D-5E   (hex)                MomCorp
	// 3C4D5E     (base 16)            MomCorp
	//
	//                                 US
	//
	// 4D-5E-6F   (hex)                Globex
	// ...
	scanner := bufio.NewScanner(bytes.NewReader(ouiBytes))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		groups := reBase16.FindStringSubmatch(line)
		if groups == nil {
			continue
		}

		vendor := Vendor{}

		vendor.HexPrefix = groups[1]
		if vendor.HexPrefix == "" {
			panic(fmt.Sprintf("no hex prefix parse on line %d: %q", lineNum, line))
		}

		vendor.Company = groups[2]
		if vendor.Company == "" {
			panic(fmt.Sprintf("no company name parse on line %d: %q", lineNum, line))
		}

		if strings.ToLower(vendor.Company) != "private" {
			for i := 0; i < 3; i++ {
				scanner.Scan()
				lineNum++
				line := scanner.Text()
				if reHex.MatchString(line) || reBase16.MatchString(line) {
					panic(fmt.Sprintf("oui found when parsing address on line %d: %q", lineNum, line))
				}
				address := strings.TrimSpace(line)
				if address == "" {
					continue
				}
				vendor.Address = append(vendor.Address, address)
			}
		}

		OUIs[vendor.HexPrefix] = vendor
	}
}
