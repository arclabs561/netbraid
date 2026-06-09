package monitor

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arclabs561/netwatch/monitor/netref"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

type Node struct {
	Vendor netref.Vendor `json:"vendor"`
}

// Interface represents a network interface used for monitoring.
type Interface struct {
	net.Interface `json:"iface"`
	Wiphy         *Wiphy        `json:"wiphy"` // TODO: mdlayher/wifi.Interface?
	Vendor        netref.Vendor `json:"vendor"`
	Channels      []int         `json:"channels"`
	Hopper        Hopper        `json:"hopper"` // can be nil, in which case a default hopper will be used
	HopperIndex   int           `json:"hopper_index"`
	HopperTotal   int           `json:"hopper_total"`
}

func (i Interface) String() string {
	return fmt.Sprintf("%v:%s", i.Hopper, i.Name)
}

type keySerial struct {
	mu sync.RWMutex
	m  map[int]int
}

var ks keySerial

func init() {
	ks = keySerial{
		m: make(map[int]int),
	}
}

func (i Interface) SerialIndex() int {
	ks.mu.RLock()
	v, ok := ks.m[i.Index]
	if ok {
		ks.mu.RUnlock()
		return v
	}
	ks.mu.RUnlock()
	ks.mu.Lock()
	defer ks.mu.Unlock()
	v = len(ks.m)
	ks.m[i.Index] = v
	return v
}

func NetInterfaceNames(ifaces []net.Interface) []string {
	var names []string
	for _, iface := range ifaces {
		names = append(names, iface.Name)
	}
	return names
}

func InterfaceNames(ifaces []Interface) []string {
	var names []string
	for _, iface := range ifaces {
		names = append(names, iface.Name)
	}
	return names
}

func (i Interface) Describe() (InterfaceDescription, error) {
	return InterfaceDescription{
		ChannelChoices: nil,
	}, nil
}

type InterfaceDescription struct {
	ChannelChoices []int
}

// FirstGoodInterface returns the name of the first good[^1] interface.
//
// [1]: https://unix.stackexchange.com/a/335082/162041
func FirstGoodInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if !isProbGoodInterface(iface) {
			continue
		}
		iface := iface
		return &iface, nil
	}
	return nil, errors.Errorf("no interfaces found")
}

func AllGoodInterfaces() ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var res []net.Interface
	for _, iface := range ifaces {
		if !isProbGoodInterface(iface) {
			continue
		}
		res = append(res, iface)
	}
	if len(res) == 0 {
		return nil, errors.Errorf("no interfaces found")
	}
	return res, nil
}

// Doesn't filter by only keeping "good" interfaces, as we let the
// regexes completely define what to include.
func FilterInterfaces(res ...*regexp.Regexp) ([]net.Interface, [][]int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	var names []string
	for _, iface := range ifaces {
		names = append(names, iface.Name)
	}
	sort.Strings(names)
	// log.Debug().
	// 	Str("ifaces", fmt.Sprintf("%v", names)).
	// 	Msgf("found %d interfaces", len(ifaces))
	if len(ifaces) == 0 {
		return nil, nil, NoInterfacesError{}
	}
	sort.Slice(ifaces, func(i, j int) bool {
		return ifaces[i].Name < ifaces[j].Name
	})
	var filtered []net.Interface
	var matchesPerIface [][]int          // indices of res matches for each iface
	matchesPerRe := make(map[string]int) // num iface matches per regex string
	for _, iface := range ifaces {
		// We specifically do not filter basics out, as we let the
		// regexes completely define what to include.
		//     if !isGoodInterface(iface) { continue }
		var indsMatch []int
		for i, re := range res {
			if re.MatchString(iface.Name) {
				indsMatch = append(indsMatch, i)
				matchesPerRe[re.String()]++
			}
		}
		if len(indsMatch) == 0 {
			continue
		}
		filtered = append(filtered, iface)
		matchesPerIface = append(matchesPerIface, indsMatch)
	}
	var noMatches []string
	for re, numMatches := range matchesPerRe {
		if numMatches == 0 {
			noMatches = append(noMatches, re)
		}
	}
	if len(noMatches) > 0 && len(ifaces) > 0 {
		// log.Warnf("no interfaces matched regexes %v", noMatches)
		return nil, nil, NoMatchRegexesError{
			NoMatchRegexes: noMatches,
			NumIfaces:      len(ifaces),
		}
	}
	return filtered, matchesPerIface, nil
}

type NoInterfacesError struct{}

func (e NoInterfacesError) Error() string {
	return "no interfaces found"
}

// won't be returned when NumIfaces == 0
type NoMatchRegexesError struct {
	NoMatchRegexes []string
	NumIfaces      int
}

func (e NoMatchRegexesError) Error() string {
	return fmt.Sprintf("some regexes matches none of the %d ifaces: %v", e.NumIfaces, e.NoMatchRegexes)
}

// this function is an approximation of determining whether
// the given iface would be appropriate to listen with,
// absent any derictives from the user.
func isProbGoodInterface(iface net.Interface) bool {
	if iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	if iface.Flags&net.FlagUp == 0 {
		return false
	}
	ignore := []string{"docker", "tailscale"}
	for _, name := range ignore {
		if strings.Contains(iface.Name, name) {
			return false
		}
	}
	return true
}

type Band struct {
	ID       int
	Channels []int
}

func ParseBands() ([]Band, error) {
	// Execute 'iw list' command
	cmd := exec.Command("iw", "list")
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting iw list: %w", err)
	}

	var bands []Band
	var band Band
	var isFreqSection bool

	channelRegex := regexp.MustCompile(`\*\s(\d+)`)

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "\tBand") {
			if band.ID != 0 {
				bands = append(bands, band)
			}
			idStr := strings.TrimSpace(strings.TrimPrefix(line, "\tBand"))
			id, err := strconv.Atoi(idStr)
			if err != nil {
				return nil, fmt.Errorf("error parsing band id: %w", err)
			}
			band = Band{ID: id}
		} else if strings.HasPrefix(line, "\t\tFrequencies") {
			isFreqSection = true
		} else if isFreqSection && strings.HasPrefix(line, "\t\t\t*") {
			match := channelRegex.FindStringSubmatch(line)
			if len(match) == 2 {
				channel, _ := strconv.Atoi(match[1])
				band.Channels = append(band.Channels, channel)
			}
		} else if isFreqSection {
			isFreqSection = false
		}
	}

	// Don't forget the last band
	if band.ID != 0 {
		bands = append(bands, band)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("error waiting for iw list: %w", err)
	}

	// Print all bands and their channels
	for _, band := range bands {
		fmt.Printf("Band %d\n", band.ID)
		fmt.Println("Channels:")
		for _, channel := range band.Channels {
			fmt.Println("\t", channel)
		}
	}

	return bands, nil
}

type Wiphy struct {
	Name  string
	Index int
	// Channels []Channel
	Bands map[int][]Channel
}

func (w Wiphy) ChannelInts() []int {
	var channels []int
	for _, band := range w.Bands {
		for _, ch := range band {
			channels = append(channels, ch.Number)
		}
	}
	return channels
}

func (w Wiphy) Valid() error {
	if w.Name == "" {
		return fmt.Errorf("missing name")
	}
	if w.Index == 0 {
		return fmt.Errorf("missing index")
	}
	return nil
}

type Channel struct {
	Frequency  int
	Number     int
	Properties []string
}

var (
	// "Wiphy phy39"
	reWiphyName = regexp.MustCompile(`^Wiphy (\w+)`)
	// "        wiphy index: 39"
	reWiphyIndex = regexp.MustCompile(`^\s+wiphy index: (\d+)`)
	// "        Band 1:"
	reWiphyBand = regexp.MustCompile(`^\s+Band (\d+):`)
	// "                        * 2437 MHz [6] (20.0 dBm)"
	// "                        * 5720 MHz [144] (20.0 dBm) (no IR, radar detection)"
	// "                        * 5785 MHz [157] (20.0 dBm) (no IR)"
	// "                        * 5845 MHz [169] (disabled)"
	reChannel = regexp.MustCompile(`\s+\* (\d+) MHz \[(\d+)\](?: ?\((.*)\))*`)
)

func parseWiphyOutput(output string) ([]Wiphy, error) {
	lines := strings.Split(output, "\n")
	wiphys := []Wiphy{}
	var currentWiphy *Wiphy
	var currentBand int

	for _, line := range lines {
		submatch := reWiphyName.FindStringSubmatch(line)
		if submatch != nil {
			if currentWiphy != nil {
				if err := currentWiphy.Valid(); err != nil {
					log.Warn().Err(err).Msgf("invalid wiphy, skipping: %#v", currentWiphy)
					continue
				}
				wiphys = append(wiphys, *currentWiphy)
			}
			currentWiphy = &Wiphy{
				Name:  submatch[1],
				Bands: make(map[int][]Channel),
			}
			continue
		}

		submatch = reWiphyIndex.FindStringSubmatch(line)
		if submatch != nil {
			index, err := strconv.Atoi(submatch[1])
			if err != nil {
				return nil, err
			}
			currentWiphy.Index = index
			continue
		}

		submatch = reWiphyBand.FindStringSubmatch(line)
		if submatch != nil {
			band, err := strconv.Atoi(submatch[1])
			if err != nil {
				return nil, err
			}
			currentBand = band
			currentWiphy.Bands[band] = []Channel{}
			continue
		}

		submatch = reChannel.FindStringSubmatch(line)
		if submatch != nil {
			freq, err := strconv.Atoi(submatch[1])
			if err != nil {
				return nil, err
			}
			number, err := strconv.Atoi(submatch[2])
			if err != nil {
				return nil, err
			}
			properties := submatch[3:]
			currentWiphy.Bands[currentBand] = append(currentWiphy.Bands[currentBand], Channel{
				Frequency:  freq,
				Number:     number,
				Properties: properties,
			})
			continue
		}
	}

	if currentWiphy != nil {
		if err := currentWiphy.Valid(); err != nil {
			log.Warn().Err(err).Msgf("invalid wiphy, skipping: %#v", currentWiphy)
		} else {
			wiphys = append(wiphys, *currentWiphy)
		}
	}

	return wiphys, nil
}

// ResolveWiphy returns iface name -> wiphy, wiphy is nil iff iface is not
// a wiphy. If failed to determine if iface is wifi then err is returned.
func ResolveWiphy(rng *rand.Rand) (map[string]*Wiphy, error) {
	ifaces, err := AllGoodInterfaces()
	if err != nil {
		return nil, err
	}
	ifaceToIndex := resolveWiphyNames(rng, ifaces)

	cmd := exec.Command("iw", "list")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run %q: %w", cmd.String(), err)
	}

	wiphys, err := parseWiphyOutput(string(out))
	if err != nil {
		return nil, fmt.Errorf("failed to parse cmd %q output: %w", cmd.String(), err)
	}
	indexToWiphy := make(map[int]Wiphy)
	for _, w := range wiphys {
		if prev, ok := indexToWiphy[w.Index]; ok {
			log.Warn().Msgf("wiphy index %d is already assigned to iface %v", w.Index, prev)
			continue
		}
		indexToWiphy[w.Index] = w
	}

	allWiphys := make(map[string]*Wiphy)
	for i := range ifaces {
		index, ok := ifaceToIndex[ifaces[i].Name]
		if !ok {
			// failure to get info, assumed tobe already logged elsewhere with more info
			continue
		}
		if index < 0 {
			// non-wifi device
			continue
		}
		wiphy, ok := indexToWiphy[index]
		if !ok {
			// wiphy not found for this index, skip
			log.Debug().Int("index", index).Str("iface", ifaces[i].Name).Msg("wiphy not found for index")
			continue
		}
		allWiphys[ifaces[i].Name] = &wiphy
	}

	return allWiphys, nil
}

// func scanThrough(
// 	sc *bufio.Scanner,
// 	reTarget *regexp.Regexp,
// 	reExit ...*regexp.Regexp,
// ) ([]string, *regexp.Regexp) {
// 	for sc.Scan() {
// 		text := sc.Text()
// 		for _, re := range reExit {
// 			if re.MatchString(text) {
// 				return nil, re
// 			}
// 		}
// 		matches := reTarget.FindStringSubmatch(text)
// 		if matches != nil {
// 			return matches, nil
// 		}
// 	}
// 	return nil, nil
// }

// type Wiphy struct {
// 	Name           string
// 	Matched        bool
// 	InterfaceModes []string
// 	Bands          []Band
// }

// type Band struct {
// 	BandNum  int
// 	Channels []int
// }

var reWiphy = regexp.MustCompile(`wiphy (\d+)`)
var reUsage = regexp.MustCompile(`(?i)usage`)

// return iface name to wiphy index
func resolveWiphyNames(rng *rand.Rand, ifaces []net.Interface) map[string]int {
	// TODO: Determine why iw dev doesn't return all iface name -> wiphy
	// mappings, but they do come back from iw dev list. And hence have to
	// recourse to requiring an ifaces []string argument to this function.
	wiphy := make(map[string]int)
loopIfaces:
	for _, iface := range ifaces {
		const (
			maxAttempts = 2
			initSleep   = 50 * time.Millisecond
			maxSleep    = 1 * time.Second
			maxDuration = 5 * time.Second
			jitter      = 10 * time.Millisecond
		)
		var (
			sleep   = initSleep
			out     string
			success bool
			start   = time.Now()
		)
		for attempt := 0; attempt < maxAttempts; attempt++ {
			cmd := exec.Command("iw", "dev", iface.Name, "info") // nolint:gosec
			b, err := cmd.CombinedOutput()
			out = strings.TrimSpace(string(b))
			if err == nil {
				if attempt > 0 {
					log.Warn().Stringer("dur", time.Since(start)).
						Msgf("resolved wiphy for iface %v after %d attempts", iface, attempt)
				}
				success = true
				break
			}
			if reUsage.MatchString(out) {
				log.Fatal().Err(err).Msgf("usage error for iface %v: %s", iface, out)
			}
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				if exitErr.ExitCode() == 151 {
					sleep *= 2
					sleep += time.Duration(rng.Int63n(int64(jitter)))
					if sleep > maxSleep {
						sleep = maxSleep
					}
					log.Debug().Err(err).
						Int("attempt", attempt).
						Stringer("sleep", sleep.Round(time.Microsecond)).
						Stringer("dur", time.Since(start).Round(time.Millisecond)).
						Msgf("failed to get info for iface %s, retrying: %s", iface.Name, out)
					time.Sleep(sleep)
					continue
				}
				// not a wifi device
				if exitErr.ExitCode() == 237 && strings.Contains(out, "No such device") {
					wiphy[iface.Name] = -1
					continue loopIfaces
				}
			}
			log.Warn().Err(err).Msgf("failed to get info for iface %s: %s", iface.Name, out)
			continue loopIfaces
		}
		if !success {
			log.Warn().Stringer("dur", time.Since(start)).
				Msgf("failed to resolve wiphy for iface %s after %d failed attempts", iface.Name, maxAttempts)
			continue loopIfaces
		}

		// $ iw dev wlan0 info
		// Interface wlan0
		// 	ifindex 42
		// 	wdev 0x2500000001
		// 	addr 00:00:00:00:00:00
		// 	type monitor
		// 	wiphy 2
		// 	channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
		// 	txpower 20.00 dBm
		submatch := reWiphy.FindStringSubmatch(out)
		if submatch == nil {
			log.Warn().Msgf("failed to parse %s wiphy index from: %s", iface.Name, out)
			continue
		}
		index, err := strconv.Atoi(submatch[1])
		if err != nil {
			log.Warn().Msgf("failed to parse %s wiphy index as int from: %s", iface.Name, submatch[1])
			continue
		}
		wiphy[iface.Name] = index
	}
	return wiphy
}
