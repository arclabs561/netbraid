package cmd

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/RoaringBitmap/roaring"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"github.com/samber/mo"
	"github.com/sourcegraph/conc/pool"
	"github.com/spf13/cobra"

	"github.com/arclabs561/netwatch/cmd/internal/csp"
	"github.com/arclabs561/netwatch/internal/logutil"
	"github.com/arclabs561/netwatch/monitor"
	"github.com/arclabs561/netwatch/monitor/netref"
)

var rootCmd = &cobra.Command{
	Use:          "netmon",
	Short:        "capture packet and RF-channel observations to PCAP and JSONL",
	RunE:         rootRunE,
	SilenceUsage: true,
}

func init() {
	rootCmd.PersistentFlags().StringP("log-level", "L", "fatal", "logging level")
	rootCmd.PersistentFlags().StringP("log-format", "F", "auto", "logging format")
	rootCmd.PersistentFlags().StringP("log-color", "c", "auto", "logging color")
	rootCmd.PersistentFlags().BoolP("log-color-always", "C", false, "whether to always log with color")

	rootCmd.Flags().BoolP("quiet", "q", false, "don't print packet info")
	rootCmd.Flags().StringArrayP("iface", "i", nil, "regex to match interfaces to monitor with")
	rootCmd.Flags().IntP("iface-limit", "l", 0, "limit on number of interfaces to use")
	rootCmd.Flags().BoolP("all-ifaces", "I", false, "monitor all active interfaces")
	rootCmd.Flags().StringP("auto-stop", "a", "never", `criterion to stop writing to a capture file, of the form test:value`)
	rootCmd.Flags().StringP("hop-strategy", "H", "uniform", "set default strategy for channel hopping")
	rootCmd.Flags().StringP("out", "o", ".", "directory to write pcaps and event data to")
	rootCmd.Flags().BoolP("summary", "S", false, "dynamically display summary, instead of printing individual packet info")
	rootCmd.Flags().StringArrayP("filter", "f", nil, "filter to apply to packets to only print, but does not affect writing to pcap")
	rootCmd.Flags().BoolP("dry-run", "n", false, "don't actually start monitoring, instead just print info")
	rootCmd.Flags().BoolP("only-start", "s", false, "whether to only start and ready interfaces, and listen only until opening handle is successful")
	rootCmd.Flags().Int("iface-expect", 0, "num ifaces to expect to monitor, fail if not met")
	rootCmd.Flags().Bool("cluster-start", false, "whether to start cluster")
	rootCmd.Flags().String("cluster-join", "", "token to join existing cluster with given token")
}

func initLogger(
	ctx context.Context,
	cmd *cobra.Command,
	args []string,
) context.Context {
	logLevel, err := zerolog.ParseLevel(mustString(cmd, "log-level"))
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	logFormat := mustString(cmd, "log-format")
	logColor := mustString(cmd, "log-color")
	if mustBool(cmd, "log-color-always") {
		logColor = "always"
	}
	return logutil.InitGlobalLogger(ctx, logutil.LoggerOptions{
		Level:  mo.Some(logLevel),
		Format: mo.Some(logFormat),
		Color:  mo.Some(logColor),
	})
}

func rootRunE(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	ctx = initLogger(ctx, cmd, args)

	rng := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec

	ifaces, err := resolveInterfaces(rng, resolveConfig{
		ifaceLimit: mustInt(cmd, "iface-limit"),
		allIfaces:  mustBool(cmd, "all-ifaces"),
		ifaces:     mustStringArray(cmd, "iface"),
	})
	if err != nil {
		return fmt.Errorf("failed to resolve interfaces: %w", err)
	}
	if mustInt(cmd, "iface-expect") > 0 && len(ifaces) != mustInt(cmd, "iface-expect") {
		return fmt.Errorf(
			"expected %d interfaces, got %d: %v",
			mustInt(cmd, "iface-expect"),
			len(ifaces),
			ifaces,
		)
	}
	opts := []monitor.MonitorOption{
		monitor.OptMonitorDataDir(mustString(cmd, "out")),
		monitor.OptMonitorOnlyStart(mustBool(cmd, "only-start")),
	}
	if mustBool(cmd, "quiet") || mustBool(cmd, "summary") {
		opts = append(opts, monitor.OptMonitorQuiet(true))
	}
	if filters := mustStringArray(cmd, "filter"); len(filters) > 0 {
		for _, fstr := range filters {
			f, err := monitor.ParseFilter(fstr)
			if err != nil {
				return fmt.Errorf("failed to parse filter %q: %w", fstr, err)
			}
			opts = append(opts, monitor.OptMonitorFilter(*f))
		}
	}
	if a := mustString(cmd, "auto-stop"); a != "" {
		autoStopOpts, err := parseAutoStop(a)
		if err != nil {
			return err
		}
		opts = append(opts, autoStopOpts...)
	}
	if hopStrategy := mustString(cmd, "hop-strategy"); hopStrategy != "" {
		h, err := parseHopperStrategy(hopStrategy)
		if err != nil {
			return fmt.Errorf("invalid hop strategy: %q", hopStrategy)
		}
		opts = append(opts, monitor.OptMonitorDefaultHopper(h))
	}
	mon, err := monitor.NewMonitor(opts...)
	if err != nil {
		return fmt.Errorf("failed to create monitor: %w", err)
	}

	if mustBool(cmd, "dry-run") || mustBool(cmd, "only-start") {
		if err := describeInterfaces(ifaces); err != nil {
			return err
		}
		if mustBool(cmd, "dry-run") {
			return nil
		}
	}

	wait := gracefulExit(mon)
	p := pool.New().WithErrors().WithContext(ctx).WithFirstError()
	p.Go(func(ctx context.Context) error {
		if err := mon.Listen(ctx, ifaces...); err != nil {
			return fmt.Errorf("failed to listen: %w", err)
		}
		return nil
	})
	if mustBool(cmd, "summary") {
		goSummary(mon, p)
	}
	if err := p.Wait(); err != nil {
		return err
	}
	mon.WithAggregate(func(agg *monitor.Aggregate) {
		log.Info().
			Int("num_ifaces", agg.Global.NumInterfaces).
			Int("packets", agg.Global.PacketsTotal).
			Stringer("dur", agg.Global.Dur).
			Int("maxStep", agg.Global.MaxStep).
			Msgf("done monitoring")
	})
	wait()
	return nil
}

func parseAutoStop(autoStopRaw string) ([]monitor.MonitorOption, error) {
	parts := strings.Split(autoStopRaw, ":")
	switch len(parts) {
	case 1:
		switch strings.TrimSpace(strings.ToLower(parts[0])) {
		case "never":
			// default behavior
			return nil, nil
		}
		dur, err := time.ParseDuration(parts[0])
		if err == nil {
			return []monitor.MonitorOption{monitor.OptMonitorStopDur(dur)}, nil
		}
		return nil, fmt.Errorf("invalid auto-stop: %q", autoStopRaw)
	case 2:
		switch strings.TrimSpace(strings.ToLower(parts[0])) {
		case "dur":
			dur, err := time.ParseDuration(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid auto-stop duration: %q", parts[1])
			}
			return []monitor.MonitorOption{monitor.OptMonitorStopDur(dur)}, nil
		default:
			return nil, fmt.Errorf("invalid auto-stop test (valid dur): %q", parts[0])
		}

	default:
		return nil, fmt.Errorf("invalid auto-stop: %q", autoStopRaw)
	}
}

func goSummary(mon *monitor.Monitor, p *pool.ContextPool) {
	var app *tview.Application
	var textView *tview.TextView
	app = tview.NewApplication()
	textView = tview.NewTextView()
	textView.SetChangedFunc(func() {
		app.Draw()
	})
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC {
			app.Stop()
		}
		return event
	})
	display := time.NewTicker(100 * time.Millisecond)
	p.Go(func(ctx context.Context) error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-display.C:
				app.QueueUpdateDraw(func() {
					mon.WithAggregate(func(agg *monitor.Aggregate) {
						textView.Clear()
						_, err := fmt.Fprint(textView, summary(*agg, 20))
						if err != nil {
							log.Error().Err(err).Msg("failed to write summary")
						}
					})
				})
			}
		}
	})
	p.Go(func(ctx context.Context) error {
		if err := app.SetRoot(textView, true).Run(); err != nil {
			return fmt.Errorf("failed to run app: %w", err)
		}
		return nil
	})
}

func gracefulExit(mon *monitor.Monitor) func() {
	var wg sync.WaitGroup
	var terminate sync.Once
	signals := make(chan os.Signal, 1)

	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		var count int
		for sig := range signals {
			log.Debug().Int("count", count).
				Str("signal", fmt.Sprintf("%#v", sig)).
				Msgf("received signal: %v", sig)
			count++
			if count > 1 {
				signal.Stop(signals)
				if n, ok := sig.(syscall.Signal); ok {
					os.Exit(128 + int(n))
				}
				os.Exit(1)
			}

			terminate.Do(func() {
				wg.Add(1)
				go func() {
					defer wg.Done()
					start := time.Now()
					if err := mon.Stop(); err != nil {
						log.Fatal().Err(err).Msg("failed to stop monitor")
					}
					log.Debug().Stringer("dur", time.Since(start).Round(time.Microsecond)).
						Msgf("gracefully stopped monitor")
				}()
			})
		}
	}()
	return func() { wg.Wait() }
}

type resolveConfig struct {
	ifaceLimit int
	allIfaces  bool
	ifaces     []string
}

func resolveInterfaces(
	rng *rand.Rand,
	cfg resolveConfig,
) ([]monitor.Interface, error) {
	ifaces, err := resolveIfacesFlat(rng, cfg)
	if err != nil {
		return nil, err
	}
	sort.Slice(ifaces, func(i, j int) bool {
		return ifaces[i].Name < ifaces[j].Name
	})
	byHopper := make(map[monitor.Hopper][]*monitor.Interface)
	for i := range ifaces {
		byHopper[ifaces[i].Hopper] = append(byHopper[ifaces[i].Hopper], &ifaces[i])
	}

	for _, ifaces := range byHopper {
		for i, iface := range ifaces {
			// Set index to with respect to ifaces with its hopper
			// up to pointer.
			iface.HopperIndex = i
			iface.HopperTotal = len(ifaces)
		}
	}
	return ifaces, nil
}

// Represents a specification to match a set of compatible interfaces. The
// regexp must be matched, and all of the clauses must be each
// satisfied as well, if non-nil. Each clause describes a a sub-spec applied
// to a subset of interfaces matching the regexp.
type ifaceSpec struct {
	Regexp  *regexp.Regexp    // must be non-nil
	Clauses []ifaceSpecClause // may be nil
}

// Match returns true if the interface matches the specification.
func (s ifaceSpec) Match(iface net.Interface) bool {
	return s.Regexp.MatchString(iface.Name)
}

// And individual clause from an ifaceSpec. The cardinality constraint
// indicates how many interfaces must match the clause. If there aren't enough
// matching interfaces, the clause is not satisfied.
type ifaceSpecClause struct {
	// The number of interfaces that must match the clause.
	Cardinality cardConst
	// Which channels the interface must have. If empty, any channel is
	// compatible.
	Channels []int

	// The hopper that should be assigned to each interface. Does NOT
	// affect compatibility.
	Hopper monitor.Hopper
}

// Exactly one must be present.
type cardConst struct {
	Eq   mo.Option[int]
	Lt   mo.Option[int]
	LtEq mo.Option[int]
	Gt   mo.Option[int]
	GtEq mo.Option[int]
}

func (cc cardConst) valid() error {
	x := 0
	if cc.Eq.IsPresent() {
		x++
	}
	if cc.Lt.IsPresent() {
		x++
	}
	if cc.LtEq.IsPresent() {
		x++
	}
	if cc.Gt.IsPresent() {
		x++
	}
	if cc.GtEq.IsPresent() {
		x++
	}
	if x > 1 {
		return fmt.Errorf("cardinality constraint must have at most one value, got %d", x)
	}
	return nil
}

func (cc cardConst) IsZero() bool {
	return cc.Eq.IsAbsent() && cc.Lt.IsAbsent() && cc.LtEq.IsAbsent() && cc.Gt.IsAbsent() && cc.GtEq.IsAbsent()
}

// The results of matching against an ifaceSpecClause. Contains overlapping
// details of a match if one exists, and is applicable to the interface.
type SpecClauseMatch struct {
	Channels []int
}

// Match returns whether this spec clause matches the given iface, with
// optional wiphy. If the iface is LAN, for example, then wiphy would be
// nil. Returns nil, true iff the spec matches the iface, and wiphy is nil.
func (c ifaceSpecClause) Match(iface net.Interface, wiphy *monitor.Wiphy) (*SpecClauseMatch, bool) {
	// If there's no wiphy, we can still match if no channels are required
	// or if we're on a platform where wiphy info isn't available (like macOS)
	if wiphy == nil {
		// If no channels specified in clause, match any interface
		if len(c.Channels) == 0 {
			return &SpecClauseMatch{
				Channels: nil,
			}, true
		}
		// If channels are specified but no wiphy info, we can't verify
		// but we'll allow it (platform limitation)
		return &SpecClauseMatch{
			Channels: c.Channels,
		}, true
	}
	supported := lo.SliceToMap(wiphy.ChannelInts(), func(ch int) (int, bool) {
		return ch, true
	})
	// Check if spec channels is overlapping with supported
	// channels, and then return that overlap.
	var overlap []int
	for _, ch := range c.Channels {
		if _, ok := supported[ch]; ok {
			overlap = append(overlap, ch)
		}
	}
	// If channels are specified but none match, return false
	// If no channels specified, match any
	if len(c.Channels) > 0 && len(overlap) == 0 {
		return nil, false
	}
	return &SpecClauseMatch{
		Channels: overlap,
	}, true
}

func resolveIfacesFlat(
	rng *rand.Rand,
	cfg resolveConfig,
) ([]monitor.Interface, error) {
	wiphys, err := monitor.ResolveWiphy(rng)
	if err != nil {
		log.Error().Err(err).Msg("failed to resolve wiphy")
	}

	if cfg.allIfaces {
		netIfaces, err := monitor.AllGoodInterfaces()
		if err != nil {
			return nil, err
		}
		availNetIfaces := netIfaces
		if cfg.ifaceLimit > 0 && len(netIfaces) > cfg.ifaceLimit {
			netIfaces = netIfaces[:cfg.ifaceLimit]
		}
		names := monitor.NetInterfaceNames(netIfaces)
		log.Info().Msgf("using %d/%d interfaces: %v", len(netIfaces), len(availNetIfaces), names)
		var ifaces []monitor.Interface
		for _, netIface := range netIfaces {
		wiphy := wiphys[netIface.Name]
		channels := []int{}
		if wiphy != nil {
			channels = wiphy.ChannelInts()
		}
		ifaces = append(ifaces, monitor.Interface{
			Interface: netIface,
			Channels:  channels,
		})
		}
		return ifaces, nil
	}

	var ifaces []monitor.Interface

	if len(cfg.ifaces) == 0 {
		var err error
		first, err := monitor.FirstGoodInterface()
		if err != nil {
			return nil, err
		}
		log.Info().Msgf("using first up interface: %v", first)
		wiphy := wiphys[first.Name]
		channels := []int{}
		if wiphy != nil {
			channels = wiphy.ChannelInts()
		}
		ifaces = append(ifaces, monitor.Interface{
			Interface: *first,
			Channels:  channels,
		})
	}

	var specs []ifaceSpec
	for _, specStr := range cfg.ifaces {
		spec, err := parseSpec(specStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse interface spec %q: %w", specStr, err)
		}
		specs = append(specs, *spec)
	}
	// Configured interfaces per spec, per clause, and their serial
	// indices.
	var specMatches [][][]monitor.Interface
	var specMatchIndices [][][]int // serial indices
	for _, spec := range specs {
		ifaceMatches, _, err := monitor.FilterInterfaces(spec.Regexp)
		if err != nil {
			return nil, fmt.Errorf("failed to filter interfaces with %v: %w", spec.Regexp, err)
		}
		// If spec has no clauses, create a default clause that matches any interface
		if len(spec.Clauses) == 0 {
			var matches []monitor.Interface
			var matchIndices []int
			for _, iface := range ifaceMatches {
				wiphy := wiphys[iface.Name]
				channels := []int{}
				if wiphy != nil {
					channels = wiphy.ChannelInts()
				}
				monIface := monitor.Interface{
					Interface: iface,
					Hopper:    monitor.NewUniformHopper(),
					Channels:  channels,
				}
				matches = append(matches, monIface)
				matchIndices = append(matchIndices, monIface.SerialIndex())
			}
			if len(matches) > 0 {
				specMatches = append(specMatches, [][]monitor.Interface{matches})
				specMatchIndices = append(specMatchIndices, [][]int{matchIndices})
			}
			continue
		}
		var clauseMatches [][]monitor.Interface
		var clauseMatchIndices [][]int
		for _, clause := range spec.Clauses {
		var clauseIfaceMatches []net.Interface
		var channels [][]int
		for _, iface := range ifaceMatches {
			wiphy := wiphys[iface.Name]
			match, ok := clause.Match(iface, wiphy)
			if !ok {
				continue
			}
			clauseIfaceMatches = append(clauseIfaceMatches, iface)
			ch := match.Channels
			if len(ch) == 0 && wiphy != nil {
				ch = wiphy.ChannelInts()
			}
			channels = append(channels, ch)
		}

			var matches []monitor.Interface
			var matchIndices []int
			hopper := clause.Hopper
			for i, iface := range clauseIfaceMatches {
				monIface := monitor.Interface{
					Interface: iface,
					Hopper:    hopper,
					Channels:  channels[i],
				}
				matches = append(matches, monIface)
				matchIndices = append(matchIndices, monIface.SerialIndex())
			}
			if len(matches) == 0 {
				return nil, fmt.Errorf("no interfaces matched clause %+v from spec %+v", clause, spec)
			}
			clauseMatches = append(clauseMatches, matches)
			clauseMatchIndices = append(clauseMatchIndices, matchIndices)
		}
		specMatches = append(specMatches, clauseMatches)
		specMatchIndices = append(specMatchIndices, clauseMatchIndices)
	}

	var regions []csp.Region
	for i, clauseMatches := range specMatches {
		if i >= len(specs) {
			continue
		}
		for j, matches := range clauseMatches {
			if j >= len(specs[i].Clauses) {
				continue
			}
			index := [2]int{i, j}
			card := specs[i].Clauses[j].Cardinality
			var bound csp.Bound
			switch {
			case card.Eq.IsPresent():
				k := card.Eq.MustGet()
				if k > len(matches) {
					return nil, csp.UnsatError{
						Reason: fmt.Errorf("eq cardinality %d > %d matches", k, len(matches)),
					}
				}
				bound = csp.Bound{
					LowerInclusive: k,
					UpperExclusive: k + 1,
				}
			default:
				atLeast := 1
				if atLeast > len(matches) {
					return nil, csp.UnsatError{
						Reason: fmt.Errorf("default cardinality %d > %d matches", atLeast, len(matches)),
					}
				}
				bound = csp.Bound{
					LowerInclusive: atLeast,
					UpperExclusive: len(matches) + 1,
				}
			}
			regions = append(regions, csp.Region{
				Index: index,
				Compatible: roaring.BitmapOf(lo.Map(specMatchIndices[i][j], func(i int, _ int) uint32 {
					return uint32(i)
				})...),
				Bound: bound,
			})
		}
	}

	// If we have specs with no clauses (direct matches), add them directly
	if len(regions) == 0 {
		for _, specMatch := range specMatches {
			if len(specMatch) > 0 && len(specMatch[0]) > 0 {
				ifaces = append(ifaces, specMatch[0]...)
			}
		}
	} else {
		asmts, err := csp.Solve(regions)
		if err != nil {
			return nil, err
		}
		log.Debug().Int("sol_len", len(asmts)).
			Msgf("solution: %v", asmts)

		for _, asmt := range asmts {
			i, j := asmt.Index[0], asmt.Index[1]
			if i >= len(specMatches) || j >= len(specMatches[i]) {
				continue
			}
			asmtIfaces := lo.Filter(specMatches[i][j], func(iface monitor.Interface, i int) bool {
				return asmt.Set.Contains(uint32(i))
			})
			if len(asmtIfaces) == 0 {
				panic(fmt.Sprintf("no interfaces kept: %v", asmt.Index))
			}
			log.Trace().Msgf(
				"keeping %d/%d interfaces from spec %d, clause %d: %v",
				len(asmtIfaces),
				len(specMatches[i][j]),
				i,
				j,
				specMatches[i][j],
			)
			ifaces = append(ifaces, asmtIfaces...)
		}
	}

	if len(ifaces) == 0 {
		log.Fatal().Msgf("no interfaces matched %d iface specs: %#v", len(cfg.ifaces), cfg.ifaces)
	}
	avail := append([]monitor.Interface{}, ifaces...)
	if cfg.ifaceLimit > 0 && len(ifaces) > cfg.ifaceLimit {
		ifaces = ifaces[:cfg.ifaceLimit]
	}

	names := monitor.InterfaceNames(ifaces)
	log.Info().Int("avail", len(avail)).Msgf("using %d interfaces: %v", len(ifaces), names)
	sort.Slice(ifaces, func(i, j int) bool {
		return ifaces[i].Name < ifaces[j].Name
	})
	return ifaces, nil
}

// e.g. -i ^wlp:static,b=1+uniform,n=1
func parseSpec(specStr string) (*ifaceSpec, error) {
	parts := strings.SplitN(specStr, ":", 2)
	if len(parts) == 1 {
		re, err := regexp.Compile(specStr)
		if err != nil {
			return nil, fmt.Errorf("invalid interface pattern: %q", specStr)
		}
		return &ifaceSpec{Regexp: re}, nil
	}

	pat, opts := parts[0], parts[1]
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, fmt.Errorf("invalid interface regexp: %q", specStr)
	}
	spec := &ifaceSpec{Regexp: re}

	// If opts is empty, create a simple clause with no channel restrictions
	if strings.TrimSpace(opts) == "" {
		spec.Clauses = []ifaceSpecClause{{
			Cardinality: cardConst{GtEq: mo.Some(1)},
			Channels:    []int{}, // No channel restrictions
			Hopper:      monitor.NewUniformHopper(),
		}}
		return spec, nil
	}

	union := strings.Split(opts, "+")
	for _, clauseStr := range union {
		clause := ifaceSpecClause{
			Cardinality: cardConst{GtEq: mo.Some(1)},
			Channels:    []int{}, // Start with empty channels, only add if band is specified
			Hopper:      monitor.NewUniformHopper(),
		}
		opts := strings.Split(clauseStr, ",")
		for _, opt := range opts {
			parts := strings.SplitN(opt, "=", 2)
			switch len(parts) {
			case 1:
				return nil, fmt.Errorf("keyless options not yet supported: %q", opt)
			case 2:
				key, val := parts[0], parts[1]
				switch strings.ToLower(key) {
				case "n", "limit", "max":
					n, err := strconv.Atoi(val)
					if err != nil {
						return nil, fmt.Errorf("invalid limit opt %s=%s: %w", key, val, err)
					}
					clause.Cardinality = cardConst{Eq: mo.Some(n)}
					if err := clause.Cardinality.valid(); err != nil {
						panic(err)
					}
				case "h", "hop", "hopper":
					h, err := parseHopperStrategy(val)
					if err != nil {
						return nil, fmt.Errorf("invalid hopper strategy opt: %s=%s: %w", key, val, err)
					}
					clause.Hopper = h
				// case "c", "ch", "channel":
				// 	// example --channel=1,6,11-14
				case "b", "band":
					var band netref.Band
					switch strings.ToLower(val) {
					case "2", "2g", "2ghz", "2.4", "2.4g", "2.4ghz":
						band = netref.Band2_4GHz
					case "5", "5g", "5ghz":
						band = netref.Band5GHz
					default:
						return nil, fmt.Errorf("unsupported band opt: %s=%s", key, val)
					}
					clause.Channels = append(clause.Channels, netref.BandToChannels[band]...)
				default:
					// TODO: implement best
					// guess for the key.
					return nil, fmt.Errorf("invalid option: %q", key)
				}
			default:
				panic("unreachable")
			}
		}
		spec.Clauses = append(spec.Clauses, clause)
	}

	return spec, nil
}

func parseHopperStrategy(raw string) (monitor.Hopper, error) {
	switch strings.ToLower(raw) {
	case "fixed", "static":
		return monitor.NewStaticHopper(), nil
	case "u", "uniform":
		return monitor.NewUniformHopper(), nil
	case "ts", "thompson", "thompsonsampling":
		return monitor.NewThompsonSamplingHopper(), nil
	default:
		return nil, fmt.Errorf("unknown hop strategy: %q", raw)
	}
}

func describeInterfaces(ifaces []monitor.Interface) error {
	byHopper := make(map[monitor.Hopper][]monitor.Interface)
	for _, iface := range ifaces {
		byHopper[iface.Hopper] = append(byHopper[iface.Hopper], iface)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Println("[Hoppers]")
	for hopper, ifaces := range byHopper {
		fmt.Fprintf(
			w,
			"hopper=%v, num_ifaces=%d, ifaces=%v\n",
			hopper,
			len(ifaces),
			monitor.InterfaceNames(ifaces),
		)
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "[Interfaces]")
	for _, iface := range ifaces {
		fmt.Fprintf(
			w,
			"iface=%s, index=%d, hopper=%v, ch=%v\n",
			iface.Name,
			iface.HopperIndex,
			iface.Hopper,
			iface.Channels,
		)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to flush tabwriter: %w", err)
	}
	return nil
}

func summary(agg monitor.Aggregate, topk int) string {
	start := time.Now()

	var buf bytes.Buffer

	age := time.Since(agg.Global.Start).Round(time.Second)
	buf.WriteString("[META]\n")
	buf.WriteString(fmt.Sprintf("age=%v\n", age))
	buf.WriteString(fmt.Sprintf("maxStep=%d\n", agg.Global.MaxStep))
	buf.WriteString(fmt.Sprintf("step=%s\n", sprintOrdered(agg.Global.Step, -1)))
	buf.WriteString(fmt.Sprintf(
		"packets=%d (%0.2f/s)\n",
		agg.Global.PacketsTotal,
		float64(agg.Global.PacketsTotal)/age.Seconds(),
	))
	buf.WriteString(fmt.Sprintf("sources=%d\n", len(agg.Sources)))
	buf.WriteString("\n")

	var chOrdered []monitor.ChannelInfo
	for _, info := range agg.Channels {
		// if info.Packets < 2 {
		// 	continue
		// }
		chOrdered = append(chOrdered, *info)
	}
	sort.SliceStable(chOrdered, func(i, j int) bool {
		return chOrdered[i].PacketsTotal > chOrdered[j].PacketsTotal
	})
	if len(chOrdered) > topk {
		chOrdered = chOrdered[:topk]
	}
	buf.WriteString("[CHANNELS]\n")
	for _, it := range chOrdered {
		buf.WriteString(fmt.Sprintf(
			"ch=%d, packets=%d, samples=%d, adj=%d\n",
			it.Channel,
			it.PacketsTotal,
			it.SamplesDirect,
			it.SamplesIndirect,
		))
	}
	buf.WriteString("\n")

	var ordered []monitor.SourceInfo
	for _, info := range agg.Sources {
		if info.Packets < 2 {
			continue
		}
		ordered = append(ordered, *info)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Packets > ordered[j].Packets
	})
	if len(ordered) > topk {
		ordered = ordered[:topk]
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Src.String() < ordered[j].Src.String()
	})
	buf.WriteString("[SOURCES]\n")
	for _, it := range ordered {
		buf.WriteString(fmt.Sprintf(
			"src=%s, packets=%d, signal=%0.2fdBm (std %0.3f), channels=%s, types=%s\n",
			it.Src.String(),
			it.Packets,
			it.SignalsMean.Get(),
			it.SignalsStd.Get(),
			sprintOrdered(it.Channels, 4),
			sprintOrdered(it.Types, 4),
		))
	}

	buf.WriteString("\n[EPILOGUE]\n")
	buf.WriteString(fmt.Sprintf("summary_dur=%v\n", time.Since(start)))

	return buf.String()
}

func sprintOrdered[T comparable](m map[T]int, topk int) string {
	var ordered []T
	for k := range m {
		ordered = append(ordered, k)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return m[ordered[i]] > m[ordered[j]]
	})
	if topk > 0 && len(ordered) > topk {
		ordered = ordered[:topk]
	}
	var parts []string
	for _, k := range ordered {
		parts = append(parts, fmt.Sprintf("%v:%d", k, m[k]))
	}
	return fmt.Sprintf("{%s}", strings.Join(parts, ", "))
}

// Execute adds all child commands to the root command and sets flags
// appropriately. This is called by main.main(). It only needs to happen once
// to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Send()
	}
}

func mustString(cmd *cobra.Command, name string) string {
	val, err := cmd.Flags().GetString(name)
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	return val
}

func mustStringArray(cmd *cobra.Command, name string) []string {
	val, err := cmd.Flags().GetStringArray(name)
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	return val
}

func mustInt(cmd *cobra.Command, name string) int {
	val, err := cmd.Flags().GetInt(name)
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	return val
}

func mustBool(cmd *cobra.Command, name string) bool {
	val, err := cmd.Flags().GetBool(name)
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	return val
}
