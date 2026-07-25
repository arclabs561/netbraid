package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/arclabs561/netwatch/monitor/netref"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/conc/pool"
)

const (
	// DefaultSnapshotLength is the default snapshot length for pcap capture
	DefaultSnapshotLength = 65536
	// DefaultIntervalDuration is the default channel hopping interval
	DefaultIntervalDuration = 200 * time.Millisecond
	// DefaultIfaceUpTimeout is the default timeout for waiting for interface to come up
	DefaultIfaceUpTimeout = 10 * time.Second
	// DefaultCommandTimeout is the default timeout for shell command execution
	DefaultCommandTimeout = 5 * time.Second
	// DefaultPacketBufferSize is the buffer size for packet processing channel
	// Sized to handle bursts without blocking capture
	DefaultPacketBufferSize = 500
	// DefaultWorkerPoolSize is the number of workers for packet processing
	DefaultWorkerPoolSize = 4
)

type Monitor struct {
	dataDir         string
	stopDur         time.Duration
	ifaceUpTimeout  time.Duration
	quiet           bool
	mu              *sync.Mutex
	agg             *Aggregate
	defaultHopper   Hopper
	intervalDur     time.Duration
	peers           *peers
	filter          Filter
	cancelListen    func()
	doneListen      chan struct{}
	muListen        *sync.Mutex
	onlyStart       bool
	packetProcessor *PacketProcessor
}

func NewMonitor(options ...MonitorOption) (*Monitor, error) {
	dataDir := "."
	m := &Monitor{
		dataDir:        dataDir,
		stopDur:        -1,
		ifaceUpTimeout: DefaultIfaceUpTimeout,
		quiet:          false,
		mu:             new(sync.Mutex),
		agg:            NewAggregate(),
		defaultHopper:  NewStaticHopper(),
		intervalDur:    DefaultIntervalDuration,
		cancelListen:   nil,
		doneListen:     nil,
		muListen:       new(sync.Mutex),
	}
	for _, opt := range options {
		opt.apply(m)
	}
	if err := os.MkdirAll(m.dataDir, 0755); err != nil {
		return nil, err
	}
	return m, nil
}

type MonitorOption interface {
	apply(*Monitor)
}

type monitorOption struct {
	fn func(*Monitor)
}

func (o monitorOption) apply(m *Monitor) {
	o.fn(m)
}

// OptMonitorDataDir specifies the directory where monitor data is written,
// such as pcap files, and if applicable channel hopping schedules, etc.
func OptMonitorDataDir(dataDir string) MonitorOption {
	return monitorOption{
		fn: func(m *Monitor) {
			m.dataDir = dataDir
		},
	}
}

func OptMonitorOnlyStart(onlyStart bool) monitorOption {
	return monitorOption{
		fn: func(m *Monitor) {
			m.onlyStart = onlyStart
		},
	}
}

// OptMonitorStopDur specifies the duration to wait for packets.
func OptMonitorStopDur(stopDur time.Duration) MonitorOption {
	return monitorOption{
		fn: func(m *Monitor) {
			m.stopDur = stopDur
		},
	}
}

// OptMonitorQuiet silences packet information from being printed.
func OptMonitorQuiet(quiet bool) MonitorOption {
	return monitorOption{
		fn: func(m *Monitor) {
			m.quiet = quiet
		},
	}
}

func OptMonitorFilter(filter Filter) MonitorOption {
	return monitorOption{
		fn: func(m *Monitor) {
			m.filter = filter
		},
	}
}

func OptMonitorDefaultHopper(hopper Hopper) MonitorOption {
	return monitorOption{
		fn: func(m *Monitor) {
			m.defaultHopper = hopper
		},
	}
}

type Filter struct {
	Src net.HardwareAddr
	Dst net.HardwareAddr
}

func (f Filter) IsOK(a AnalyzedPacket, p gopacket.Packet) bool {
	if f.Src != nil && !isPrefix(a.Src, f.Src) {
		return false
	}
	if f.Dst != nil && !isPrefix(a.Dst, f.Dst) {
		return false
	}
	return true
}

func ParseFilter(s string) (*Filter, error) {
	f := new(Filter)
	t := strings.ToLower(s)
	if strings.HasPrefix(t, "src:") {
		parts := strings.SplitN(t, "src:", 2)
		src, err := net.ParseMAC(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid src mac address: %w", err)
		}
		f.Src = src
	}
	if strings.HasPrefix(t, "dst:") {
		parts := strings.SplitN(t, "dst:", 2)
		dst, err := net.ParseMAC(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid dst mac address: %w", err)
		}
		f.Dst = dst
	}
	return f, nil
}

func isPrefix(a, prefix []byte) bool {
	if len(prefix) > len(a) {
		return false
	}
	for i := range prefix {
		if a[i] != prefix[i] {
			return false
		}
	}
	return true
}

func (m *Monitor) StartNewCluster(ctx context.Context, addr string) error {
	peers, err := startNewCluster(ctx, addr)
	if err != nil {
		return err
	}
	m.peers = peers
	return nil
}

func (m *Monitor) JoinExistingCluster(ctx context.Context, addr string, token []byte) error {
	peers, err := joinExistingCluster(ctx, addr, token)
	if err != nil {
		return err
	}
	m.peers = peers
	return nil
}

func (m *Monitor) Listen(ctx context.Context, ifaces ...Interface) error {
	m.muListen.Lock()
	defer m.muListen.Unlock()
	if m.cancelListen != nil {
		return fmt.Errorf("already listening")
	}

	if m.stopDur > 0 {
		var done func()
		ctx, done = context.WithTimeout(ctx, m.stopDur)
		defer done()
	}

	if len(ifaces) == 0 {
		log.Info().Msgf("no interfaces specified, using default")
		iface, err := FirstGoodInterface()
		if err != nil {
			return fmt.Errorf("failed to find live interface: %w", err)
		}
		ifaces = []Interface{{
			Interface:   *iface,
			Hopper:      m.defaultHopper,
			HopperIndex: 0,
			HopperTotal: 1,
		}}
	}

	events := &events{
		mu:   new(sync.Mutex),
		path: filepath.Join(m.dataDir, "events.jsonl"),
		f:    nil,
	}
	defer events.Close()
	start := time.Now()
	events.WriteEvent(EventListenStart{
		Start:         start,
		NumInterfaces: len(ifaces),
		Interfaces:    ifaces,
	})
	m.WithAggregate(func(agg *Aggregate) {
		agg.Global.Start = time.Now()
		agg.Global.NumInterfaces = len(ifaces)
	})
	defer func() {
		m.WithAggregate(func(agg *Aggregate) {
			stoppedAt := time.Now()
			agg.Global.Dur = stoppedAt.Sub(agg.Global.Start)
			events.WriteEvent(EventListenStop{
				Start: start,
				Stop:  stoppedAt,
				Dur:   agg.Global.Dur,
				Agg:   *agg,
			})
		})
	}()

	ctx, cancel := context.WithCancel(ctx)
	m.cancelListen = cancel
	m.doneListen = make(chan struct{})
	defer func() {
		m.cancelListen = nil
		close(m.doneListen)
	}()

	poolListen := pool.New().WithContext(ctx)
	for _, iface := range ifaces {
		poolListen.Go(func(ctx context.Context) error {
			return m.listenInterface(ctx, iface, events)
		})
	}
	if err := poolListen.Wait(); err != nil {
		if errors.Is(err, context.Canceled) {
			log.Debug().Msg("Context was cancelled")
		}
		return fmt.Errorf("failed to monitor interfaces: %w", err)

	}
	// if m.onlyStart {
	// 	defer log.Info().Msg("only start mode, success bringing all interfaces up, not hopping")
	// }
	return nil
}

func (m *Monitor) Stop() error {
	log.Debug().Msg("stopping monitor")
	if m.cancelListen == nil {
		return nil
	}
	m.cancelListen()

	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case <-timeout.C:
			return fmt.Errorf("failed to stop monitor")
		case <-m.doneListen:
			return nil
		}
	}
}

func (m *Monitor) listenInterface(
	ctx context.Context,
	iface Interface,
	events *events,
) error {
	hopper := iface.Hopper
	if hopper == nil {
		hopper = m.defaultHopper
		// log.Debug().Msgf("no hopper specified for interface %s, using default %v", iface.Name, hopper)
	}

	// Initialize interface for listening.
	start := time.Now()
	// Try to set monitor mode - required for full WiFi packet capture
	// On macOS, this may require sudo and special setup
	if err := setMode(ctx, iface.Name); err != nil {
		log.Warn().Err(err).Msgf("failed to set monitor mode - packet capture may be limited. Try running with sudo.")
		// Continue anyway - we can still capture some packets
	}
	// Check to see if we can successfully change the interface's
	// channel, prior to hopping so that we can fail early.
	// Channel hopping requires monitor mode and sudo on most platforms
	// On macOS, channel setting may not be supported - make it optional
	channelHoppingEnabled := true
	if err := setChannel(ctx, iface.Name, 6); err != nil {
		log.Warn().Err(err).Msgf("failed to set init channel - channel hopping disabled. Will capture on current channel only.")
		channelHoppingEnabled = false
		// Continue anyway - we can still capture packets on current channel
	}
	h, err := m.waitOpenLive(iface)
	if err != nil {
		return fmt.Errorf("failed to create packet source: %w", err)
	}

	// Create optimized packet processor for this interface
	m.packetProcessor = NewPacketProcessor(h.Handle.LinkType())

	// Use optimized packet source with lazy and nocopy decoding
	src := gopacket.NewPacketSource(h.Handle, h.Handle.LinkType())
	src.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}

	// Check to see if hopping works at least once (only if channel hopping is enabled)
	var action *HopAction
	if channelHoppingEnabled {
		action, err = hopper.Hop(ctx, iface)
		if err != nil {
			log.Warn().Err(err).Msgf("failed to hop interface %v - disabling channel hopping, will capture on current channel", iface)
			channelHoppingEnabled = false
		}
	}

	// If channel hopping is disabled, create a dummy action for the current channel
	if !channelHoppingEnabled {
		// Try to detect current channel, or use 0 (unknown)
		action = &HopAction{
			Channel: 0, // Will be detected from packets
			Index:   0,
		}
		log.Info().Msgf("Channel hopping disabled - capturing on current channel (will detect from packets)")
	}
	log.Info().Int("index", action.Index).
		Str("iface", iface.Name).
		Int("ch", action.Channel).
		Int("attempt", h.Attempt).
		Stringer("dur", time.Since(start).Round(time.Millisecond)).
		Str("hopper", fmt.Sprint(hopper)).
		Msgf("interface ready to listen")
	if m.onlyStart {
		return nil
	}

	// Start pcap files, one for each interface.
	pcapFile := filepath.Join(m.dataDir, fmt.Sprintf("%v:%s.pcap", iface.Hopper, iface.Name))
	f, err := os.Create(pcapFile)
	if err != nil {
		return fmt.Errorf("failed to create pcap file %s: %w", pcapFile, err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(DefaultSnapshotLength, h.Handle.LinkType()); err != nil {
		return fmt.Errorf("failed to write pcap file header: %w", err)
	}

	log.Info().Stringer("linkType", h.Handle.LinkType()).
		Str("pcapFile", pcapFile).
		Str("iface", iface.Name).
		Msgf("listening for packets")

	// Close pcap handle when context is cancelled to stop packet reading
	defer h.Handle.Close()

	// Primary loop for both listening and hopping concurrently,
	// but not in parallel.
	// Use buffered channel for async packet processing to avoid blocking capture
	packetChan := make(chan gopacket.Packet, DefaultPacketBufferSize)

	// Shared state for packet processing (protected by mutex)
	state := &packetState{
		seenCh: make(map[int]bool),
	}

	// Start worker pool for packet processing
	var wg sync.WaitGroup
	for i := 0; i < DefaultWorkerPoolSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for packet := range packetChan {
				state.mu.RLock()
				currAction := state.currAction
				obs := state.obs
				seenChCopy := make(map[int]bool)
				for k, v := range state.seenCh {
					seenChCopy[k] = v
				}
				state.mu.RUnlock()
				m.processPacket(packet, currAction, obs, seenChCopy, w, iface, state)
			}
		}()
	}
	defer func() {
		close(packetChan)
		wg.Wait()
	}()

	// Read packets in a separate goroutine to allow context cancellation
	// Using NextPacket() instead of Packets() channel for immediate context cancellation
	packetSrcChan := make(chan gopacket.Packet, DefaultPacketBufferSize)
	var srcWg sync.WaitGroup
	srcWg.Add(1)
	go func() {
		defer srcWg.Done()
		defer close(packetSrcChan)
		for {
			// Check context before blocking on NextPacket
			select {
			case <-ctx.Done():
				return
			default:
			}
			// NextPacket will block, but with 100ms timeout on OpenLive it should return quickly
			packet, err := src.NextPacket()
			if err != nil {
				// Check if context was cancelled during read
				if ctx.Err() != nil {
					return
				}
				// EOF or other error - stop reading
				if err == io.EOF {
					return
				}
				log.Debug().Err(err).Msg("error reading packet")
				// Continue trying, but check context again
				continue
			}
			if packet == nil {
				// Shouldn't happen, but handle it
				continue
			}
			// Send packet, but check context
			select {
			case packetSrcChan <- packet:
			case <-ctx.Done():
				return
			}
		}
	}()
	defer srcWg.Wait()

	var obs HopObservation
	first := true
	ticker := time.NewTicker(m.intervalDur)
	defer ticker.Stop()
	var hopStart time.Time
	step := 0
	// The context timeout is set in Listen() if stopDur > 0
	// We'll check ctx.Done() in the select statement
	for {
		select {
		case <-ctx.Done():
			// Close handle immediately to stop packet reading
			h.Handle.Close()
			if ctx.Err() == context.DeadlineExceeded {
				log.Info().Stringer("dur", m.stopDur).Msg("auto-stop timeout reached, stopping capture")
			} else {
				log.Info().Msg("context cancelled, stopping capture")
			}
			return nil
		case <-ticker.C:
			var prevHopStart time.Time
			if !first {
				prevHopStart = hopStart
			}
			hopStart = time.Now()

			// Only try to hop if channel hopping is enabled
			if channelHoppingEnabled {
				newAction, err := hopper.Hop(ctx, iface)
				if err != nil {
					log.Warn().Err(err).Msgf("failed to hop interface %v - disabling channel hopping", iface)
					channelHoppingEnabled = false
					// Continue with current action
				} else {
					action = newAction
				}
			}
			// If channel hopping is disabled, keep using the same action (channel 0, detected from packets)
			// Update shared state
			state.mu.Lock()
			state.currAction = action
			state.mu.Unlock()

			m.WithAggregate(func(agg *Aggregate) {
				agg.WithChannel(action.Channel, func(info *ChannelInfo) {
					info.SamplesDirect++
				})
				if agg.Global.Start.IsZero() {
					agg.Global.Start = hopStart
				}
			})

			if !first {
				// Get current observation from shared state
				state.mu.RLock()
				currentObs := state.obs
				state.mu.RUnlock()
				events.WriteEvent(EventHop{
					Interface: iface.Name,
					Step:      step - 1, // because this hop represents the previous step
					PeriodMS:  float64(m.intervalDur.Nanoseconds()) / float64(time.Millisecond),
					Action:    *action,
					Obs:       currentObs,
					Start:     prevHopStart,
					Stop:      hopStart,
					DurMS:     float64(hopStart.Sub(prevHopStart).Nanoseconds()) / float64(time.Millisecond),
				})
			}

			hopper.Update(iface, *action, obs)

			m.WithAggregate(func(agg *Aggregate) {
				agg.Global.Step[iface.Name] = step
				if step > agg.Global.MaxStep {
					agg.Global.MaxStep = step
				}
				if !first {
					agg.WithInterface(iface, func(info *InterfaceInfo) {
						dur := hopStart.Sub(prevHopStart)
						info.HopDurMean.Add(float64(dur.Nanoseconds()))
						info.HopDurStd.Add(float64(dur.Nanoseconds()))
						// mu := info.HopDurMean.Get()
						std := info.HopDurStd.Get()
						n := info.HopDurMean.Len()
						bound := 2 * std / math.Sqrt(float64(n))
						info.HopDurConfBound = time.Duration(bound)
						log.Debug().
							Stringer("iface", iface).
							Str("hopper", fmt.Sprintf("%v", hopper)).
							Int("ch", action.Channel).
							Int("step", agg.Global.Step[iface.Name]).
							Stringer("dur", hopStart.Sub(prevHopStart).Round(time.Microsecond)).
							Int("packets", state.obs.Packets).
							Str("packetsCh", sprintOrdered(state.obs.ChannelPackets, -1)).
							// Str("durMean", fmt.Sprintf(
							// 	"%v ± %v",
							// 	time.Duration(mu).Round(time.Microsecond),
							// 	time.Duration(bound).Round(time.Microsecond),
							// )).
							// Stringer("durConf95", time.Duration(bound).Round(time.Microsecond)).
							// Str("durConf", fmt.Sprintf(
							// 	"%v < %v < %v",
							// 	time.Duration(mu).Round(time.Microsecond),
							// 	time.Duration(lower).Round(time.Microsecond),
							// 	time.Duration(upper).Round(time.Microsecond),
							// )).
							Msgf("hop interval end")
					})
				}
			})

			first = false
			obs = NewHopObservation()
			// Update shared state
			state.mu.Lock()
			state.obs = obs
			state.mu.Unlock()
			step++
		case packet, ok := <-packetSrcChan:
			if !ok {
				// Packet source closed, exit
				return nil
			}
			if first {
				log.Trace().Msg("dropping packet until hopping begins")
				continue
			}
			// Send to worker pool for async processing
			select {
			case packetChan <- packet:
				// Packet queued for processing
			default:
				// Buffer full - log warning but continue
				log.Warn().Msg("packet buffer full, dropping packet")
			}
		}
	}
}

type PacketHandle struct {
	Handle  *pcap.Handle
	Attempt int
}

func (m *Monitor) waitOpenLive(
	iface Interface,
) (*PacketHandle, error) {
	start := time.Now()
	var h *pcap.Handle
	var err error
	var (
		sleep    = 10 * time.Millisecond
		jitter   = 100 * time.Millisecond
		maxSleep = 1 * time.Second
	)
	var i int
	for i = 0; ; i++ {
		if i > 0 && time.Since(start) > m.ifaceUpTimeout {
			return nil, fmt.Errorf("interface %v failed to come up: %w", iface, err)
		}
		// Use a short timeout (100ms) instead of BlockForever to allow context cancellation
		// The context timeout in Listen() will handle the overall stop duration
		h, err = pcap.OpenLive(iface.Name, DefaultSnapshotLength, true, 100*time.Millisecond)
		if err != nil {
			if strings.Contains(err.Error(), "That device is not up") {
				log.Debug().
					Int("attempts", i+1).
					Stringer("dur", time.Since(start).Round(time.Millisecond)).
					Msgf(
						"interface %v is not up yet, retrying in %v",
						iface,
						sleep.Round(time.Millisecond),
					)
				sleep *= 2
				sleep += time.Duration(rand.Float64() * float64(jitter))
				if maxSleep > 0 && sleep > maxSleep {
					sleep = maxSleep
				}
				time.Sleep(sleep)
				continue
			}
			return nil, fmt.Errorf("failed to open: %w", err)
		}
		break
	}
	if h == nil {
		log.Warn().Str("iface", iface.Name).
			Stringer("dur", time.Since(start).Round(time.Millisecond)).
			Msgf("nil handle after %d attempts", i)
		return nil, fmt.Errorf("failed to open handle: %w", err)
	}
	return &PacketHandle{
		Handle:  h,
		Attempt: i,
	}, nil
}

type AnalyzedPacket struct {
	ObservedAt              time.Time
	FirstLayerDecodeFailure bool
	FirstLayerType          gopacket.LayerType
	LinkType                layers.LinkType
	Src                     net.HardwareAddr
	Dst                     net.HardwareAddr
	Dot11Type               layers.Dot11Type
	Channel                 int
	DbmSignal, DbmNoise     int
	SSID                    string
}

func analyzePacket(packet gopacket.Packet) *AnalyzedPacket {
	var analyzed AnalyzedPacket
	obs := packet.Metadata().Timestamp
	if obs.IsZero() {
		obs = time.Now()
	}
	analyzed.ObservedAt = obs
	var txCh, rxCh uint8
	for _, l := range packet.Layers() {
		switch l := l.(type) {
		case *layers.RadioTap:
			ch, ok := netref.FrequencyToChannel[int(l.ChannelFrequency)]
			if ok {
				rxCh = uint8(ch)
			} else {
				log.Warn().Msgf("unknown channel: %d", l.ChannelFrequency)
			}
			analyzed.DbmSignal = int(l.DBMAntennaSignal)
			analyzed.DbmNoise = int(l.DBMAntennaNoise)
		case *layers.Dot11:
			analyzed.Src = l.Address2
			analyzed.Dst = l.Address1
			analyzed.Dot11Type = l.Type
		case *layers.Dot11InformationElement:
			switch l.ID {
			case layers.Dot11InformationElementIDSSID:
				analyzed.SSID = string(l.Info)
			case layers.Dot11InformationElementIDDSSet:
				txCh = l.Info[0]
			}
		}
	}

	firstLayer, linkType := FirstLayerType(packet)
	if firstLayer == gopacket.LayerTypeDecodeFailure {
		analyzed.FirstLayerDecodeFailure = true
	}
	analyzed.FirstLayerType = firstLayer
	analyzed.LinkType = linkType

	// Transmitting channel (Dot11 DS Set) should take precidence over the
	// receiving channel (RadioTap header), and we rely on that layer
	// preceding this layer.
	if txCh != 0 {
		analyzed.Channel = int(txCh)
	} else if rxCh != 0 {
		analyzed.Channel = int(rxCh)
	} else {
		log.Trace().Int("bytes", packet.Metadata().CaptureLength).
			Stringer("linkType", linkType).
			Stringer("firstLayer", firstLayer).
			Msgf("no channel info found")
		analyzed.Channel = 0
	}

	return &analyzed
}

// processPacket processes a single packet (called by worker pool)
// packetState holds shared state for packet processing
type packetState struct {
	mu         sync.RWMutex
	currAction *HopAction
	obs        HopObservation
	seenCh     map[int]bool
}

func (m *Monitor) processPacket(
	packet gopacket.Packet,
	currAction *HopAction,
	obs HopObservation,
	seenCh map[int]bool,
	w *pcapgo.Writer,
	iface Interface,
	state *packetState,
) {
	now := time.Now()
	var a *AnalyzedPacket

	// Use optimized processor if available
	// Note: We use the packet's link type from the source, not from metadata
	// For now, always use analyzePacket which handles link type internally
	a = analyzePacket(packet)

	m.WithAggregate(func(agg *Aggregate) {
		agg.Global.PacketsTotal++
		agg.Global.PacketsPerChannel[a.Channel]++
		agg.Global.LastSeen = now
		if agg.Global.FirstSeen.IsZero() {
			agg.Global.FirstSeen = now
		}
		agg.WithChannel(a.Channel, func(info *ChannelInfo) {
			info.LastSeenPacket = now
			if info.FirstSeenPacket.IsZero() {
				info.FirstSeenPacket = now
			}

			info.PacketsTotal++
			if currAction != nil && currAction.Channel == a.Channel {
				info.PacketsDirect++
			} else {
				info.PacketsIndirect++
			}

			if a.FirstLayerDecodeFailure {
				info.BrokenTotal++
				if currAction != nil && currAction.Channel == a.Channel {
					info.BrokenDirect++
				} else {
					info.BrokenIndirect++
				}
			} else if a.Channel == 0 {
				log.Warn().Msgf("packet with 0 ch: %#v", a)
			}

			if !seenCh[a.Channel] {
				if currAction != nil && currAction.Channel == a.Channel {
					info.SamplesDirect++
				} else {
					info.SamplesIndirect++
					if currAction != nil {
						info.SampledFrom[currAction.Channel]++
					}
				}
			}
			seenCh[a.Channel] = true
		})
		if !m.quiet {
			m.printPacket(agg, a, packet)
		}
	})

	// Update observation atomically
	state.mu.Lock()
	if state.obs.IsZero() {
		state.obs = NewHopObservation()
	}
	state.obs.Packets++
	state.obs.ChannelPackets[a.Channel]++
	if !seenCh[a.Channel] {
		state.seenCh[a.Channel] = true
	}
	state.mu.Unlock()

	// Write packet to pcap file (synchronous I/O)
	if err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
		log.Error().Err(err).Msg("failed to write packet to pcap file")
	}
}

func (m *Monitor) printPacket(
	agg *Aggregate,
	a *AnalyzedPacket,
	packet gopacket.Packet,
) {
	if a.FirstLayerDecodeFailure {
		fmt.Printf(
			"%d %0.6f DECODE FAILURE\n",
			agg.Global.PacketsTotal,
			time.Since(agg.Global.Start).Seconds(),
		)
		return
	}
	// e.g. tshark
	// 41 0.941181591 02:00:00:00:00:01 → 02:00:00:00:00:02 802.11 255 Probe Response, SN=3254, FN=0, Flags=........C, BI=100, SSID="fixture-network"
	fmt.Printf(
		"%d %0.6f %d (%d dBm) %s > %s\n",
		agg.Global.PacketsTotal,
		time.Since(agg.Global.Start).Seconds(),
		a.Channel,
		a.DbmSignal,
		a.Src,
		a.Dst,
	)
}

func (m *Monitor) WithAggregate(fn func(agg *Aggregate)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(m.agg)
}

var _ io.Closer = (*events)(nil)

type events struct {
	mu   *sync.Mutex
	path string
	f    *os.File
}

func (es *events) WriteEvent(e Event) {
	if err := e.Validate(); err != nil {
		log.Error().Err(err).Str("type", e.Type()).Msgf("invalid event, not writing: %#v", e)
		return
	}
	if err := es.writeEvent(e); err != nil {
		log.Error().Err(err).Msg("failed to write event")
	}
}

func (es *events) writeEvent(e Event) error {
	es.mu.Lock()
	defer es.mu.Unlock()
	if es.f == nil {
		f, err := os.Create(es.path)
		if err != nil {
			return fmt.Errorf("failed to create events file: %w", err)
		}
		es.f = f
	}
	b, err := json.Marshal(EventWrapper{
		Type:  e.Type(),
		Event: e,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}
	n, err := es.f.Write(append(b, '\n'))
	if err != nil {
		return fmt.Errorf("failed to write event: %w", err)
	}
	if n < len(b) {
		return fmt.Errorf("failed to write event: short write (%d < %d)", n, len(b))
	}
	return nil
}

func (es *events) Close() error {
	if es.f != nil {
		if err := es.f.Close(); err != nil {
			return fmt.Errorf("failed to close events file: %w", err)
		}
		es.f = nil
	}
	return nil
}

type Event interface {
	Type() string
	Validate() error
	event()
}

type EventWrapper struct {
	Type  string `json:"type"`
	Event Event  `json:"event"`
}

type EventListenStart struct {
	Start         time.Time   `json:"start"`
	NumInterfaces int         `json:"num_ifaces"`
	Interfaces    []Interface `json:"ifaces"`
}

type EventListenStop struct {
	Start time.Time     `json:"start"`
	Stop  time.Time     `json:"stop"`
	Dur   time.Duration `json:"dur"`
	Agg   Aggregate     `json:"agg"`
}

type EventHop struct {
	Interface string         `json:"iface"`
	Step      int            `json:"step"`
	PeriodMS  float64        `json:"period_ms"`
	Action    HopAction      `json:"hop_action"`
	Obs       HopObservation `json:"hop_obs"`
	Start     time.Time      `json:"start"`
	Stop      time.Time      `json:"stop"`
	DurMS     float64        `json:"dur_ms"`
}

func (e EventListenStart) Validate() error {
	if e.Start.IsZero() {
		return fmt.Errorf("missing stop")
	}
	if e.NumInterfaces != len(e.Interfaces) {
		return fmt.Errorf(
			"mismatched num_ifaces and ifaces: %d != %d",
			e.NumInterfaces,
			len(e.Interfaces),
		)
	}
	return nil
}

func (e EventListenStop) Validate() error {
	if e.Start.IsZero() {
		return fmt.Errorf("missing start")
	}
	if e.Stop.IsZero() {
		return fmt.Errorf("missing stop")
	}
	if e.Stop.Sub(e.Start)-e.Dur > 10*time.Millisecond {
		return fmt.Errorf(
			"dur does not match started_at and stopped_at, diff: %v",
			e.Stop.Sub(e.Start)-e.Dur,
		)
	}
	return nil
}

func (e EventHop) Validate() error {
	if e.Interface == "" {
		return fmt.Errorf("missing iface name")
	}
	if e.Step < 0 {
		return fmt.Errorf("step must be >= 0")
	}
	if e.PeriodMS <= 0 {
		return fmt.Errorf("invalid period: %v <= 0", e.PeriodMS)
	}
	if e.Action.Channel <= 0 {
		return fmt.Errorf("invalid action channel: %d <= 0", e.Action.Channel)
	}
	if e.Start.IsZero() {
		return fmt.Errorf("missing start")
	}
	if e.Stop.IsZero() {
		return fmt.Errorf("missing stop")
	}
	if e.Start.After(e.Stop) {
		return fmt.Errorf("start after stop")
	}
	if e.DurMS <= 0 {
		return fmt.Errorf("invalid dur: %v <= 0", e.DurMS)
	}
	return nil
}

func (EventListenStart) Type() string { return "ListenStart" }
func (EventListenStop) Type() string  { return "ListenStop" }
func (EventHop) Type() string         { return "Hop" }

func (EventListenStart) event() {}
func (EventListenStop) event()  {}
func (EventHop) event()         {}

func FirstLayerType(packet gopacket.Packet) (gopacket.LayerType, layers.LinkType) {
	for _, l := range packet.Layers() {
		switch l.LayerType() {
		case layers.LayerTypeRadioTap:
			return l.LayerType(), layers.LinkTypeIEEE80211Radio
		case layers.LayerTypeDot11:
			return l.LayerType(), layers.LinkTypeIEEE802_11
		case layers.LayerTypeEthernet:
			return l.LayerType(), layers.LinkTypeEthernet
		default:
			return l.LayerType(), layers.LinkTypeNull
		}
	}
	panic(fmt.Sprintf("no layers in packet: %#v", packet))
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

func setMode(
	ctx context.Context,
	iface string,
) error {
	return platformWiFi.SetMonitorMode(ctx, iface)
}

// setModeLinux is the Linux-specific implementation
func setModeLinux(
	ctx context.Context,
	iface string,
) error {
	cmd := exec.CommandContext(ctx, "ip", "link", "set", iface, "down")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("setting link down failed: %w", err)
	}
	// We are only doing passive monitoring, so there's no reason to set
	// monitor control.
	cmd = exec.CommandContext(ctx, "iw", iface, "set", "monitor", "none")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("setting monitor control failed: %w", err)
	}
	cmd = exec.CommandContext(ctx, "ip", "link", "set", iface, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("setting link up failed: %w", err)
	}
	return nil
}
