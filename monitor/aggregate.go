package monitor

import (
	"encoding/json"
	"math"
	"net"
	"time"

	"github.com/arclabs561/netwatch/monitor/netref"
)

type Aggregate struct {
	Global     GlobalAggregate           `json:"global"`
	Interfaces map[string]*InterfaceInfo `json:"ifaces"`
	Channels   map[int]*ChannelInfo      `json:"ch"`
	Sources    map[string]*SourceInfo    `json:"src"`
}

func NewAggregate() *Aggregate {
	return &Aggregate{
		Global: GlobalAggregate{
			Step:              make(map[string]int),
			PacketsPerChannel: make(map[int]int),
		},
		Interfaces: make(map[string]*InterfaceInfo),
		Channels:   make(map[int]*ChannelInfo),
		Sources:    make(map[string]*SourceInfo),
	}
}

// GlobalAggregate holds aggregate information across all listening interfaces.
type GlobalAggregate struct {
	// The total number of channels that are listening.
	NumInterfaces int `json:"num_ifaces"`
	// The maximum step of any interface.
	MaxStep int `json:"max_step"`
	// Current step for each listening interface.
	Step map[string]int `json:"step"`
	// The earliest time at which all interfaces have started listening for
	// packets.
	Start time.Time `json:"start"`
	// The earliest time at which all interfaces stop listening for
	// packets.
	Stop time.Time `json:"stop"`
	// The total duration between StoppedAt and StartedAt.
	Dur time.Duration `json:"dur"`
	// The total number of packets seen, not taking
	// deduplication into consideration. For any given listening interface
	// dwelling on center channel i, the total packet it observes will be
	// P_i = \sum p_{ij} for packets transmitted from channel j. This
	// PacketsTotal is then the total sum of P_i for all listening channel
	// i.
	PacketsTotal int `json:"packets_total"`
	// The total number of packets seen per channel, not taking
	// deduplication into consideration.
	PacketsPerChannel map[int]int `json:"packets_per_ch"`
	// The time at which the first packet was observed from any listening
	// interface.
	FirstSeen time.Time `json:"first_seen"`
	// The time at which the last packet was observed from any listening
	// interface. This may well precede the StoppedAt time when listening
	// finally stops across all interfaces.
	LastSeen time.Time `json:"last_seen"`
}

func (agg *Aggregate) WithInterface(iface Interface, fn func(*InterfaceInfo)) {
	info, ok := agg.Interfaces[iface.Interface.Name]
	if !ok {
		info = &InterfaceInfo{
			Interface: iface.Name,
		}
	}
	fn(info)
	agg.Interfaces[iface.Name] = info
}

func (agg *Aggregate) WithChannel(ch int, fn func(*ChannelInfo)) {
	info, ok := agg.Channels[ch]
	if !ok {
		info = &ChannelInfo{
			Channel:     ch,
			Freq:        netref.ChanToFreq[ch],
			SampledFrom: make(map[int]int),
		}
	}
	fn(info)
	agg.Channels[ch] = info
}

type ChannelInfo struct {
	Index           int         `json:"index"`
	Channel         int         `json:"channel"`
	Freq            int         `json:"freq"`
	PacketsTotal    int         `json:"packets_total"`
	PacketsDirect   int         `json:"packets_direct"`
	PacketsIndirect int         `json:"packets_indirect"`
	SamplesTotal    int         `json:"samples_total"`
	SamplesDirect   int         `json:"samples_direct"`
	SamplesIndirect int         `json:"samples_indirect"`
	SampledFrom     map[int]int `json:"sampled_from"`
	BrokenTotal     int         `json:"broken_total"`
	BrokenDirect    int         `json:"broken_direct"`
	BrokenIndirect  int         `json:"broken_indirect"`
	FirstSeenPacket time.Time   `json:"first_seen_packet"`
	LastSeenPacket  time.Time   `json:"last_seen_packet"`
}

type SourceInfo struct {
	Src         net.HardwareAddr `json:"src"`
	LastSeen    time.Time        `json:"last_seen"`
	Packets     int              `json:"packets"`
	SignalsMean RollMean         `json:"signals_mean"`
	SignalsStd  RollStd          `json:"signals_std"`
	Types       map[string]int   `json:"types"`
	Channels    map[string]int   `json:"channels"`
}

type InterfaceInfo struct {
	Interface       string        `json:"iface"`
	Step            int           `json:"step"`
	HopDurMean      RollMean      `json:"hop_dur_mean"`
	HopDurStd       RollStd       `json:"hop_dur_std"`
	HopDurConfBound time.Duration `json:"hop_dur_conf_bound"`
}

type RollMean struct {
	Window int
	pos    int
	filled bool
	n      int
	total  float64
	curr   float64
	values []float64
	oldest float64
}

func (r *RollMean) Add(x float64) {
	if r.Window <= 0 {
		r.Window = 1000
	}
	if r.values == nil {
		r.values = make([]float64, r.Window)
	}
	r.total += x
	if r.filled {
		r.total -= r.oldest
		r.oldest = r.values[r.pos]
	} else if r.pos == r.Window-1 {
		r.filled = true
	}
	r.values[r.pos] = x
	r.pos = (r.pos + 1) % r.Window
	if r.n < r.Window {
		r.n++
	}
	r.curr = r.total / float64(r.n)
}
func (r RollMean) Len() int {
	return r.n
}

func (r *RollMean) Get() float64 {
	return r.curr
}

func (r *RollMean) Set(x float64) {
	zero := RollMean{}
	zero.Add(x)
	*r = zero
}

type RollStd struct {
	rollMean RollMean
	sum      float64
	sqrSum   float64
	curr     float64
}

func (r *RollStd) Add(x float64) {
	r.rollMean.Add(x)
	r.sqrSum += x * x
	r.sum += x
	if r.rollMean.Len() >= r.rollMean.Window {
		oldest := r.rollMean.oldest
		r.sqrSum -= oldest * oldest
		r.sum -= oldest
	}
	mu := r.rollMean.Get()
	n := float64(r.rollMean.Len())
	r.curr = math.Sqrt(r.sqrSum/n - (mu * mu))
}

func (r RollStd) Len() int {
	return r.rollMean.Len()
}

func (r RollStd) Get() float64 {
	return r.curr
}

func (r *RollStd) Set(x float64) {
	zero := RollStd{}
	zero.Add(x)
	*r = zero
}

type Roller interface {
	Get() float64
	Set(float64)
	Add(float64)
	Len() int
}

type RollFloat64 struct {
	val float64
}

func (f RollFloat64) Get() float64 {
	return f.val
}

func (f *RollFloat64) Set(v float64) {
	f.val = v
}

func (f *RollFloat64) Add(v float64) {
	f.val = v
}

func (f *RollFloat64) Len() int {
	return 1
}

type DurNano[T Roller] struct {
	Value T
}

func (d DurNano[T]) Get() float64 {
	return d.Value.Get()
}

func (d DurNano[T]) Dur() time.Duration {
	return time.Duration(d.Value.Get())
}

func (d DurNano[T]) Set(x float64) {
	d.Value.Set(x)
}

func (d DurNano[T]) Add(x float64) {
	d.Value.Add(x)
}

func (d DurNano[T]) Len() int {
	return d.Value.Len()
}

func (d DurNano[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Dur().String())
}

func (d *DurNano[T]) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	dur, err := time.ParseDuration(v)
	if err != nil {
		return err
	}
	d.Set(float64(dur.Nanoseconds()))
	return nil
}
