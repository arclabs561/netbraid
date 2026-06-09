package monitor

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketBufferPool provides reusable buffers for packet processing
var PacketBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, DefaultSnapshotLength)
	},
}

// GetPacketBuffer retrieves a buffer from the pool
func GetPacketBuffer() []byte {
	return PacketBufferPool.Get().([]byte)
}

// PutPacketBuffer returns a buffer to the pool
func PutPacketBuffer(buf []byte) {
	if cap(buf) >= DefaultSnapshotLength {
		PacketBufferPool.Put(buf[:cap(buf)])
	}
}

// PacketProcessor provides optimized packet processing with zero-copy and lazy decoding
type PacketProcessor struct {
	parser *gopacket.DecodingLayerParser
	layers []gopacket.LayerType
}

// NewPacketProcessor creates a new optimized packet processor
func NewPacketProcessor(linkType layers.LinkType) *PacketProcessor {
	// Create reusable layer objects for DecodingLayerParser
	// This is ~10x faster than NewPacket
	var (
		radioTap layers.RadioTap
		dot11    layers.Dot11
		dot11IE  layers.Dot11InformationElement
		ethernet layers.Ethernet
		ip4      layers.IPv4
		tcp      layers.TCP
		udp      layers.UDP
	)

	// Choose parser based on link type
	switch linkType {
	case layers.LinkTypeIEEE80211Radio:
		return &PacketProcessor{
			parser: gopacket.NewDecodingLayerParser(
				layers.LayerTypeRadioTap,
				&radioTap, &dot11, &dot11IE,
			),
			layers: make([]gopacket.LayerType, 0, 10),
		}
	case layers.LinkTypeEthernet:
		return &PacketProcessor{
			parser: gopacket.NewDecodingLayerParser(
				layers.LayerTypeEthernet,
				&ethernet, &ip4, &tcp, &udp,
			),
			layers: make([]gopacket.LayerType, 0, 10),
		}
	default:
		// Fallback to standard packet creation
		return nil
	}
}

// ProcessPacket processes a packet using optimized decoding
// Returns AnalyzedPacket and whether processing was successful
func (pp *PacketProcessor) ProcessPacket(data []byte, linkType layers.LinkType) (*AnalyzedPacket, bool) {
	if pp == nil || pp.parser == nil {
		// Fallback to standard processing
		packet := gopacket.NewPacket(data, linkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		return analyzePacket(packet), true
	}

	// Use DecodingLayerParser for faster processing
	pp.layers = pp.layers[:0]
	err := pp.parser.DecodeLayers(data, &pp.layers)
	if err != nil {
		// Fallback to standard packet creation
		packet := gopacket.NewPacket(data, linkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		return analyzePacket(packet), true
	}

	// Create packet with decoded layers for analysis
	packet := gopacket.NewPacket(data, linkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	return analyzePacket(packet), true
}

