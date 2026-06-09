package monitor

import (
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

type PcapWriter struct {
	w *pcapgo.Writer
	f io.WriteCloser
}

func NewPcapWriter(path string) (*PcapWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create pcap file: %w", err)
	}
	return &PcapWriter{
		f: f,
	}, nil
}

func (w *PcapWriter) Write(packet gopacket.Packet) error {
	if w.w == nil {
		wtr := pcapgo.NewWriter(w.f)
		_, linkType := FirstLayerType(packet)
		if err := wtr.WriteFileHeader(65536, linkType); err != nil {
			return err
		}
		w.w = wtr
	}
	return w.w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
}

func (w *PcapWriter) Close() error {
	w.f.Close()
	return nil
}
