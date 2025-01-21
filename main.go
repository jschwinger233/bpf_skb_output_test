package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/jschwinger233/bpf_skb_output_test/bpf"
)

func main() {
	objs := &bpf.TestObjects{}
	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelInstruction

	if err := bpf.LoadTestObjects(objs, &opts); err != nil {
		slog.Error("Failed to load BPF objects", "error", err)
		return
	}

	tp, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.TpBtfNetifReceiveSkb,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		slog.Error("Failed to attach program", "error", err)
		return
	}
	defer tp.Close()

	f, err := os.Create(os.Args[1])
	if err != nil {
		slog.Error("Failed to create pcap file", "err", err)
		return
	}
	defer f.Close()

	pcapw := pcapgo.NewWriter(f)
	if err = pcapw.WriteFileHeader(1600, layers.LinkTypeIPv4); err != nil {
		slog.Error("Failed to write pcap file header", "err", err)
		return
	}

	perfReader, err := perf.NewReader(objs.PerfOutput, 1500*1000)
	if err != nil {
		slog.Error("Failed to create perf reader", "error", err)
		return
	}
	defer perfReader.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	go func() {
		<-ctx.Done()
		perfReader.Close()
	}()

	println("Capturing packets, press Ctrl+C to stop")
	for {
		rec, err := perfReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Error("Failed to read record", "error", err)
			continue
		}

		size := len(rec.RawSample)
		captureInfo := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: int(size),
			Length:        int(size),
		}

		if err = pcapw.WritePacket(captureInfo, rec.RawSample); err != nil {
			slog.Error("failed to write packet", "err", err)
			return
		}
	}
}
