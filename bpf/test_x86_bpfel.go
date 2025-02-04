// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type TestEvent struct{ Payload [4095]uint8 }

// LoadTest returns the embedded CollectionSpec for Test.
func LoadTest() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TestBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Test: %w", err)
	}

	return spec, err
}

// LoadTestObjects loads Test and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*TestObjects
//	*TestPrograms
//	*TestMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadTestObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadTest()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// TestSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TestSpecs struct {
	TestProgramSpecs
	TestMapSpecs
	TestVariableSpecs
}

// TestProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TestProgramSpecs struct {
	KprobeNetifReceiveSkbCore *ebpf.ProgramSpec `ebpf:"kprobe___netif_receive_skb_core"`
	TpBtfNetifReceiveSkb      *ebpf.ProgramSpec `ebpf:"tp_btf_netif_receive_skb"`
}

// TestMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TestMapSpecs struct {
	PerfOutput    *ebpf.MapSpec `ebpf:"perf_output"`
	RingbufOutput *ebpf.MapSpec `ebpf:"ringbuf_output"`
}

// TestVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type TestVariableSpecs struct {
	*ebpf.VariableSpec `ebpf:"_"`
}

// TestObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadTestObjects or ebpf.CollectionSpec.LoadAndAssign.
type TestObjects struct {
	TestPrograms
	TestMaps
	TestVariables
}

func (o *TestObjects) Close() error {
	return _TestClose(
		&o.TestPrograms,
		&o.TestMaps,
	)
}

// TestMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadTestObjects or ebpf.CollectionSpec.LoadAndAssign.
type TestMaps struct {
	PerfOutput    *ebpf.Map `ebpf:"perf_output"`
	RingbufOutput *ebpf.Map `ebpf:"ringbuf_output"`
}

func (m *TestMaps) Close() error {
	return _TestClose(
		m.PerfOutput,
		m.RingbufOutput,
	)
}

// TestVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to LoadTestObjects or ebpf.CollectionSpec.LoadAndAssign.
type TestVariables struct {
	*ebpf.Variable `ebpf:"_"`
}

// TestPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadTestObjects or ebpf.CollectionSpec.LoadAndAssign.
type TestPrograms struct {
	KprobeNetifReceiveSkbCore *ebpf.Program `ebpf:"kprobe___netif_receive_skb_core"`
	TpBtfNetifReceiveSkb      *ebpf.Program `ebpf:"tp_btf_netif_receive_skb"`
}

func (p *TestPrograms) Close() error {
	return _TestClose(
		p.KprobeNetifReceiveSkbCore,
		p.TpBtfNetifReceiveSkb,
	)
}

func _TestClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed test_x86_bpfel.o
var _TestBytes []byte
