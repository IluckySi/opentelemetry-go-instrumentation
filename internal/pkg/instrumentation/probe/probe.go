// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package probe provides instrumentation probe types and definitions.
package probe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/go-logr/logr"
	"github.com/hashicorp/go-version"

	"go.opentelemetry.io/auto/internal/pkg/inject"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/bpffs"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/utils"
	"go.opentelemetry.io/auto/internal/pkg/process"
	"go.opentelemetry.io/auto/internal/pkg/structfield"
)

// Probe is the instrument used by instrumentation for a Go package to measure
// and report on the state of that packages operation.
type Probe interface {
	// Manifest returns the Probe's instrumentation Manifest. This includes all
	// the information about the package the Probe instruments.
	Manifest() Manifest

	// Load loads all instrumentation offsets.
	Load(*link.Executable, *process.TargetDetails) error

	// Run runs the events processing loop.
	Run(eventsChan chan<- *Event)

	// Close stops the Probe.
	Close() error
}

// Base is a base implementation of [Probe].
//
// This type can be returned by instrumentation directly. Instrumentation can
// also wrap this implementation with their own type if they need to override
// default behavior.
type Base[BPFObj any, BPFEvent any] struct { // TODO: 核心结构体
	// ID is a unique identifier for the probe.
	ID ID
	// Logger is used to log operations and errors.
	Logger logr.Logger

	// Consts are the constants that need to be injected into the eBPF program
	// that is run by this Probe.
	Consts []Const
	// Uprobes is a the collection of eBPF programs that need to be attached to
	// the target process.
	Uprobes []Uprobe[BPFObj]

	// ReaderFn is a creation function for a perf.Reader based on the passed
	// BPFObj related to the probe.
	ReaderFn func(BPFObj) (*perf.Reader, error)
	// SpecFn is a creation function for an eBPF CollectionSpec related to the
	// probe.
	SpecFn func() (*ebpf.CollectionSpec, error)
	// ProcessFn processes probe events into a uniform Event type.
	ProcessFn func(*BPFEvent) []*SpanEvent

	reader  *perf.Reader
	closers []io.Closer
}

// Manifest returns the Probe's instrumentation Manifest.
func (i *Base[BPFObj, BPFEvent]) Manifest() Manifest {
	structfields := consts(i.Consts).structFields()
	i.Logger.Info("I_TEST", "structfields", structfields) // {"level":"info","ts":1715174003.6266043,"logger":"Instrumentation.Manager.net/http/server","caller":"probe/probe.go:89","msg":"I_TEST","structfields":[{"ModPath":"std","PkgPath":"net/http","Struct":"Request","Field":"Method"},{"ModPath":"std","PkgPath":"net/http","Struct":"Request","Field":"URL"},{"ModPath":"std","PkgPath":"net/http","Struct":"Request","Field":"ctx"},{"ModPath":"std","PkgPath":"net/url","Struct":"URL","Field":"Path"},{"ModPath":"std","PkgPath":"net/http","Struct":"Request","Field":"Header"},{"ModPath":"std","PkgPath":"net/http","Struct":"response","Field":"req"},{"ModPath":"std","PkgPath":"net/http","Struct":"response","Field":"status"},{"ModPath":"std","PkgPath":"runtime","Struct":"hmap","Field":"buckets"},{"ModPath":"std","PkgPath":"net/http","Struct":"Request","Field":"RemoteAddr"},{"ModPath":"std","PkgPath":"net/http","Struct":"Request","Field":"Host"},{"ModPath":"std","PkgPath":"net/http","Struct":"Request","Field":"Proto"}]}

	symbols := make([]FunctionSymbol, 0, len(i.Uprobes))
	for _, up := range i.Uprobes {
		symbols = append(symbols, FunctionSymbol{Symbol: up.Sym, DependsOn: up.DependsOn})
	}
	i.Logger.Info("I_TEST", "symbols", symbols) // "symbols":[{"Symbol":"net/http.serverHandler.ServeHTTP","DependsOn":null}

	return NewManifest(i.ID, structfields, symbols)
}

// Load loads all instrumentation offsets. // TODO: 加载所有instrumentation offsets.
func (i *Base[BPFObj, BPFEvent]) Load(exec *link.Executable, td *process.TargetDetails) error {
	spec, err := i.SpecFn() // 获取加载EBPF程序的方法
	if err != nil {
		return err
	}
	i.Logger.Info("I_TEST", "spec", spec) //

	err = i.injectConsts(td, spec) // TODO: 核心方法, 写入常量
	if err != nil {
		return err
	}

	obj, err := i.buildObj(exec, td, spec) // TODO: 核心方法, 构建EBPFObject
	if err != nil {
		return err
	}
	i.Logger.Info("I_TEST", "obj", spec) // ??? {"level":"info","ts":1715226684.7854648,"logger":"Instrumentation.Manager.net/http/server","caller":"probe/probe.go:117","msg":"I_TEST","obj":{"Maps":{".rodata":{"Name":".rodata","Type":2,"KeySize":4,"ValueSize":144,"MaxEntries":1,"Flags":128,"Pinning":0,"NumaNode":0,"Contents":[{"Key":0,"Value":"6AAAAAAAAAA4AAAAAAAAAAgAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADgAAAAAAAAAsAAAAAAAAACAAAAAAAAAABgAAAAAAAAAeAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAA"}],"Freeze":true,"InnerMap":null,"Extra":null,"Key":{},"Value":{"Name":".rodata","Size":144,"Vars":[{"Type":{"Name":"ctx_ptr_pos","Type":{"Type":{"Type":{"Name":"u64","Type":{"Name":"__u64","Type":{"Name":"unsigned long long","Size":8,"Encoding":0}}}}},"Linkage":1},"Offset":0,"Size":8},{"Type":{"Name":"headers_ptr_pos","Type":{"Type":{"Type":{"Name":"u64","Type":{"Name":"__u64","Type":{"Name":"unsigned long long","Size":8,"Encoding":0}}}}},"Linkage":1},"Offset":8,"Size":8},{"Type":{"Name":"req_ptr_pos","Type":{"Type":{"Type":{"Name":"u64","Type":{"Name":"__u64","Type":{"Name":"unsigned long long","Size":8,"Encoding":0}}}}},"Linkage":1},"Offset":16,"Size":8},{"Type":{"Name":"url_ptr_pos","Type":{"Type":{"Type":{"Name":"u64","Type":{"Name":"__u64","Type":{"Name":"unsigned long long","Size":8,"Encoding":0}}}}},"Linkage":1},"Offset":24,"Size":8},{"Type":{"Name":"method_ptr_pos","Type":{"Type":{"Type":{"Name":"u64","Type":{"Name":"__u64","Type":{"Name":"unsigned long long","Size":8,"Encoding":0}}}}}

	i.reader, err = i.ReaderFn(*obj)              // HTTPServer的reader: return perf.NewReader(obj.Events, os.Getpagesize()), TODO: 后面就可以从ebpf程序read数据了.
	i.Logger.Info("I_TEST", "i.reader", i.reader) // "i.reader":{}
	if err != nil {
		return err
	}
	i.closers = append(i.closers, i.reader)

	return nil
}

func (i *Base[BPFObj, BPFEvent]) injectConsts(td *process.TargetDetails, spec *ebpf.CollectionSpec) error {
	opts, err := consts(i.Consts).injectOpts(td)
	if err != nil {
		return err
	}
	return inject.Constants(spec, opts...) // TODO: 在consts.go文件里面
}

func (i *Base[BPFObj, BPFEvent]) buildObj(exec *link.Executable, td *process.TargetDetails, spec *ebpf.CollectionSpec) (*BPFObj, error) {
	obj := new(BPFObj)
	if c, ok := ((interface{})(obj)).(io.Closer); ok {
		i.closers = append(i.closers, c)
	}

	sOpts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpffs.PathForTargetApplication(td),
		},
	}
	err := utils.LoadEBPFObjects(spec, obj, sOpts) // TODO: ???
	i.Logger.Info("I_TEST", "spec", "spec", "obj", obj, "sOpts", sOpts)
	if err != nil {
		return nil, err
	}

	for _, up := range i.Uprobes {
		// {"level":"info","ts":1715236054.0010176,"logger":"Instrumentation.Manager.net/http/server","caller":"probe/probe.go:154","msg":"I_TEST","upError":"json: unsupported type: probe.UprobeFunc[go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/net/http/server.bpfObjects]","up.fnError":"json: unsupported type: probe.UprobeFunc[go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/net/http/server.bpfObjects]","up.sym":"net/http.serverHandler.ServeHTTP"}
		i.Logger.Info("I_TEST", "up", up, "up.fn", up.Fn, "up.sym", up.Sym)
		links, err := up.Fn(up.Sym, exec, td, obj) // TODO: 核心方法: attach the eBPF program to the function.  Httpserver对应的Fn是: uprobeServeHTTP
		i.Logger.Info("I_TEST", "links", links)    // "links":[{},{}]
		if err != nil {
			if up.Optional {
				i.Logger.Info("failed to attach optional uprobe", "probe", i.ID, "symbol", up.Sym, "error", err)
				continue
			}
			return nil, err
		}
		for _, l := range links {
			i.closers = append(i.closers, l)
		}
	}

	return obj, nil
}

// Run runs the events processing loop.
func (i *Base[BPFObj, BPFEvent]) Run(dest chan<- *Event) {
	for {
		i.Logger.Info("------------run----------------")
		record, err := i.reader.Read() // TODO: 核心方法
		// 示例1："record":{"CPU":5,"RawSample":"SV9URVNUOnN0YXJ0","LostSamples":0,"Remaining":0}  SV9URVNUOnN0YXJ0 -> base64解码：I_TEST:start
		// 示例2："record":{"CPU":6,"RawSample":"SV9URVNUOmVuZAAA","LostSamples":0,"Remaining":872} SV9URVNUOmVuZAAA -> base64解码：I_TEST:end
		// 示例3："record":{"CPU":6,"RawSample":"fTnZLgsPAwBrQqYwCw8DAHhIai/BeSE5Ufk7aauNikLi8DIfQGDXdwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMgAAAAAAAAAR0VUAAAAAAAvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMTAuMC4yMC4yMTM6NTQ0NjkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADEwLjAuNi4xMDI6ODA4MAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIVFRQLzEuMQAAAAA=","LostSamples":0,"Remaining":0}
		// ${RawSample}是经过base64编码的...
		i.Logger.Info("I_TEST", "record", record)
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			i.Logger.Error(err, "error reading from perf reader")
			continue
		}

		if record.LostSamples != 0 {
			i.Logger.Info("perf event ring buffer full", "dropped", record.LostSamples)
			continue
		}

		se, err := i.processRecord(record) // TODO: 核心方法
		i.Logger.Info("I_TEST", "se", se)
		if err != nil {
			i.Logger.Error(err, "failed to process perf record")
		}
		e := &Event{
			Package:    i.ID.InstrumentedPkg,
			Kind:       i.ID.SpanKind,
			SpanEvents: se,
		}
		i.Logger.Info("I_TEST", "e", e.SpanEvents)
		dest <- e // TODO: 放到dest队列中...
	}
}

func (i *Base[BPFObj, BPFEvent]) processRecord(record perf.Record) ([]*SpanEvent, error) {
	buf := bytes.NewBuffer(record.RawSample) // 转换为字节流: "buf":"\ufffd\ufffd\u0016\ufffdf\u0012\u0003\u0000\ufffd{\ufffd\ufffdf\u0012\u0003\u0000hq\u0019Q4\ufffd2\ufffd`)\ufffd\ufffd{\ufffd\ufffdP\u0008\ufffdX_\ufffd QX\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\ufffd\u0000\u0000\u0000\u0000\u0000\u0000\u0000GET\u0000\u0000\u0000\u0000\u0000/favicon.ico\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u000010.0.20.213:60973\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u000010.0.6.102:8080\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000HTTP/1.1\u0000\u0000\u0000\u0000"
	i.Logger.Info("I_TEST", "buf", buf)

	var event BPFEvent
	err := binary.Read(buf, binary.LittleEndian, &event) // TODO: 核心方法...
	if err != nil {
		return nil, err
	}
	return i.ProcessFn(&event), nil
}

// Close stops the Probe.
func (i *Base[BPFObj, BPFEvent]) Close() error {
	var err error
	for _, c := range i.closers {
		err = errors.Join(err, c.Close())
	}
	if err == nil {
		i.Logger.Info("Closed", "Probe", i.ID)
	}
	return err
}

// TODO: 核心重点
// UprobeFunc is a function that will attach a eBPF program to a perf event
// that fires when the given symbol starts executing in exec.
//
// It is expected the symbol belongs to are shared library and its offset can
// be determined using target.
//
// Losing the reference to the resulting Link (up) will close the Uprobe and
// prevent further execution of prog. The Link must be Closed during program
// shutdown to avoid leaking system resources.
type UprobeFunc[BPFObj any] func(symbol string, exec *link.Executable, target *process.TargetDetails, obj *BPFObj) ([]link.Link, error)

// Uprobe is an eBPF program that is attached in the entry point and/or the reutrn of a function.
type Uprobe[BPFObj any] struct { // TODO: 核心结构体
	// Sym is the symbol name of the function to attach the eBPF program to.
	Sym string
	// Fn is the function that will attach the eBPF program to the function. // TODO: 核心方法
	Fn UprobeFunc[BPFObj]
	// Optional is a boolean flag informing if the Uprobe is optional. If the
	// Uprobe is optional and fails to attach, the error is logged and
	// processing continues.
	Optional  bool
	DependsOn []string
}

// Const is an constant that needs to be injected into an eBPF program.
type Const interface {
	// InjectOption returns the inject.Option to run for the Const when running
	// inject.Constants.
	InjectOption(td *process.TargetDetails) (inject.Option, error)
}

type consts []Const

func (c consts) structFields() []structfield.ID {
	var out []structfield.ID
	for _, cnst := range c {
		if sfc, ok := cnst.(StructFieldConst); ok {
			out = append(out, sfc.Val)
		}
	}
	return out
}

func (c consts) injectOpts(td *process.TargetDetails) ([]inject.Option, error) {
	var (
		out []inject.Option
		err error
	)
	for _, cnst := range c {
		o, e := cnst.InjectOption(td)
		err = errors.Join(err, e)
		if e == nil && o != nil {
			out = append(out, o)
		}
	}
	return out, err
}

// StructFieldConst is a [Const] for a struct field offset. These struct field
// ID needs to be known offsets in the [inject] package.
type StructFieldConst struct {
	Key string
	Val structfield.ID
}

// InjectOption returns the appropriately configured [inject.WithOffset] if the
// version of the struct field module is known. If it is not, an error is
// returned.
func (c StructFieldConst) InjectOption(td *process.TargetDetails) (inject.Option, error) {
	ver, ok := td.Libraries[c.Val.ModPath]
	if !ok {
		return nil, fmt.Errorf("unknown module version: %s", c.Val.ModPath)
	}
	return inject.WithOffset(c.Key, c.Val, ver), nil
}

// StructFieldConstMinVersion is a [Const] for a struct field offset. These struct field
// ID needs to be known offsets in the [inject] package. The offset is only
// injected if the module version is greater than or equal to the MinVersion.
type StructFieldConstMinVersion struct {
	StructField StructFieldConst
	MinVersion  *version.Version
}

// InjectOption returns the appropriately configured [inject.WithOffset] if the
// version of the struct field module is known and is greater than or equal to
// the MinVersion. If the module version is not known, an error is returned.
// If the module version is known but is less than the MinVersion, no offset is
// injected.
func (c StructFieldConstMinVersion) InjectOption(td *process.TargetDetails) (inject.Option, error) {
	sf := c.StructField
	ver, ok := td.Libraries[sf.Val.ModPath]
	if !ok {
		return nil, fmt.Errorf("unknown module version: %s", sf.Val.ModPath)
	}

	if !ver.GreaterThanOrEqual(c.MinVersion) {
		return nil, nil
	}

	return inject.WithOffset(sf.Key, sf.Val, ver), nil
}

// AllocationConst is a [Const] for all the allocation details that need to be
// injected into an eBPF program.
type AllocationConst struct{}

// InjectOption returns the appropriately configured
// [inject.WithAllocationDetails] if the [process.AllocationDetails] within td
// are not nil. An error is returned if [process.AllocationDetails] is nil.
func (c AllocationConst) InjectOption(td *process.TargetDetails) (inject.Option, error) {
	if td.AllocationDetails == nil {
		return nil, errors.New("no allocation details")
	}
	return inject.WithAllocationDetails(*td.AllocationDetails), nil
}

// RegistersABIConst is a [Const] for the boolean flag informing an eBPF
// program if the Go space has registered ABI.
type RegistersABIConst struct{}

// InjectOption returns the appropriately configured [inject.WithRegistersABI].
func (c RegistersABIConst) InjectOption(td *process.TargetDetails) (inject.Option, error) {
	return inject.WithRegistersABI(td.IsRegistersABI()), nil
}

// KeyValConst is a [Const] for a generic key-value pair.
//
// This should not be used as a replacement for any of the other provided
// [Const] implementations. Those implementations may have added significance
// and should be used instead where applicable.
type KeyValConst struct {
	Key string
	Val interface{}
}

// InjectOption returns the appropriately configured [inject.WithKeyValue].
func (c KeyValConst) InjectOption(*process.TargetDetails) (inject.Option, error) {
	return inject.WithKeyValue(c.Key, c.Val), nil
}
