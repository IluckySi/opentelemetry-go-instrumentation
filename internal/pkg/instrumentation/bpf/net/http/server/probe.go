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

package server

import (
	"github.com/siddontang/go-log/log"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/go-logr/logr"
	"github.com/hashicorp/go-version"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/auto/internal/pkg/inject"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/net/http"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/context"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/probe"
	"go.opentelemetry.io/auto/internal/pkg/process"
	"go.opentelemetry.io/auto/internal/pkg/structfield"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cc clang -cflags $CFLAGS bpf ./bpf/probe.bpf.c

const (
	// pkg is the package being instrumented.
	pkg = "net/http"
)

// New returns a new [probe.Probe].
func New(logger logr.Logger) probe.Probe {
	log.Info("I_TEST", "New", "HTTPServer") // [2024/05/08 13:02:20] [info] probe.go:48 I_TESTNewHTTPServer
	id := probe.ID{
		SpanKind:        trace.SpanKindServer,
		InstrumentedPkg: pkg,
	}
	return &probe.Base[bpfObjects, event]{
		ID:     id,
		Logger: logger.WithName(id.String()),
		Consts: []probe.Const{
			probe.RegistersABIConst{},
			probe.StructFieldConst{
				Key: "method_ptr_pos",
				Val: structfield.NewID("std", "net/http", "Request", "Method"),
			},
			probe.StructFieldConst{
				Key: "url_ptr_pos",
				Val: structfield.NewID("std", "net/http", "Request", "URL"),
			},
			probe.StructFieldConst{
				Key: "ctx_ptr_pos",
				Val: structfield.NewID("std", "net/http", "Request", "ctx"),
			},
			probe.StructFieldConst{
				Key: "path_ptr_pos",
				Val: structfield.NewID("std", "net/url", "URL", "Path"),
			},
			probe.StructFieldConst{
				Key: "headers_ptr_pos",
				Val: structfield.NewID("std", "net/http", "Request", "Header"),
			},
			probe.StructFieldConst{
				Key: "req_ptr_pos",
				Val: structfield.NewID("std", "net/http", "response", "req"),
			},
			probe.StructFieldConst{
				Key: "status_code_pos",
				Val: structfield.NewID("std", "net/http", "response", "status"),
			},
			probe.StructFieldConst{
				Key: "buckets_ptr_pos",
				Val: structfield.NewID("std", "runtime", "hmap", "buckets"),
			},
			probe.StructFieldConst{
				Key: "remote_addr_pos",
				Val: structfield.NewID("std", "net/http", "Request", "RemoteAddr"),
			},
			probe.StructFieldConst{
				Key: "host_pos",
				Val: structfield.NewID("std", "net/http", "Request", "Host"),
			},
			probe.StructFieldConst{
				Key: "proto_pos",
				Val: structfield.NewID("std", "net/http", "Request", "Proto"),
			},
			probe.StructFieldConstMinVersion{
				StructField: probe.StructFieldConst{
					Key: "req_pat_pos",
					Val: structfield.NewID("std", "net/http", "Request", "pat"),
				},
				MinVersion: patternPathMinVersion,
			},
			probe.StructFieldConstMinVersion{
				StructField: probe.StructFieldConst{
					Key: "pat_str_pos",
					Val: structfield.NewID("std", "net/http", "pattern", "str"),
				},
				MinVersion: patternPathMinVersion,
			},
			patternPathSupportedConst{},
		},
		Uprobes: []probe.Uprobe[bpfObjects]{
			{
				Sym: "net/http.serverHandler.ServeHTTP",
				Fn:  uprobeServeHTTP,
			},
		},

		ReaderFn: func(obj bpfObjects) (*perf.Reader, error) { // TODO: 关键方法,接收EBPF程序的数据
			return perf.NewReader(obj.Events, os.Getpagesize())
		},
		SpecFn:    loadBpf,      // TODO: 加载BPF
		ProcessFn: convertEvent, // TODO: 转换事件
	}
}

type patternPathSupportedConst struct{}

var (
	patternPathMinVersion  = version.Must(version.NewVersion("1.22.0"))
	isPatternPathSupported = false
)

func (c patternPathSupportedConst) InjectOption(td *process.TargetDetails) (inject.Option, error) {
	isPatternPathSupported = td.GoVersion.GreaterThanOrEqual(patternPathMinVersion)
	return inject.WithKeyValue("pattern_path_supported", isPatternPathSupported), nil
}

func uprobeServeHTTP(name string, exec *link.Executable, target *process.TargetDetails, obj *bpfObjects) ([]link.Link, error) {
	offset, err := target.GetFunctionOffset(name)
	log.Info("I_TEST", "name", name, "offset", offset) // I_TESTnamenet/http.serverHandler.ServeHTTPoffset2248992
	if err != nil {
		return nil, err
	}

	opts := &link.UprobeOptions{Address: offset, PID: target.PID}
	log.Info("I_TEST", "opts", opts, "obj.UprobeHandlerFuncServeHTTP", obj.UprobeHandlerFuncServeHTTP) // I_TESTopts&{2248992 0 76102 0 0 }
	// link.Executable.Uprobe是一个函数，用于在用户空间执行uprobes, uprobes是Linux内核中的一种功能，允许用户在指定的代码地址上插入断点，
	// 以便在运行时监视和分析程序的行为。这对于调试和性能优化非常有用。
	// 创建EBPF程序: SEC("uprobe/HandlerFunc_ServeHTTP"), 当HandlerFunc_ServeHTTP函数执行时会触发对应的方法....
	// obj.UprobeHandlerFuncServeHTTP ->  *ebpf.Program `ebpf:"uprobe_HandlerFunc_ServeHTTP"`,在probe.bpf.c文件中
	l, err := exec.Uprobe("", obj.UprobeHandlerFuncServeHTTP, opts) // TODO: 调C的方法了？？？确实...
	if err != nil {
		return nil, err
	}
	log.Info("I_TEST", "link", l) // I_TESTlink&{{0xc000abcd38 } 0xc00059e4d0}
	links := []link.Link{l}

	retOffsets, err := target.GetFunctionReturns(name)
	if err != nil {
		return nil, err
	}
	log.Info("I_TEST", "retOffsets", retOffsets) // I_TESTretOffsets[2249139]

	for _, ret := range retOffsets {
		opts := &link.UprobeOptions{Address: ret}
		log.Info("I_TEST", "opts", opts) // I_TESTopts&{2249139 0 0 0 0 }

		l, err := exec.Uprobe("", obj.UprobeHandlerFuncServeHTTP_Returns, opts)
		log.Info("I_TEST", "link", l) // I_TESTlink&{{0xc000abcda8 } 0xc00059e530}
		if err != nil {
			return nil, err
		}
		links = append(links, l)
	}

	return links, nil
}

// event represents an event in an HTTP server during an HTTP
// request-response.
type event struct {
	context.BaseSpanProperties
	StatusCode  uint64
	Method      [8]byte
	Path        [128]byte
	PathPattern [128]byte
	RemoteAddr  [256]byte
	Host        [256]byte
	Proto       [8]byte
}

func convertEvent(e *event) []*probe.SpanEvent {
	// TODO: base64转-> hex -> 10进制 -> unix切割, 注意前面已经解析完了....
	log.Info("I_TEST", "convertEvent", e) // [2024/05/09 08:00:02] [info] probe.go:200 I_TESTconvertEvent&{{860965635176829 860965665391211 {78486a2fc179213951f93b69ab8d8a42 e2f0321f4060d777} {00000000000000000000000000000000 0000000000000000}} 200 [71 69 84 0 0 0 0 0] [47 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] [49 48 46 48 46 50 48 46 50 49 51 58 53 52 52 54 57 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] [49 48 46 48 46 54 46 49 48 50 58 56 48 56 48 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] [72 84 84 80 47 49 46 49]}
	path := unix.ByteSliceToString(e.Path[:])
	method := unix.ByteSliceToString(e.Method[:])
	patternPath := unix.ByteSliceToString(e.PathPattern[:])
	log.Info("I_TEST", "path", path, "method", method, "patternPath", patternPath) // I_TESTpath/methodGETpatternPath

	isValidPatternPath := true
	patternPath, err := http.ParsePattern(patternPath)
	if err != nil || patternPath == "" {
		isValidPatternPath = false
	}

	proto := unix.ByteSliceToString(e.Proto[:])

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    e.SpanContext.TraceID,
		SpanID:     e.SpanContext.SpanID,
		TraceFlags: trace.FlagsSampled,
	})

	var pscPtr *trace.SpanContext
	if e.ParentSpanContext.TraceID.IsValid() {
		psc := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    e.ParentSpanContext.TraceID,
			SpanID:     e.ParentSpanContext.SpanID,
			TraceFlags: trace.FlagsSampled,
			Remote:     true,
		})
		pscPtr = &psc
	} else {
		pscPtr = nil
	}

	attributes := []attribute.KeyValue{
		semconv.HTTPRequestMethodKey.String(method),
		semconv.URLPath(path),
		semconv.HTTPResponseStatusCodeKey.Int(int(e.StatusCode)),
	}

	// Client address and port
	peerAddr, peerPort := http.NetPeerAddressPortAttributes(e.RemoteAddr[:])
	if peerAddr.Valid() {
		attributes = append(attributes, peerAddr)
	}
	if peerPort.Valid() {
		attributes = append(attributes, peerPort)
	}

	// Server address and port
	serverAddr, serverPort := http.ServerAddressPortAttributes(e.Host[:])
	if serverAddr.Valid() {
		attributes = append(attributes, serverAddr)
	}
	if serverPort.Valid() {
		attributes = append(attributes, serverPort)
	}

	if proto != "" {
		parts := strings.Split(proto, "/")
		if len(parts) == 2 {
			attributes = append(attributes, semconv.NetworkProtocolVersion(parts[1]))
		}
	}

	spanName := method
	if isPatternPathSupported && isValidPatternPath {
		spanName = spanName + " " + patternPath
		attributes = append(attributes, semconv.HTTPRouteKey.String(patternPath))
	}

	return []*probe.SpanEvent{
		{
			SpanName:          spanName,
			StartTime:         int64(e.StartTime),
			EndTime:           int64(e.EndTime),
			SpanContext:       &sc,
			ParentSpanContext: pscPtr,
			Attributes:        attributes,
		},
	}
}
