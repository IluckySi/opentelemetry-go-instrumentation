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

package instrumentation

import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/go-logr/logr"
	"sync"

	//dbSql "go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/database/sql"
	//kafkaConsumer "go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/github.com/segmentio/kafka-go/consumer"
	//kafkaProducer "go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/github.com/segmentio/kafka-go/producer"
	otelTraceGlobal "go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/go.opentelemetry.io/otel/traceglobal"
	//grpcClient "go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/google.golang.org/grpc/client"
	//grpcServer "go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/google.golang.org/grpc/server"
	httpClient "go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/net/http/client"
	httpServer "go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/net/http/server"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/bpffs"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/probe"
	"go.opentelemetry.io/auto/internal/pkg/opentelemetry"
	"go.opentelemetry.io/auto/internal/pkg/process"
)

// Manager handles the management of [probe.Probe] instances.
type Manager struct {
	logger         logr.Logger
	probes         map[probe.ID]probe.Probe
	done           chan bool
	incomingEvents chan *probe.Event
	otelController *opentelemetry.Controller
	globalImpl     bool
	wg             sync.WaitGroup
	closingErrors  chan error
}

// NewManager returns a new [Manager].
func NewManager(logger logr.Logger, otelController *opentelemetry.Controller, globalImpl bool) (*Manager, error) {
	logger = logger.WithName("Manager")
	m := &Manager{
		logger:         logger,
		probes:         make(map[probe.ID]probe.Probe),
		done:           make(chan bool, 1),
		incomingEvents: make(chan *probe.Event),
		otelController: otelController,
		globalImpl:     globalImpl,
		closingErrors:  make(chan error, 1),
	}

	err := m.registerProbes() // TODO: 注册probe
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (m *Manager) validateProbeDependents(id probe.ID, symbols []probe.FunctionSymbol) error {
	// Validate that dependent probes point to real standalone probes.
	funcsMap := make(map[string]interface{})
	m.logger.Info("I_TEST", "symbols", symbols) // server: "symbols":[{"Symbol":"net/http.serverHandler.ServeHTTP","DependsOn":null}]  client: "symbols":[{"Symbol":"net/http.(*Transport).roundTrip","DependsOn":null},{"Symbol":"net/http.Header.writeSubset","DependsOn":["net/http.(*Transport).roundTrip"]}]
	for _, s := range symbols {
		funcsMap[s.Symbol] = nil
	}

	for _, s := range symbols {
		m.logger.Info("I_TEST", "s", s) // "s":{"Symbol":"net/http.serverHandler.ServeHTTP","DependsOn":null}
		for _, d := range s.DependsOn {
			m.logger.Info("I_TEST", "d", d) // "iError":"json: unsupported type: probe.UprobeFunc[go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/net/http/client.bpfObjects]"
			if _, exists := funcsMap[d]; !exists {
				return fmt.Errorf("library %s has declared a dependent function %s for probe %s which does not exist, aborting", id, d, s.Symbol)
			}
		}
	}

	return nil
}

func (m *Manager) registerProbe(p probe.Probe) error {
	m.logger.Info("I_TEST", "probe", p) // 以httpserver为例: "probeError":"json: unsupported type: probe.UprobeFunc[go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/net/http/server.bpfObjects]"
	id := p.Manifest().Id
	m.logger.Info("I_TEST", "p.Manifest().Id", id) // "p.Manifest().Id":"net/http/server"
	if _, exists := m.probes[id]; exists {
		return fmt.Errorf("library %s registered twice, aborting", id)
	}

	if err := m.validateProbeDependents(id, p.Manifest().Symbols); err != nil {
		return err
	} // TODO:PR:id.Symbols

	m.probes[id] = p
	return nil
}

// GetRelevantFuncs returns the instrumented functions for all managed probes.
func (m *Manager) GetRelevantFuncs() map[string]interface{} {
	m.logger.Info("I_TEST", "GetRelevantFuncs")
	funcsMap := make(map[string]interface{})
	for _, i := range m.probes {
		for _, s := range i.Manifest().Symbols {
			funcsMap[s.Symbol] = nil
		}
	}

	return funcsMap
}

// FilterUnusedProbes filterers probes whose functions are already instrumented
// out of the Manager.
func (m *Manager) FilterUnusedProbes(target *process.TargetDetails) {
	existingFuncMap := make(map[string]interface{})
	for _, f := range target.Functions {
		existingFuncMap[f.Name] = nil
	}

	for name, inst := range m.probes {
		funcsFound := false
		for _, s := range inst.Manifest().Symbols {
			if len(s.DependsOn) == 0 {
				if _, exists := existingFuncMap[s.Symbol]; exists {
					funcsFound = true
					break
				}
			}
		}

		if !funcsFound {
			m.logger.Info("no functions found for probe, removing", "name", name)
			delete(m.probes, name)
		}
	}
}

// Run runs the event processing loop for all managed probes.
func (m *Manager) Run(ctx context.Context, target *process.TargetDetails) error {
	m.logger.Info("-------------------——Run--------------------")
	if len(m.probes) == 0 {
		err := errors.New("no instrumentation for target process")
		close(m.closingErrors)
		return err
	}

	err := m.load(target) // TODO: 核心方法
	if err != nil {
		close(m.closingErrors)
		return err
	}

	m.wg.Add(len(m.probes))
	for _, i := range m.probes {
		go func(p probe.Probe) {
			defer m.wg.Done()
			p.Run(m.incomingEvents)
		}(i)
	}

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("shutting down all probes due to context cancellation")
			err := m.cleanup(target)
			err = errors.Join(err, ctx.Err())
			m.closingErrors <- err
			return nil
		case <-m.done:
			m.logger.Info("shutting down all probes due to signal")
			err := m.cleanup(target)
			m.closingErrors <- err
			return nil
		case e := <-m.incomingEvents:
			m.otelController.Trace(e)
		}
	}
}

func (m *Manager) load(target *process.TargetDetails) error {
	// Allow the current process to lock memory for eBPF resources.  // TODO: lock memory是什么行为?
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	exe, err := link.OpenExecutable(fmt.Sprintf("/proc/%d/exe", target.PID))
	if err != nil {
		return err
	}
	m.logger.Info("I_TEST", "exe", exe) // "exe":{}

	if err := m.mount(target); err != nil {
		return err
	} // TODO: 这是什么行为呢? 挂载目录??????

	// Load probes
	for name, i := range m.probes {
		m.logger.Info("loading probe", "probe", i, "name", name) // {"level":"info","ts":1715220803.3591125,"logger":"Instrumentation.Manager","caller":"instrumentation/manager.go:208","msg":"loading probe","probeError":"json: unsupported type: probe.UprobeFunc[go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/net/http/server.bpfObjects]","name":"net/http/server"}
		err := i.Load(exe, target)                               // TODO: 核心方法
		if err != nil {
			m.logger.Error(err, "error while loading probes, cleaning up", "name", name)
			return errors.Join(err, m.cleanup(target))
		}
	}

	m.logger.Info("loaded probes to memory", "total_probes", len(m.probes)) // {"level":"info","ts":1715153507.7838812,"logger":"Instrumentation.Manager","caller":"instrumentation/manager.go:215","msg":"loaded probes to memory","total_probes":2}
	return nil
}

func (m *Manager) mount(target *process.TargetDetails) error {
	if target.AllocationDetails != nil {
		m.logger.Info("Mounting bpffs", "allocations_details", target.AllocationDetails)
	} else {
		m.logger.Info("Mounting bpffs")
	}
	return bpffs.Mount(target)
}

func (m *Manager) cleanup(target *process.TargetDetails) error {
	var err error
	close(m.incomingEvents)
	for _, i := range m.probes {
		err = errors.Join(err, i.Close())
	}

	m.logger.Info("Cleaning bpffs")
	return errors.Join(err, bpffs.Cleanup(target))
}

// Close closes m.
func (m *Manager) Close() error {
	m.done <- true
	err := <-m.closingErrors
	m.wg.Wait()
	return err
}

func (m *Manager) registerProbes() error {
	insts := []probe.Probe{
		// TODO: 调试，先只保留httpserver和httpclient
		//grpcClient.New(m.logger),
		//grpcServer.New(m.logger),
		httpServer.New(m.logger),
		httpClient.New(m.logger),
		//dbSql.New(m.logger),
		//kafkaProducer.New(m.logger),
		//kafkaConsumer.New(m.logger),
	}
	m.logger.Info("I_TEST", "insts.probe", insts) // "insts.probeError":"json: unsupported type: probe.UprobeFunc[go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/google.golang.org/grpc/client.bpfObjects]"
	if m.globalImpl {
		insts = append(insts, otelTraceGlobal.New(m.logger))
	}

	for _, i := range insts {
		m.logger.Info("I_TEST", "i", i) // {"level":"info","ts":1715173340.1835983,"logger":"Instrumentation.Manager","caller":"instrumentation/manager.go:264","msg":"I_TEST","iError":"json: unsupported type: probe.UprobeFunc[go.opentelemetry.io/auto/internal/pkg/instrumentation/bpf/net/http/server.bpfObjects]"
		err := m.registerProbe(i)       // TODO: 注册Probe
		if err != nil {
			return err
		}
	}

	return nil
}
