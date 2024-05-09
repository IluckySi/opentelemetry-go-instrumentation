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

package process

import (
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/go-version"

	"go.opentelemetry.io/auto/internal/pkg/process/binary"
)

// TargetDetails are the details about a target function.
type TargetDetails struct {
	PID               int
	Functions         []*binary.Func
	GoVersion         *version.Version
	Libraries         map[string]*version.Version
	AllocationDetails *AllocationDetails
}

// IsRegistersABI returns if t is supported.
func (t *TargetDetails) IsRegistersABI() bool {
	regAbiMinVersion, _ := version.NewVersion("1.17")
	return t.GoVersion.GreaterThanOrEqual(regAbiMinVersion)
}

// GetFunctionOffset returns the offset for of the function with name.
func (t *TargetDetails) GetFunctionOffset(name string) (uint64, error) {
	for _, f := range t.Functions {
		if f.Name == name {
			return f.Offset, nil
		}
	}

	return 0, fmt.Errorf("could not find offset for function %s", name)
}

// GetFunctionReturns returns the return value of the call for the function
// with name.
func (t *TargetDetails) GetFunctionReturns(name string) ([]uint64, error) {
	for _, f := range t.Functions {
		if f.Name == name {
			return f.ReturnOffsets, nil
		}
	}

	return nil, fmt.Errorf("could not find returns for function %s", name)
}

// Analyze returns the target details for an actively running process.
func (a *Analyzer) Analyze(pid int, relevantFuncs map[string]interface{}) (*TargetDetails, error) {
	result := &TargetDetails{
		PID: pid,
	}

	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, err
	}

	defer f.Close()
	elfF, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}
	a.logger.Info("I_TEST", "elfF", elfF) // 读取elf文件："elfF":{"Class":2,"Data":1,"Version":1,"OSABI":0,"ABIVersion":0,"ByteOrder":{},"Type":2,"Machine":62,"Entry":4626944,"Sections":[{"Name":"","Type":0,"Flags":0,"Addr":0,"Offset":0,"Size":0,"Link":0,"Info":0,"Addralign":0,"Entsize":0,"FileSize":0,"ReaderAt":{}},{"Name":".text","Type":1,"Flags":6,"Addr":4198400,"Offset":4096,"Size":2379510,"Link":0,"Info":0,"Addralign":32,"Entsize":0,"FileSize":2379510,"ReaderAt":{}},{"Name":".plt","Type":1,"Flags":6,"Addr":6577920,"Offset":2383616,"Size":608,"Link":0,"Info":0,"Addralign":16,"Entsize":16,"FileSize":608,"ReaderAt":{}},{"Name":".rodata","Type":1,"Flags":2,"Addr":6582272,"Offset":2387968,"Size":1026147,"Link":0,"Info":0,"Addralign":32,"Entsize":0,"FileSize":1026147,"ReaderAt":{}},{"Name":".rela","Type":4,"Flags":2,"Addr":7608424,"Offset":3414120,"Size":24,"Link":11,"Info":0,"Addralign":8,"Entsize":24,"FileSize":24,"ReaderAt":{}},{"Name":".rela.plt","Type":4,"Flags":2,"Addr":7608448,"Offset":3414144,"Size":888,"Link":11,"Info":2,"Addralign":8,"Entsize":24,"FileSize":888,"ReaderAt":{}},{"Name":".gnu.version","Type":1879048191,"Flags":2,"Addr":7609344,"Offset":3415040,"Size":84,"Link":11,"Info":0,"Addralign":2,"Entsize":2,"FileSize":84,"ReaderAt":{}},{"Name":".gnu.version_r","Type":1879048190,"Flags":2,"Addr":7609440,"Offset":3415136,"Size":96,"Link":10,"Info":1,"Addralign":8,"Entsize":0,"FileSize":96,"ReaderAt":{}},{"Name":".hash","Type":5,"Flags":2,"Addr":7609536,"Offset":3415232,"Size":204,"Link":11,"Info":0,"Addralign":8,"Entsize":4,"FileSize":204,"ReaderAt":{}},{"Name":".shstrtab","Type":3,"Flags":0,"Addr":0,"Offset":3415456,"Size":371,"Link":0,"Info":0,"Addralign":1,"Entsize":0,"FileSize":371,"ReaderAt":{}},{"Name":".dynstr","Type":3,"Flags":2,"Addr":7610144,"Offset":3415840,"Size":626,"Link":0,"Info":0,"Addralign":1,"Entsize":0,"FileSize":626,"ReaderAt":{}},{"Name":".dynsym","Type":11,"Flags":2,"Addr":7610784,"Offset":3416480,"Size":1008,"Link":10,"Info":1,"Addralign":8,"Entsize":24,"FileSize":1008,"ReaderAt":{}},{"Name":".typelink","Type":1,"Flags":2,"Addr":7611808,"Offset":3417504,"Size":6084,"Link":0,"Info":0,"Addralign":32,"Entsize":0,"FileSize":6084,"ReaderAt":{}},{"Name":".itablink","Type":1,"Flags":2,"Addr":7617920,"Offset":3423616,"Size":2456,"Link":0,"Info":0,"Addralign":32,"Entsize":0,"FileSize":2456,"ReaderAt":{}},{"Name":".gosymtab","Type":1,"Flags":2,"Addr":7620376,"Offset":3426072,"Size":0,"Link":0,"Info":0,"Addralign":1,"Entsize":0,"FileSize":0,"ReaderAt":{}},{"Name":".gopclntab","Type":1,"Flags":2,"Addr":7620384,"Offset":3426080,"Size":1458832,"Link":0,"Info":0,"Addralign":32,"Entsize":0,"FileSize":1458832,"ReaderAt":{}},{"Name":".go.buildinfo","Type":1,"Flags":3,"Addr":9080832,"Offset":4886528,"Size":304,"Link":0,"Info":0,"Addralign":16,"Entsize":0,"FileSize":304,"ReaderAt":{}},{"Name":".dynamic","Type":6,"Flags":3,"Addr":9081152,"Offset":4886848,"Size":288,"Link":10,"Info":0,"Addralign":8,"Entsize":16,"FileSize":288,"ReaderAt":{}},{"Name":".got.plt","Type":1,"Flags":3,"Addr":9081440,"Offset":4887136,"Size":320,"Link":0,"Info":0,"Addralign":8,"Entsize":8,"FileSize":320,"ReaderAt":{}},{"Name":".got","Type":1,"Flags":3,"Addr":9081760,"Offset":4887456,"Size":8,"Link":0,"Info":0,"Addralign":8,"Entsize":8,"FileSize":8,"ReaderAt":{}},{"Name":".noptrdata","Type":1,"Flags":3,"Addr":9081792,"Offset":4887488,"Size":158114,"Link":0,"Info":0,"Addralign":32,"Entsize":0,"FileSize":158114,"ReaderAt":{}},{"Name":".data","Type":1,"Flags":3,"Addr":9239936,"Offset":5045632,"Size":40912,"Link":0,"Info":0,"Addralign":32,"Entsize":0,"FileSize":40912,"ReaderAt":{}},{"Name":".bss","Type":8,"Flags":3,"Addr":9280864,"Offset":5086560,"Size":196440,"Link":0,"Info":0,"Addralign":32,"Entsize":0,"FileSize":196440,"ReaderAt":{}},{"Name":".noptrbss","Type":8,"Flags":3,"Addr":9477312,"Offset":5283008,"Size":27504,"Link":0,"Info":0,"Addralign":32,"Entsize":0,"FileSize":27504,"ReaderAt":{}},{"Name":".tbss","Type":8,"Flags":1027,"Addr":0,"Offset":0,"Size":8,"Link":0,"Info":0,"Addralign":8,"Entsize":0,"FileSize":8,"ReaderAt":{}},{"Name":".debug_abbrev","Type":1,"Flags":2048,"Addr":0,"Offset":5087232,"Size":532,"Link":0,"Info":0,"Addralign":1,"Entsize":0,"FileSize":309,"ReaderAt":null},{"Name":".debug_line","Type":1,"Flags":2048,"Addr":0,"Offset":5087541,"Size":799619,"Link":0,"Info":0,"Addralign":1,"Entsize":0,"FileSize":427091,"ReaderAt":null},{"Name":".debug_frame","Type":1,"Flags":2048,"Addr":0,"Offset":5514632,"Size":285884,"Link":0,"Info":0,"Addralign":1,"Entsize":0,"FileSize":91617,"ReaderAt":null},{"Name":".debug_gdb_scripts","Type":1,"Flags":0,"Addr":0,"Offset":5606249,"Size":45,"Link":0,"Info":0,"Addralign":1,"Entsize":0,"FileSize":45,"ReaderAt":{}},{"Name":".debug_info","Type":1,"Flags":2048,"Addr":0,"Offset":5606294,"Size":1875389,"Link":0,"Info":0,"Addralign":1,"Entsize":0,"FileSize":757316,"ReaderAt":null},{"Name":".debug_loc","Type":1,"Flags":2048,"Addr":0,"Offset":6363610,"Size":3015984,"Link":0,"Info":0,"Addralign":1,"Entsize":0,"FileSize":552310,"ReaderAt":null},{"Name":".debug_ranges","Type":1,"Flags":2048,"Addr":0,"Offset":6915920,"Size":864416,"Link":0,"Info":0,"Addralign":1,"Entsize":0,"FileSize":157875,"ReaderAt":null},{"Name":".interp","Type":1,"Flags":2,"Addr":4198372,"Offset":4068,"Size":28,"Link":0,"Info":0,"Addralign":1,"Entsize":0,"FileSize":28,"ReaderAt":{}},{"Name":".note.go.buildid","Type":7,"Flags":2,"Addr":4198272,"Offset":3968,"Size":100,"Link":0,"Info":0,"Addralign":4,"Entsize":0,"FileSize":100,"ReaderAt":{}},{"Name":".symtab","Type":2,"Flags":0,"Addr":0,"Offset":7073800,"Size":170472,"Link":35,"Info":292,"Addralign":8,"Entsize":24,"FileSize":170472,"ReaderAt":{}},{"Name":".strtab","Type":3,"Flags":0,"Addr":0,"Offset":7244272,"Size":217579,"Link":0,"Info":0,"Addralign":1,"Entsize":0,"FileSize":217579,"ReaderAt":{}}],"Progs":[{"Type":6,"Flags":4,"Off":64,"Vaddr":4194368,"Paddr":4194368,"Filesz":504,"Memsz":504,"Align":4096,"ReaderAt":{}},{"Type":3,"Flags":4,"Off":4068,"Vaddr":4198372,"Paddr":4198372,"Filesz":28,"Memsz":28,"Align":1,"ReaderAt":{}},{"Type":4,"Flags":4,"Off":3968,"Vaddr":4198272,"Paddr":4198272,"Filesz":100,"Memsz":100,"Align":4,"ReaderAt":{}},{"Type":1,"Flags":5,"Off":0,"Vaddr":4194304,"Paddr":4194304,"Filesz":2384224,"Memsz":2384224,"Align":4096,"ReaderAt":{}},{"Type":1,"Flags":4,"Off":2387968,"Vaddr":6582272,"Paddr":6582272,"Filesz":2496944,"Memsz":2496944,"Align":4096,"ReaderAt":{}},{"Type":1,"Flags":6,"Off":4886528,"Vaddr":9080832,"Paddr":9080832,"Filesz":200032,"Memsz":423984,"Align":4096,"ReaderAt":{}},{"Type":2,"Flags":6,"Off":4886848,"Vaddr":9081152,"Paddr":9081152,"Filesz":288,"Memsz":288,"Align":8,"ReaderAt":{}},{"Type":7,"Flags":4,"Off":0,"Vaddr":0,"Paddr":0,"Filesz":0,"Memsz":8,"Align":8,"ReaderAt":{}},{"Type":1685382481,"Flags":6,"Off":0,"Vaddr":0,"Paddr":0,"Filesz":0,"Memsz":0,"Align":8,"ReaderAt":{}}]}

	goVersion, err := version.NewVersion(a.BuildInfo.GoVersion)
	if err != nil {
		return nil, err
	}
	a.logger.Info("I_TEST", "GoVersion", goVersion) // "GoVersion":"1.21.1"

	result.GoVersion = goVersion
	result.Libraries = make(map[string]*version.Version, len(a.BuildInfo.Deps)+1)
	for _, dep := range a.BuildInfo.Deps {
		depVersion, err := version.NewVersion(dep.Version)
		if err != nil {
			a.logger.Error(err, "error parsing module version")
			continue
		}
		result.Libraries[dep.Path] = depVersion
	}
	result.Libraries["std"] = goVersion

	a.logger.Info("I_TEST", "relevantFuncs", relevantFuncs)
	funcs, err := a.findFunctions(elfF, relevantFuncs)
	if err != nil {
		return nil, err
	}
	for _, fn := range funcs {
		a.logger.Info("found function", "function_name", fn)
	}

	result.Functions = funcs
	if len(result.Functions) == 0 {
		return nil, errors.New("could not find function offsets for instrumenter")
	}

	return result, nil
}

func (a *Analyzer) SetBuildInfo(pid int) error {
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return err
	}
	a.logger.Info("I_TEST", "f.name", f.Name()) // "f.name":"/proc/76102/exe"

	defer f.Close()
	bi, err := buildinfo.Read(f) // TODO: Read returns build information embedded in a Go binary file
	if err != nil {
		return err
	}
	a.logger.Info("I_TEST", "buildinfo", bi) // "buildinfo":"go\tgo1.21.1\npath\tcommand-line-arguments\nbuild\t-buildmode=exe\nbuild\t-compiler=gc\nbuild\tCGO_ENABLED=1\nbuild\tCGO_CFLAGS=\nbuild\tCGO_CPPFLAGS=\nbuild\tCGO_CXXFLAGS=\nbuild\tCGO_LDFLAGS=\nbuild\tGOARCH=amd64\nbuild\tGOOS=linux\nbuild\tGOAMD64=v1\n"

	bi.GoVersion = parseGoVersion(bi.GoVersion)
	a.logger.Info("I_TEST", "GoVersion", bi.GoVersion) // "GoVersion":"1.21.1"

	a.BuildInfo = bi
	a.logger.Info("I_TEST", "a.BuildInfo", a.BuildInfo) // "a.BuildInfo":"go\t1.21.1\npath\tcommand-line-arguments\nbuild\t-buildmode=exe\nbuild\t-compiler=gc\nbuild\tCGO_ENABLED=1\nbuild\tCGO_CFLAGS=\nbuild\tCGO_CPPFLAGS=\nbuild\tCGO_CXXFLAGS=\nbuild\tCGO_LDFLAGS=\nbuild\tGOARCH=amd64\nbuild\tGOOS=linux\nbuild\tGOAMD64=v1\n"
	return nil
}

func parseGoVersion(vers string) string {
	vers = strings.ReplaceAll(vers, "go", "")
	// Trims GOEXPERIMENT version suffix if present.
	if idx := strings.Index(vers, " X:"); idx > 0 {
		vers = vers[:idx]
	}
	return vers
}

func (a *Analyzer) findFunctions(elfF *elf.File, relevantFuncs map[string]interface{}) ([]*binary.Func, error) {
	result, err := binary.FindFunctionsUnStripped(elfF, relevantFuncs)
	if err != nil {
		if errors.Is(err, elf.ErrNoSymbols) {
			a.logger.Info("No symbols found in binary, trying to find functions using .gosymtab")
			return binary.FindFunctionsStripped(elfF, relevantFuncs)
		}
		return nil, err
	}

	return result, nil
}
