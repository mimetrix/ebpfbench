package ebpfbench

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

func NewEBPFBenchmark(b *testing.B) *EBPFBenchmark {
	return &EBPFBenchmark{
		b:      b,
		progs:  make(map[int]string),
		infoCh: make(chan fdNameTuple),
	}
}

type fdNameTuple struct {
	fd   int
	name string
}

type EBPFBenchmark struct {
	b     *testing.B
	progs map[int]string
	// infoCh transport the bpf fd and program name.
	infoCh chan fdNameTuple
}

func (e *EBPFBenchmark) ProfileProgram(fd int, name string) {
	e.infoCh <- fdNameTuple{
		fd:   fd,
		name: name,
	}
}

func (e *EBPFBenchmark) getAllStats() (map[int]*bpfProgramStats, error) {
	res := map[int]*bpfProgramStats{}
	for fd := range e.progs {
		stats, err := getProgramStats(fd)
		if err != nil {
			return nil, err
		}
		res[fd] = stats
	}
	return res, nil
}

type BpfProgramStatsEvent struct {
	BpfProgramStats   map[int]*bpfProgramStats
	TimestampInSecond int64
}

func (e *EBPFBenchmark) Start(ctx context.Context) (<-chan *BpfProgramStatsEvent, <-chan error) {

	disableFunc, err := enableBPFStats()
	if err != nil {
		return nil, nil
	}
	out := make(chan *BpfProgramStatsEvent)
	errc := make(chan error, 1)

	go func() {
		ticker := time.NewTicker(time.Second)

		for {
			select {
			case p := <-e.infoCh:
				e.progs[p.fd] = p.name
			case <-ticker.C:
				programsStats, err := e.getAllStats()
				if err != nil {
					errc <- err
				}
				out <- &BpfProgramStatsEvent{
					BpfProgramStats:   programsStats,
					TimestampInSecond: time.Now().Unix(),
				}

			case <-ctx.Done():
				disableFunc()
				close(out)
				close(errc)
			}
		}
	}()

	return out, errc
}

func (e *EBPFBenchmark) Close() {
	e.progs = make(map[int]string)
}

func (e *EBPFBenchmark) Run(fn func(*testing.B)) {
	disableFunc, err := enableBPFStats()
	if err != nil {
		e.b.Fatal(err)
	}
	defer func() { _ = disableFunc() }()

	var results map[string]*testing.BenchmarkResult
	e.b.Run("eBPF", func(b *testing.B) {
		baseline, err := e.getAllStats()
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		fn(b)
		b.StopTimer()

		post, err := e.getAllStats()
		if err != nil {
			b.Fatal(err)
		}

		// override outer variable here so we only report on the last run of results
		results = make(map[string]*testing.BenchmarkResult, len(baseline))
		for fd, base := range baseline {
			p := post[fd]
			runTime := p.RunTime - base.RunTime
			runCount := p.RunCount - base.RunCount
			name := e.progs[fd]
			if name == "" && p.Name != "" {
				name = p.Name
			}
			results[name] = &testing.BenchmarkResult{
				N: int(runCount),
				T: runTime,
			}
		}
	})
	fmt.Print(prettyPrintEBPFResults(e.b.Name(), results))
}

func prettyPrintEBPFResults(benchName string, results map[string]*testing.BenchmarkResult) string {
	maxLen := 0
	var names []string
	for name := range results {
		if len(name) > maxLen {
			maxLen = len(name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	buf := new(strings.Builder)
	for _, name := range names {
		pr := results[name]
		_, _ = fmt.Fprintf(buf, "%s/eBPF/%-*s\t%s\n", benchName, maxLen, name, pr.String())
	}
	return buf.String()
}
