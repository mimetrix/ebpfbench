package ebpfbench

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

type disableFunc func() error

var SupportsStatsSyscall = supportsBpfEnableStats()()

func enableBPFStats() (disableFunc, error) {
	var fd *wrappedFD
	var err error

	if SupportsStatsSyscall {
		fd, err = bpfEnableStats()
		if err != nil && !errors.Is(err, unix.EINVAL) {
			return nil, err
		}
	}

	err = writeSysctl(bpfSysctlProcfile, []byte("1"))
	if err != nil {
		return nil, err
	}
	return disableBPFStats(fd), nil
}

func isBPFStatsEnabled() (bool, error) {
	val, err := readSysctl(bpfSysctlProcfile)
	if err != nil {
		return false, err
	}
	return val[0] == '1', nil
}

func disableBPFStats(fd *wrappedFD) func() error {
	return func() error {
		if fd != nil {
			return fd.Close()
		}
		return writeSysctl(bpfSysctlProcfile, []byte("0"))
	}
}

type bpfProgramStats struct {
	Name     string
	RunCount uint
	RunTime  time.Duration
}

func getProgramStats(fd int) (*bpfProgramStats, error) {
	pi, err := bpfGetProgInfoByFD(fd)
	if err != nil {
		return nil, err
	}
	name := goString(pi.name[:])
	return &bpfProgramStats{
		Name:     name,
		RunCount: uint(pi.run_cnt),
		RunTime:  time.Duration(pi.run_time_ns),
	}, nil
}
