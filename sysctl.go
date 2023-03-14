package ebpfbench

import (
	"fmt"
	"os"
)

var bpfSysctlProcfile = "/proc/sys/kernel/bpf_stats_enabled"

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func validSysctlPath(path string) error {
	exists, err := fileExists(path)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("invalid sysctl path %s, it does not exist", path)
	}
	return nil
}

func writeSysctl(path string, val []byte) error {
	if err := validSysctlPath(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	n, err := f.Write(val)
	if err != nil {
		return err
	}
	if n != len(val) {
		return fmt.Errorf("write to sysctl %s too short, expected %d got %d", path, len(val), n)
	}
	return nil
}

// readSysctl reads a single byte from the sysctl at the given path.
func readSysctl(path string) ([]byte, error) {
	val := make([]byte, 1)
	if err := validSysctlPath(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	n, err := f.Read(val)
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, fmt.Errorf("read to sysctl %s failed, expected %d got %d", path, 1, n)
	}
	return val, nil
}
