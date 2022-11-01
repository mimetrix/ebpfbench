//go:build linux
// +build linux

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/DataDog/ebpfbench"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang  bpf benchtest.c -- -I../headers

func main() {

	// eb := ebpfbech.NewEBPFBenchmark(&testing.B{})
	eb := ebpfbench.NewEBPFBenchmark(&testing.B{})

	// Name of the kernel function to trace.
	fn := "sys_execve"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, objs.Open, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// // Read loop reporting the total amount of times the kernel
	// // function was entered, once per second.
	// ticker := time.NewTicker(1 * time.Second)
	// defer ticker.Stop()

	// log.Println("Waiting for events..")

	// for range ticker.C {
	// 	var value uint64
	// 	// if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
	// 	// log.Fatalf("reading map: %v", err)
	// 	// }
	// 	log.Printf("%s called %d times\n", fn, value)
	// }

	// register probe with benchmark and run
	eb.ProfileProgram(objs.Open.FD(), "")

	ctx, cancelFunc := context.WithCancel(context.Background())
	bpfProgStatsCh, erroCh := eb.Start(ctx)

	// open b.N temp files
	go func() {
		for {
			select {
			case b := <-bpfProgStatsCh:
				for _, stat := range b.BpfProgramStats {
					fmt.Printf("Run %d us\n", stat.RunTime.Microseconds())
					fmt.Printf("Run %d counter\n", stat.RunCount)
				}
			case e := <-erroCh:
				fmt.Printf("ERROR %v", e)
			}
		}
	}()

	for i := 0; i < 10000; i++ {
		fmt.Printf("Iteraction %v\n", i)
		time.Sleep(time.Second)
		f, err := ioutil.TempFile(os.TempDir(), "ebpf-benchtest-*")
		if err != nil {
			log.Fatal(err)
		}
		_, err = f.Write([]byte{1})
		if err != nil {
			log.Fatal(err)
		}
		fn := f.Name()
		_ = f.Close()
		_ = os.Remove(fn)
	}
	cancelFunc()
}
