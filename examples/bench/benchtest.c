// +build ignore

#include "common.h"

char __license[] __attribute__((section("license"), used)) = "MIT";

__attribute__((section("kprobe/do_sys_open"), used))
int open() {
    __u64 ns = bpf_ktime_get_ns();
    return 0;
}
