#include "bpf_helpers.h"
#include <linux/types.h>

SEC("kprobe/do_sys_open")
int open() {
    __u64 ns = bpf_ktime_get_ns();
    return 0;
}

char __license[] SEC("license") = "Dual BSD/GPL";
