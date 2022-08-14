/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

// Custom eBPF helpers
#include "include/all.h"

// Effectively returns task->group_leader->real_start_time;
// Note that before Linux 5.5, real_start_time was called start_boottime.
static inline __attribute__((__always_inline__)) int get_tgid() {
  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  u32 tgid = BPF_CORE_READ(task, tgid);
  return tgid;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int sys_enter_mkdirat(void *ctx)
{
    bpf_printk("mkdirat enter (tracepoint)\n");
    return 0;
};

SEC("tracepoint/my_tracepoint")
int my_tracepoint(void *ctx)
{
    // bpf_printk("my_tracepoint (tracepoint)\n");
    const int current_tgid = get_tgid();
    bpf_printk("PID from my_tracepoint: %d\n", current_tgid);
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
