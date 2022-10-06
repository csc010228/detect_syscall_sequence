// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <sys/types.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, size_t);
	__uint(max_entries, 1024 * 16);
} status SEC(".maps");

#include<asm/signal.h>
BEGIN
{
	printf("Tracing sliver implant... Hit Ctrl-C to end.\n");
	printf("%-9s %-20s %-10s %-10s %-20s\n", "TIME", "IMPLANT", "PID", "TID", "COMMAND");
}

SEC("tracepoint/syscalls/sys_enter_accept")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_acct")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_add_key")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_adjtimex")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_arm64_personality")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_brk")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_capget")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_chdir")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (*current_status_p == 2) {
		next_status = 3;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_chroot")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_adjtime")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_getres")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_gettime")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_nanosleep")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_settime")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone3")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (*current_status_p == 77) {
		next_status = 78;
	}
	else if (*current_status_p == 68) {
		next_status = 69;
	}
	else if (*current_status_p == 38) {
		next_status = 39;
	}
	else if (*current_status_p == 29) {
		next_status = 30;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_close_range")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_copy_file_range")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_create1")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_ctl")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (*current_status_p == 64) {
		next_status = 65;
	}
	else if (*current_status_p == 57) {
		next_status = 75;
	}
	else if (*current_status_p == 25) {
		next_status = 26;
	}
	else if (*current_status_p == 18) {
		next_status = 36;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (*current_status_p == 98 && (args->epfd==4 && args->maxevents==128)) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"cd");
		next_status = 0;
	}
	else if (*current_status_p == 97 && (args->epfd==4 && args->maxevents==128)) {
		next_status = 98;
	}
	else if (*current_status_p == 94 && (args->epfd==4 && args->maxevents==128)) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"cd");
		next_status = 0;
	}
	else if (*current_status_p == 93 && (args->epfd==4 && args->maxevents==128)) {
		next_status = 94;
	}
	else if (*current_status_p == 86 && (args->epfd==4 && args->maxevents==128)) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"mkdir");
		next_status = 0;
	}
	else if (*current_status_p == 85 && (args->epfd==4 && args->maxevents==128)) {
		next_status = 86;
	}
	else if (*current_status_p == 81 && (args->epfd==4 && args->maxevents==128)) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"ls");
		next_status = 0;
	}
	else if (*current_status_p == 80 && (args->epfd==4 && args->maxevents==128)) {
		next_status = 81;
	}
	else if (*current_status_p == 73) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"cat");
		next_status = 0;
	}
	else if (*current_status_p == 72) {
		next_status = 73;
	}
	else if (*current_status_p == 71) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"cat");
		next_status = 0;
	}
	else if (*current_status_p == 70) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"cat");
		next_status = 0;
	}
	else if (*current_status_p == 69) {
		next_status = 70;
	}
	else if (*current_status_p == 62 && (args->epfd==4 && args->maxevents==128)) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"rm");
		next_status = 0;
	}
	else if (*current_status_p == 61 && (args->epfd==4 && args->maxevents==128)) {
		next_status = 62;
	}
	else if (*current_status_p == 59) {
		next_status = 55;
	}
	else if (*current_status_p == 55) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"cat");
		next_status = 0;
	}
	else if (*current_status_p == 53 && (args->epfd==4 && args->maxevents==128)) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"pwd");
		next_status = 0;
	}
	else if (*current_status_p == 52 && (args->epfd==4 && args->maxevents==128)) {
		next_status = 53;
	}
	else if (*current_status_p == 50) {
		next_status = 55;
	}
	else if (*current_status_p == 47 && (args->epfd==4 && args->maxevents==128)) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"mkdir");
		next_status = 0;
	}
	else if (*current_status_p == 46 && (args->epfd==4 && args->maxevents==128)) {
		next_status = 47;
	}
	else if (*current_status_p == 42 && (args->epfd==4 && args->maxevents==128)) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"ls");
		next_status = 0;
	}
	else if (*current_status_p == 41 && (args->epfd==4 && args->maxevents==128)) {
		next_status = 42;
	}
	else if (*current_status_p == 34) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"cat");
		next_status = 0;
	}
	else if (*current_status_p == 33) {
		next_status = 34;
	}
	else if (*current_status_p == 32) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"cat");
		next_status = 0;
	}
	else if (*current_status_p == 31) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"cat");
		next_status = 0;
	}
	else if (*current_status_p == 30) {
		next_status = 31;
	}
	else if (*current_status_p == 23 && (args->epfd==4 && args->maxevents==128)) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"rm");
		next_status = 0;
	}
	else if (*current_status_p == 22 && (args->epfd==4 && args->maxevents==128)) {
		next_status = 23;
	}
	else if (*current_status_p == 20) {
		next_status = 16;
	}
	else if (*current_status_p == 16) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"cat");
		next_status = 0;
	}
	else if (*current_status_p == 14 && (args->epfd==4 && args->maxevents==128)) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"pwd");
		next_status = 0;
	}
	else if (*current_status_p == 13 && (args->epfd==4 && args->maxevents==128)) {
		next_status = 14;
	}
	else if (*current_status_p == 7 && (args->epfd==4 && args->maxevents==128)) {
		time("%H:%M:%S  ");printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"ping");
		next_status = 0;
	}
	else if (*current_status_p == 6 && (args->epfd==4 && args->maxevents==128)) {
		next_status = 7;
	}
	else if (*current_status_p == 11) {
		next_status = 16;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait2")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_eventfd2")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat2")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fadvise64_64")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fallocate")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_init")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_mark")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchdir")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchown")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fgetxattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_flistxattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_flock")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fremovexattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsconfig")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsetxattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsmount")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsopen")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fspick")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fstatfs")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_get_mempolicy")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_get_robust_list")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getcpu")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getcwd")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (*current_status_p == 90) {
		next_status = 91;
	}
	else if (*current_status_p == 9) {
		next_status = 10;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (*current_status_p == 76) {
		next_status = 77;
	}
	else if (*current_status_p == 75) {
		next_status = 76;
	}
	else if (*current_status_p == 37) {
		next_status = 38;
	}
	else if (*current_status_p == 36) {
		next_status = 37;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getegid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_geteuid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getgid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getgroups")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getitimer")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpeername")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpgid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getppid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpriority")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrandom")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getresgid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getresuid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrlimit")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrusage")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockname")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_gettid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_gettimeofday")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getuid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getxattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_add_watch")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_init1")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_rm_watch")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_cancel")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_destroy")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_getevents")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_pgetevents")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_setup")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_submit")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_enter")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_register")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_setup")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioprio_get")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioprio_set")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kcmp")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kexec_file_load")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kexec_load")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_keyctl")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_add_rule")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_create_ruleset")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_restrict_self")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lgetxattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_listxattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_llistxattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lremovexattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lseek")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lsetxattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mbind")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_membarrier")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_secret")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_migrate_pages")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mincore")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (*current_status_p == 56) {
		next_status = 83;
	}
	else if (*current_status_p == 17) {
		next_status = 44;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknodat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlock")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlock2")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlockall")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount_setattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_move_mount")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_move_pages")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_getsetattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_notify")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_open")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_timedreceive")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_timedsend")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_unlink")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mremap")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgctl")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgget")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgrcv")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgsnd")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msync")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_munlock")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_munlockall")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_name_to_handle_at")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (*current_status_p == 75) {
		next_status = 66;
	}
	else if (*current_status_p == 65) {
		next_status = 66;
	}
	else if (*current_status_p == 36) {
		next_status = 27;
	}
	else if (*current_status_p == 26) {
		next_status = 27;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (*current_status_p == 89) {
		next_status = 90;
	}
	else if (*current_status_p == 76) {
		next_status = 76;
	}
	else if (*current_status_p == 50) {
		next_status = 56;
	}
	else if (*current_status_p == 37) {
		next_status = 37;
	}
	else if (*current_status_p == 11) {
		next_status = 17;
	}
	else if (*current_status_p == 10) {
		next_status = 50;
	}
	else if (*current_status_p == 9) {
		next_status = 11;
	}
	else if (*current_status_p == 4) {
		next_status = 9;
	}
	else if (*current_status_p == 3) {
		next_status = 89;
	}
	else if (*current_status_p == 2) {
		next_status = 4;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_newuname")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_by_handle_at")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_tree")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (*current_status_p == 59) {
		next_status = 64;
	}
	else if (*current_status_p == 50) {
		next_status = 57;
	}
	else if (*current_status_p == 20) {
		next_status = 25;
	}
	else if (*current_status_p == 11) {
		next_status = 18;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_perf_event_open")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_getfd")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_open")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_send_signal")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe2")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pivot_root")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ppoll")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pread64")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv2")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_prlimit64")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_madvise")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_mrelease")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pselect6")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev2")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_quotactl")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_quotactl_fd")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (*current_status_p == 67) {
		next_status = 68;
	}
	else if (*current_status_p == 66) {
		next_status = 67;
	}
	else if (*current_status_p == 28) {
		next_status = 29;
	}
	else if (*current_status_p == 1 && (args->fd==3 && args->count==1676)) {
		next_status = 2;
	}
	else if (*current_status_p == 0 && (args->fd==3 && args->count==1676)) {
		next_status = 1;
	}
	else if (*current_status_p == 27) {
		next_status = 28;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_readahead")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlinkat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_reboot")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_remap_file_pages")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_removexattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_request_key")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_restart_syscall")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rseq")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigaction")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigpending")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigprocmask")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigqueueinfo")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigsuspend")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigtimedwait")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_tgsigqueueinfo")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_get_priority_max")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_get_priority_min")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getaffinity")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getparam")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getscheduler")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_rr_get_interval")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setaffinity")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setparam")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setscheduler")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_yield")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_seccomp")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_semctl")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_semget")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_semop")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_semtimedop")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendfile64")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_mempolicy")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_robust_list")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_tid_address")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setdomainname")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setfsgid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setfsuid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgroups")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sethostname")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setitimer")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setpgid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setpriority")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setrlimit")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_settimeofday")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setxattr")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmctl")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmdt")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmget")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sigaltstack")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_signalfd4")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_socketpair")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_splice")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_statfs")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_statx")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_swapoff")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_swapon")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync_file_range")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_syncfs")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sysinfo")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_syslog")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_tee")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_create")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_delete")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_getoverrun")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_gettime")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_settime")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_create")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_gettime")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_settime")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_times")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_umask")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_umount")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (*current_status_p == 58) {
		next_status = 58;
	}
	else if (*current_status_p == 50) {
		next_status = 58;
	}
	else if (*current_status_p == 19) {
		next_status = 19;
	}
	else if (*current_status_p == 11) {
		next_status = 19;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_userfaultfd")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_utimensat")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_vhangup")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_vmsplice")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_wait4")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_waitid")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (*current_status_p == 96 && (args->fd==3)) {
		next_status = 97;
	}
	else if (*current_status_p == 92 && (args->fd==3)) {
		next_status = 93;
	}
	else if (*current_status_p == 91 && (args->fd==3)) {
		next_status = 96;
	}
	else if (*current_status_p == 90 && (args->fd==3)) {
		next_status = 92;
	}
	else if (*current_status_p == 84 && (args->fd==3)) {
		next_status = 85;
	}
	else if (*current_status_p == 83 && (args->fd==3)) {
		next_status = 84;
	}
	else if (*current_status_p == 79 && (args->fd==3)) {
		next_status = 80;
	}
	else if (*current_status_p == 78 && (args->fd==3)) {
		next_status = 79;
	}
	else if (*current_status_p == 72) {
		next_status = 72;
	}
	else if (*current_status_p == 70) {
		next_status = 72;
	}
	else if (*current_status_p == 69) {
		next_status = 69;
	}
	else if (*current_status_p == 60 && (args->fd==3)) {
		next_status = 61;
	}
	else if (*current_status_p == 59) {
		next_status = 59;
	}
	else if (*current_status_p == 58 && (args->fd==3)) {
		next_status = 60;
	}
	else if (*current_status_p == 51 && (args->fd==3)) {
		next_status = 52;
	}
	else if (*current_status_p == 50 && (args->fd==3)) {
		next_status = 60;
	}
	else if (*current_status_p == 50) {
		next_status = 59;
	}
	else if (*current_status_p == 45 && (args->fd==3)) {
		next_status = 46;
	}
	else if (*current_status_p == 44 && (args->fd==3)) {
		next_status = 45;
	}
	else if (*current_status_p == 40 && (args->fd==3)) {
		next_status = 41;
	}
	else if (*current_status_p == 39 && (args->fd==3)) {
		next_status = 40;
	}
	else if (*current_status_p == 33) {
		next_status = 33;
	}
	else if (*current_status_p == 31) {
		next_status = 33;
	}
	else if (*current_status_p == 30) {
		next_status = 30;
	}
	else if (*current_status_p == 21 && (args->fd==3)) {
		next_status = 22;
	}
	else if (*current_status_p == 20) {
		next_status = 20;
	}
	else if (*current_status_p == 19 && (args->fd==3)) {
		next_status = 21;
	}
	else if (*current_status_p == 12 && (args->fd==3)) {
		next_status = 13;
	}
	else if (*current_status_p == 11 && (args->fd==3)) {
		next_status = 21;
	}
	else if (*current_status_p == 10 && (args->fd==3)) {
		next_status = 51;
	}
	else if (*current_status_p == 9 && (args->fd==3)) {
		next_status = 12;
	}
	else if (*current_status_p == 5 && (args->fd==3)) {
		next_status = 6;
	}
	else if (*current_status_p == 2 && (args->fd==3)) {
		next_status = 5;
	}
	else if (*current_status_p == 11) {
		next_status = 20;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int handle_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}








































































































































































































































































































END
{
	printf("Tracing sliver implant end.\n");
}

