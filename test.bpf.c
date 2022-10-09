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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_accept")
int handle_sys_enter_accept(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int handle_sys_enter_accept4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_acct")
int handle_sys_enter_acct(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_add_key")
int handle_sys_enter_add_key(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_adjtimex")
int handle_sys_enter_adjtimex(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_arm64_personality")
int handle_sys_enter_arm64_personality(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int handle_sys_enter_bind(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 7) {
		next_status = 8;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int handle_sys_enter_bpf(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_brk")
int handle_sys_enter_brk(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_capget")
int handle_sys_enter_capget(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int handle_sys_enter_capset(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_chdir")
int handle_sys_enter_chdir(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_chroot")
int handle_sys_enter_chroot(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_adjtime")
int handle_sys_enter_clock_adjtime(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_getres")
int handle_sys_enter_clock_getres(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_gettime")
int handle_sys_enter_clock_gettime(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_nanosleep")
int handle_sys_enter_clock_nanosleep(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_settime")
int handle_sys_enter_clock_settime(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int handle_sys_enter_clone(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 18) {
		next_status = 19;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone3")
int handle_sys_enter_clone3(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int handle_sys_enter_close(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 39) {
		bpf_printk("docker create\n");
		next_status = 0;
	}
	else if (*current_status_p == 26) {
		next_status = 27;
	}
	else if (*current_status_p == 23) {
		bpf_printk("docker run\n");
		next_status = 0;
	}
	else if (*current_status_p == 21) {
		bpf_printk("docker run\n");
		next_status = 0;
	}
	else if (*current_status_p == 9) {
		next_status = 10;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_close_range")
int handle_sys_enter_close_range(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_enter_connect(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_copy_file_range")
int handle_sys_enter_copy_file_range(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int handle_sys_enter_delete_module(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup")
int handle_sys_enter_dup(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int handle_sys_enter_dup3(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_create1")
int handle_sys_enter_epoll_create1(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_ctl")
int handle_sys_enter_epoll_ctl(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 36) {
		next_status = 37;
	}
	else if (*current_status_p == 32) {
		next_status = 33;
	}
	else if (*current_status_p == 13) {
		next_status = 14;
	}
	else if (*current_status_p == 1) {
		next_status = 2;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait2")
int handle_sys_enter_epoll_pwait2(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_eventfd2")
int handle_sys_enter_eventfd2(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_sys_enter_execve(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_sys_enter_execveat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int handle_sys_enter_exit(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int handle_sys_enter_exit_group(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat")
int handle_sys_enter_faccessat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat2")
int handle_sys_enter_faccessat2(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fadvise64_64")
int handle_sys_enter_fadvise64_64(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fallocate")
int handle_sys_enter_fallocate(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_init")
int handle_sys_enter_fanotify_init(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_mark")
int handle_sys_enter_fanotify_mark(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchdir")
int handle_sys_enter_fchdir(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int handle_sys_enter_fchmod(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_sys_enter_fchmodat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 27) {
		next_status = 28;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchown")
int handle_sys_enter_fchown(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int handle_sys_enter_fchownat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int handle_sys_enter_fcntl(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int handle_sys_enter_fdatasync(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fgetxattr")
int handle_sys_enter_fgetxattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int handle_sys_enter_finit_module(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_flistxattr")
int handle_sys_enter_flistxattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_flock")
int handle_sys_enter_flock(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fremovexattr")
int handle_sys_enter_fremovexattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsconfig")
int handle_sys_enter_fsconfig(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsetxattr")
int handle_sys_enter_fsetxattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsmount")
int handle_sys_enter_fsmount(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsopen")
int handle_sys_enter_fsopen(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fspick")
int handle_sys_enter_fspick(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fstatfs")
int handle_sys_enter_fstatfs(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int handle_sys_enter_fsync(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 38) {
		next_status = 39;
	}
	else if (*current_status_p == 25) {
		next_status = 26;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int handle_sys_enter_ftruncate(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_get_mempolicy")
int handle_sys_enter_get_mempolicy(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_get_robust_list")
int handle_sys_enter_get_robust_list(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getcpu")
int handle_sys_enter_getcpu(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getcwd")
int handle_sys_enter_getcwd(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int handle_sys_enter_getdents64(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getegid")
int handle_sys_enter_getegid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_geteuid")
int handle_sys_enter_geteuid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getgid")
int handle_sys_enter_getgid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getgroups")
int handle_sys_enter_getgroups(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getitimer")
int handle_sys_enter_getitimer(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpeername")
int handle_sys_enter_getpeername(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpgid")
int handle_sys_enter_getpgid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int handle_sys_enter_getpid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 19) {
		next_status = 20;
	}
	else if (*current_status_p == 15) {
		next_status = 16;
	}
	else if (*current_status_p == 1) {
		next_status = 3;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getppid")
int handle_sys_enter_getppid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpriority")
int handle_sys_enter_getpriority(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrandom")
int handle_sys_enter_getrandom(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getresgid")
int handle_sys_enter_getresgid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getresuid")
int handle_sys_enter_getresuid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrlimit")
int handle_sys_enter_getrlimit(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrusage")
int handle_sys_enter_getrusage(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsid")
int handle_sys_enter_getsid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockname")
int handle_sys_enter_getsockname(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int handle_sys_enter_getsockopt(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_gettid")
int handle_sys_enter_gettid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 3) {
		next_status = 4;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_gettimeofday")
int handle_sys_enter_gettimeofday(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getuid")
int handle_sys_enter_getuid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getxattr")
int handle_sys_enter_getxattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int handle_sys_enter_init_module(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_add_watch")
int handle_sys_enter_inotify_add_watch(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_init1")
int handle_sys_enter_inotify_init1(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_rm_watch")
int handle_sys_enter_inotify_rm_watch(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_cancel")
int handle_sys_enter_io_cancel(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_destroy")
int handle_sys_enter_io_destroy(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_getevents")
int handle_sys_enter_io_getevents(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_pgetevents")
int handle_sys_enter_io_pgetevents(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_setup")
int handle_sys_enter_io_setup(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_submit")
int handle_sys_enter_io_submit(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_enter")
int handle_sys_enter_io_uring_enter(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_register")
int handle_sys_enter_io_uring_register(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_setup")
int handle_sys_enter_io_uring_setup(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int handle_sys_enter_ioctl(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioprio_get")
int handle_sys_enter_ioprio_get(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioprio_set")
int handle_sys_enter_ioprio_set(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kcmp")
int handle_sys_enter_kcmp(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kexec_file_load")
int handle_sys_enter_kexec_file_load(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kexec_load")
int handle_sys_enter_kexec_load(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_keyctl")
int handle_sys_enter_keyctl(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int handle_sys_enter_kill(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_add_rule")
int handle_sys_enter_landlock_add_rule(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_create_ruleset")
int handle_sys_enter_landlock_create_ruleset(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_restrict_self")
int handle_sys_enter_landlock_restrict_self(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lgetxattr")
int handle_sys_enter_lgetxattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int handle_sys_enter_linkat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int handle_sys_enter_listen(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_listxattr")
int handle_sys_enter_listxattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_llistxattr")
int handle_sys_enter_llistxattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lremovexattr")
int handle_sys_enter_lremovexattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lseek")
int handle_sys_enter_lseek(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_lsetxattr")
int handle_sys_enter_lsetxattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_madvise")
int handle_sys_enter_madvise(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mbind")
int handle_sys_enter_mbind(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_membarrier")
int handle_sys_enter_membarrier(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_sys_enter_memfd_create(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_secret")
int handle_sys_enter_memfd_secret(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_migrate_pages")
int handle_sys_enter_migrate_pages(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mincore")
int handle_sys_enter_mincore(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int handle_sys_enter_mkdirat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknodat")
int handle_sys_enter_mknodat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlock")
int handle_sys_enter_mlock(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlock2")
int handle_sys_enter_mlock2(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlockall")
int handle_sys_enter_mlockall(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int handle_sys_enter_mmap(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int handle_sys_enter_mount(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount_setattr")
int handle_sys_enter_mount_setattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_move_mount")
int handle_sys_enter_move_mount(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_move_pages")
int handle_sys_enter_move_pages(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int handle_sys_enter_mprotect(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_getsetattr")
int handle_sys_enter_mq_getsetattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_notify")
int handle_sys_enter_mq_notify(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_open")
int handle_sys_enter_mq_open(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_timedreceive")
int handle_sys_enter_mq_timedreceive(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_timedsend")
int handle_sys_enter_mq_timedsend(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_unlink")
int handle_sys_enter_mq_unlink(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mremap")
int handle_sys_enter_mremap(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgctl")
int handle_sys_enter_msgctl(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgget")
int handle_sys_enter_msgget(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgrcv")
int handle_sys_enter_msgrcv(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgsnd")
int handle_sys_enter_msgsnd(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_msync")
int handle_sys_enter_msync(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_munlock")
int handle_sys_enter_munlock(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_munlockall")
int handle_sys_enter_munlockall(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int handle_sys_enter_munmap(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_name_to_handle_at")
int handle_sys_enter_name_to_handle_at(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstat")
int handle_sys_enter_newfstat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int handle_sys_enter_newfstatat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 34) {
		next_status = 35;
	}
	else if (*current_status_p == 30) {
		next_status = 31;
	}
	else if (*current_status_p == 28) {
		next_status = 29;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_newuname")
int handle_sys_enter_newuname(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_by_handle_at")
int handle_sys_enter_open_by_handle_at(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_tree")
int handle_sys_enter_open_tree(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 35) {
		next_status = 36;
	}
	else if (*current_status_p == 31) {
		next_status = 32;
	}
	else if (*current_status_p == 12) {
		next_status = 13;
	}
	else if (*current_status_p == 4) {
		next_status = 5;
	}
	else if (*current_status_p == 0) {
		next_status = 1;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int handle_sys_enter_openat2(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_perf_event_open")
int handle_sys_enter_perf_event_open(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_getfd")
int handle_sys_enter_pidfd_getfd(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_open")
int handle_sys_enter_pidfd_open(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_send_signal")
int handle_sys_enter_pidfd_send_signal(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe2")
int handle_sys_enter_pipe2(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 14) {
		next_status = 15;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pivot_root")
int handle_sys_enter_pivot_root(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ppoll")
int handle_sys_enter_ppoll(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int handle_sys_enter_prctl(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pread64")
int handle_sys_enter_pread64(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv")
int handle_sys_enter_preadv(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv2")
int handle_sys_enter_preadv2(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_prlimit64")
int handle_sys_enter_prlimit64(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_madvise")
int handle_sys_enter_process_madvise(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_mrelease")
int handle_sys_enter_process_mrelease(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int handle_sys_enter_process_vm_readv(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int handle_sys_enter_process_vm_writev(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pselect6")
int handle_sys_enter_pselect6(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_sys_enter_ptrace(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int handle_sys_enter_pwrite64(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev")
int handle_sys_enter_pwritev(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev2")
int handle_sys_enter_pwritev2(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_quotactl")
int handle_sys_enter_quotactl(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_quotactl_fd")
int handle_sys_enter_quotactl_fd(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_sys_enter_read(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_readahead")
int handle_sys_enter_readahead(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlinkat")
int handle_sys_enter_readlinkat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int handle_sys_enter_readv(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_reboot")
int handle_sys_enter_reboot(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int handle_sys_enter_recvfrom(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int handle_sys_enter_recvmmsg(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int handle_sys_enter_recvmsg(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_remap_file_pages")
int handle_sys_enter_remap_file_pages(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_removexattr")
int handle_sys_enter_removexattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_sys_enter_renameat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 29) {
		next_status = 30;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_sys_enter_renameat2(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_request_key")
int handle_sys_enter_request_key(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_restart_syscall")
int handle_sys_enter_restart_syscall(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rseq")
int handle_sys_enter_rseq(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigaction")
int handle_sys_enter_rt_sigaction(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigpending")
int handle_sys_enter_rt_sigpending(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigprocmask")
int handle_sys_enter_rt_sigprocmask(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 20) {
		next_status = 23;
	}
	else if (*current_status_p == 19) {
		next_status = 21;
	}
	else if (*current_status_p == 17) {
		next_status = 18;
	}
	else if (*current_status_p == 16) {
		next_status = 17;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigqueueinfo")
int handle_sys_enter_rt_sigqueueinfo(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigsuspend")
int handle_sys_enter_rt_sigsuspend(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigtimedwait")
int handle_sys_enter_rt_sigtimedwait(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_tgsigqueueinfo")
int handle_sys_enter_rt_tgsigqueueinfo(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_get_priority_max")
int handle_sys_enter_sched_get_priority_max(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_get_priority_min")
int handle_sys_enter_sched_get_priority_min(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getaffinity")
int handle_sys_enter_sched_getaffinity(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getattr")
int handle_sys_enter_sched_getattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getparam")
int handle_sys_enter_sched_getparam(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getscheduler")
int handle_sys_enter_sched_getscheduler(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_rr_get_interval")
int handle_sys_enter_sched_rr_get_interval(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setaffinity")
int handle_sys_enter_sched_setaffinity(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setattr")
int handle_sys_enter_sched_setattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setparam")
int handle_sys_enter_sched_setparam(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setscheduler")
int handle_sys_enter_sched_setscheduler(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_seccomp")
int handle_sys_enter_seccomp(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_semctl")
int handle_sys_enter_semctl(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_semget")
int handle_sys_enter_semget(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_semop")
int handle_sys_enter_semop(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_semtimedop")
int handle_sys_enter_semtimedop(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendfile64")
int handle_sys_enter_sendfile64(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int handle_sys_enter_sendmmsg(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int handle_sys_enter_sendmsg(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_sys_enter_sendto(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_mempolicy")
int handle_sys_enter_set_mempolicy(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_robust_list")
int handle_sys_enter_set_robust_list(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_tid_address")
int handle_sys_enter_set_tid_address(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setdomainname")
int handle_sys_enter_setdomainname(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setfsgid")
int handle_sys_enter_setfsgid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setfsuid")
int handle_sys_enter_setfsuid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int handle_sys_enter_setgid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgroups")
int handle_sys_enter_setgroups(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sethostname")
int handle_sys_enter_sethostname(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setitimer")
int handle_sys_enter_setitimer(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int handle_sys_enter_setns(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 8) {
		next_status = 9;
	}
	else if (*current_status_p == 5) {
		next_status = 6;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setpgid")
int handle_sys_enter_setpgid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setpriority")
int handle_sys_enter_setpriority(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int handle_sys_enter_setregid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int handle_sys_enter_setresgid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int handle_sys_enter_setresuid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int handle_sys_enter_setreuid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setrlimit")
int handle_sys_enter_setrlimit(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsid")
int handle_sys_enter_setsid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int handle_sys_enter_setsockopt(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 11) {
		next_status = 12;
	}
	else if (*current_status_p == 10) {
		next_status = 11;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_settimeofday")
int handle_sys_enter_settimeofday(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_sys_enter_setuid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setxattr")
int handle_sys_enter_setxattr(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmat")
int handle_sys_enter_shmat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmctl")
int handle_sys_enter_shmctl(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmdt")
int handle_sys_enter_shmdt(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmget")
int handle_sys_enter_shmget(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int handle_sys_enter_shutdown(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sigaltstack")
int handle_sys_enter_sigaltstack(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_signalfd4")
int handle_sys_enter_signalfd4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int handle_sys_enter_socket(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 6) {
		next_status = 7;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_socketpair")
int handle_sys_enter_socketpair(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_splice")
int handle_sys_enter_splice(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_statfs")
int handle_sys_enter_statfs(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_statx")
int handle_sys_enter_statx(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_swapoff")
int handle_sys_enter_swapoff(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_swapon")
int handle_sys_enter_swapon(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int handle_sys_enter_symlinkat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync")
int handle_sys_enter_sync(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync_file_range")
int handle_sys_enter_sync_file_range(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_syncfs")
int handle_sys_enter_syncfs(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sysinfo")
int handle_sys_enter_sysinfo(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_syslog")
int handle_sys_enter_syslog(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_tee")
int handle_sys_enter_tee(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_create")
int handle_sys_enter_timer_create(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_delete")
int handle_sys_enter_timer_delete(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_getoverrun")
int handle_sys_enter_timer_getoverrun(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_gettime")
int handle_sys_enter_timer_gettime(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_settime")
int handle_sys_enter_timer_settime(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_create")
int handle_sys_enter_timerfd_create(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_gettime")
int handle_sys_enter_timerfd_gettime(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_settime")
int handle_sys_enter_timerfd_settime(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_times")
int handle_sys_enter_times(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int handle_sys_enter_tkill(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int handle_sys_enter_truncate(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_umask")
int handle_sys_enter_umask(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_umount")
int handle_sys_enter_umount(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_sys_enter_unlinkat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int handle_sys_enter_unshare(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_userfaultfd")
int handle_sys_enter_userfaultfd(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_utimensat")
int handle_sys_enter_utimensat(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_vhangup")
int handle_sys_enter_vhangup(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_vmsplice")
int handle_sys_enter_vmsplice(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_wait4")
int handle_sys_enter_wait4(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_waitid")
int handle_sys_enter_waitid(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_sys_enter_write(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else if (*current_status_p == 37) {
		next_status = 38;
	}
	else if (*current_status_p == 33) {
		next_status = 34;
	}
	else if (*current_status_p == 2) {
		next_status = 25;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int handle_sys_enter_writev(void *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t *current_status_p = bpf_map_lookup_elem(&status, &pid);
	size_t next_status;
	if (!current_status_p) {
		next_status = 0;
	}
	else next_status = 0;
	bpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);
	return 0;
}






































































































































































































































































































