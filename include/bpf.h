/*
 *
 *  bpf.h
 *  bpftrace有关
 *  Creator:Sichao Chen
 *  Create time:2022/3/4
 *
*/
#ifndef __BPF_H
#define __BPF_H

#include <set>
#include <string>

using namespace std;

//获取所有tracepoint:syscalls:sys_enter_*的名字
set<string> get_all_tracepoint_syscalls_sys_enter(bool print_error);

//获取所有tracepoint:syscalls:sys_exit_*的名字
set<string> get_all_tracepoint_syscalls_sys_exit(bool print_error);

#endif //__BPF_H
