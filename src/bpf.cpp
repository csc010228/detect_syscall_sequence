/*
 *
 *  bpf.cpp
 *  bpftrace有关
 *  Creator:Sichao Chen
 *  Create time:2022/3/4
 *
*/

#include "bpf.h"
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <iostream>

using namespace std;

#define SYSCALL_RPOBES_DIR_NAME "/sys/kernel/tracing/events/syscalls/"
#define SYS_ENTER_PREFIX "sys_enter_"
#define SYS_ENTER_PREFIX_LENGTH 10
#define SYS_EXIT_PREFIX "sys_exit_"
#define SYS_EXIT_PREFIX_LENGTH 9
#define TRACEPOINT_SYSCALLS_PREFIX "tracepoint:syscalls:"

set<string> get_all_tracepoint_syscalls_sys_enter()
{
    set<string> res;
    struct dirent * entry;
    DIR * dir;
    string filename,line;
    if((dir=opendir(SYSCALL_RPOBES_DIR_NAME))!=NULL)
    {
        while((entry=readdir(dir))!=NULL)
        {
            filename=string(entry->d_name);
            if(filename.compare(0,SYS_ENTER_PREFIX_LENGTH,SYS_ENTER_PREFIX)==0)
            {
                res.insert(TRACEPOINT_SYSCALLS_PREFIX+filename);
            }
        }
        closedir(dir);
    }
    else
    {
        cout<<"Can not open dir \"/sys/kernel/tracing/events/syscalls/\",please run this programe in root!"<<endl;
        cout<<"Or maybe your Linux do not allow debug!"<<endl;
    }
    return res;
}

set<string> get_all_tracepoint_syscalls_sys_exit()
{
    set<string> res;
    struct dirent * entry;
    DIR * dir;
    string filename,line;
    if((dir=opendir(SYSCALL_RPOBES_DIR_NAME))!=NULL)
    {
        while((entry=readdir(dir))!=NULL)
        {
            filename=string(entry->d_name);
            if(filename.compare(0,SYS_EXIT_PREFIX_LENGTH,SYS_EXIT_PREFIX)==0)
            {
                res.insert(TRACEPOINT_SYSCALLS_PREFIX+filename);
            }
        }
        closedir(dir);
    }
    else
    {
        cout<<"Can not open dir \"/sys/kernel/tracing/events/syscalls/\",please run this programe in root!"<<endl;
        cout<<"Or maybe your Linux do not allow debug!"<<endl;
    }
    return res;
}
