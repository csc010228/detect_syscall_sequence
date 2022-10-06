/*
 *
 *  translator.cpp
 *  把系统调用序列检测脚本翻译成bpftrace脚本
 *  Creator:Sichao Chen
 *  Create time:2022/3/4
 *
*/

#include "translator.h"
#include "bpf.h"
#include "y.tab.h"
#include <iostream>
#include <fstream>

#define is_digit(ch) ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))
#define is_number(ch) (ch >= '0' && ch <= '9')
#define print_error(error_info) cout << "Error:line " << line_num << " error:" << (error_info) << endl;goto out

#define DEF_TRACEPOINT_SYSCALLS_SYS_PREFIX "#tracepoint:syscalls:"
#define TRACEPOINT_SYSCALLS_PREFIX "tracepoint:syscalls:"
#define TRACEPOINT_SYSCALLS_SYS_ENTER_PREFIX "tracepoint:syscalls:sys_enter_"
#define TRACEPOINT_SYSCALLS_SYS_EXIT_PREFIX "tracepoint:syscalls:sys_exit_"

#define TMP_FILE_NAME "sequences.txt"

#define BPFTRACE_FILE_SUFFIX ".bt"
#define LIBBPF_BPF_FILE_SUFFIX ".bpf.c"
#define LIBBPF_C_FILE_SUFFIX ".c"

extern int parse(const char * filename);

//查看某一个字符串是否是合理的变量名
bool is_legal_var_name(string str) {
    bool first_char = true;
    if (str.size() > 0) {
        for (auto i : str) {
            if (first_char) {
                first_char = false;
                if (!(is_digit(i) || i == '_')) return false;
            } else if (!(is_digit(i) || is_number(i) || i == '_')) return false;
        }
        return true;
    }
    return false;
}

Translator * Translator::instance_=nullptr;

Translator::Translator() {
    detection_atom_ = syscall_detection_atom::THREAD;
    //获取所有的tracepoint:syscalls:sys_enter_*探针并进行初始化
    set<string> all_sys_enter_probes = get_all_tracepoint_syscalls_sys_enter(true);
    for (auto i : all_sys_enter_probes) syscall_probes_.insert(make_pair(i, syscall_probe(i)));
    //获取所有的tracepoint:syscalls:sys_exit_*探针并进行初始化
    set<string> all_sys_exit_probes = get_all_tracepoint_syscalls_sys_exit(false);
    for (auto i : all_sys_exit_probes) syscall_probes_.insert(make_pair(i, syscall_probe(i)));
}

Translator::~Translator() {
    for (auto i : syscall_detection_points_) delete i.second;
}

Translator * Translator::get_instance()
{
    if (instance_ == nullptr) instance_ = new Translator();
    return instance_;
}

void Translator::delete_instance() {
    if (instance_ != nullptr) {
        delete instance_;
        instance_ = nullptr;
    }
}

bool Translator::translate(string source_filename, string output_filename, enum output_file_type oft) {
    return (input_source_file(source_filename, oft) && output_bpftrace_file(output_filename, oft));
}

bool Translator::input_source_file(string source_filename, enum output_file_type oft) {
    ifstream in(source_filename);
    ofstream out;
    string line, current_detection_point_name, sequence_action, tmp;
    enum source_file_parse_step step = source_file_parse_step::NONE;
    struct syscall_detection_point * current_detection_point;
    bool res = false;
    size_t line_num = 0,blank_pos;
    if (!in.is_open()) {
        cout << "Source file " + source_filename + " opening failed!" << endl;
        return res;
    }
    out.open(TMP_FILE_NAME, ios::out);
    while (getline(in,line)) {
        line_num ++;
        trim(line);
        if (line.size() == 0) {
            out << endl;
            continue;
        }
        switch (step) {
        case source_file_parse_step::NONE:
            blank_pos = line.find(" ");
            if (string_start_with(line, DEF_TRACEPOINT_SYSCALLS_SYS_PREFIX) && blank_pos != string::npos) {
                current_detection_point = new struct syscall_detection_point(line.substr(blank_pos), line.substr(1, blank_pos - 1));
                trim(current_detection_point->name);
                trim(current_detection_point->probe_name);
                syscall_detection_points_.insert(make_pair(current_detection_point->name,current_detection_point));
                if (syscall_probes_.find(current_detection_point->probe_name) == syscall_probes_.end()) {
                    print_error("Can not find syscall tracepoint " + current_detection_point->probe_name + "!");
                }
                if (!is_legal_var_name(current_detection_point->name)) {
                    print_error("Illegal point name " + current_detection_point->name + "!");
                }
                step = source_file_parse_step::DEFINE_POINT;
            } else if (line == "#sequence") {
                step = source_file_parse_step::DEFINE_SEQUENCE;
            } else if (line == "#includes") {
                step = source_file_parse_step::DEFINE_INCLUDES;
            } else if (line == "#BEGIN_probe") {
                step = source_file_parse_step::DEFINE_BEGIN_PROBE;
            } else if (line == "#END_probe") {
                step = source_file_parse_step::DEFINE_END_PROBE;
            } else if (string_start_with(line,"#atom ")) {
                line.erase(0, string("#atom ").size());
                trim(line);
                if (line == "process") {
                    detection_atom_ = syscall_detection_atom::PROCESS;
                } else if (line == "thread") {
                    detection_atom_ = syscall_detection_atom::THREAD;
                } else {
                    print_error("Value after \"#atom\" can only be \"process\" or \"thread\"!");
                }
            } else if (string_start_with(line, "#ignore ")) {
                line.erase(0, string("#ignore ").size());
                trim(line);
                while (line.size() != 0) {
                    if (line.find(",") != string::npos) {
                        tmp = line.substr(0, line.find(","));
                        line.erase(0, line.find(",") + 1);
                    } else {
                        tmp = line;
                        line = "";
                    }
                    trim(tmp);
                    trim(line);
                    if (string_start_with(tmp, "sys_")) {
                        tmp.erase(0, string("sys_").size());
                        if (syscall_probes_.find(TRACEPOINT_SYSCALLS_SYS_ENTER_PREFIX + tmp) != syscall_probes_.end()) {
                            syscall_probes_.erase(TRACEPOINT_SYSCALLS_SYS_ENTER_PREFIX + tmp);
                        } else {
                            print_error("Can not find probe \"tracepoint:syscalls:sys_enter_" + tmp + "\"!");
                        }
                        if (syscall_probes_.find(TRACEPOINT_SYSCALLS_SYS_EXIT_PREFIX + tmp) != syscall_probes_.end()) {
                            syscall_probes_.erase(TRACEPOINT_SYSCALLS_SYS_EXIT_PREFIX + tmp);
                        } else {
                            print_error("Can not find probe \"tracepoint:syscalls:sys_exit_" + tmp + "\"!");
                        }
                    } else {
                        print_error("Ignored syscalls tracepoint must start with \"sys_\"!");
                    }
                }
            } else {
                print_error("Can not parse line \"" + line + "\"!");
            }
            out << endl;
            break;
        case source_file_parse_step::DEFINE_POINT:
            if (line == "#end") {
                step = source_file_parse_step::NONE;
            } else if (string_start_with(line, "#cond ")) {
                line = line.substr(string("#cond ").size());
                trim(line);
                current_detection_point->condition = line;
            } else if(line == "#do") {
                step = source_file_parse_step::DEFINE_DO_IN_POINT;
            } else {
                print_error("Can not parse line \"" + line + "\"!");
            }
            out << endl;
            break;
        case source_file_parse_step::DEFINE_DO_IN_POINT:
            if (line == "#end") {
                step = source_file_parse_step::NONE;
            } else {
                current_detection_point->action.push_back(line);
            }
            out << endl;
            break;
        case source_file_parse_step::DEFINE_SEQUENCE:
            if (line == "#end") {
                step = source_file_parse_step::NONE;
                out << endl;
            } else if(line == "#do") {
                step=source_file_parse_step::DEFINE_DO_IN_SEQUENCE;
                out << endl;
            } else {
                out << line << endl;
            }
            break;
        case source_file_parse_step::DEFINE_DO_IN_SEQUENCE:
            if (line == "#end") {
                sequence_actions_.push_back(sequence_action);
                sequence_action.clear();
                step = source_file_parse_step::NONE;
            } else {
                sequence_action += line;
            }
            out<<endl;
            break;
        case source_file_parse_step::DEFINE_INCLUDES:
            if (line == "#end") {
                step=source_file_parse_step::NONE;
            } else {
                include_filenames_.push_back(line);
            }
            out << endl;
            break;
        case source_file_parse_step::DEFINE_BEGIN_PROBE:
            if (line == "#end") {
                step = source_file_parse_step::NONE;
            } else {
                BEGIN_probe_data_.push_back(line);
            }
            out << endl;
            break;
        case source_file_parse_step::DEFINE_END_PROBE:
            if (line == "#end") {
                step = source_file_parse_step::NONE;
            } else {
                END_probe_data_.push_back(line);
            }
            out << endl;
            break;
        default:
            break;
        }
    }
    res = true;
out:
    in.close();
    out.close();
    return res;
}

bool Translator::output_bpftrace_file(string output_filename, enum output_file_type oft) {
    ofstream out, out_auxiliary;
    struct syscall_detection_point * current_syscall_detection_point;
    DFA<string,string> final_DFA;
    string stop_action;
    bool tag = false;

    parse(TMP_FILE_NAME);
    final_DFA = final_NFA_->to_DFA();

    map<state_index, map<string, state_index> > dfa_state_transition_table = final_DFA.get_state_transition_table();
    for(auto i : dfa_state_transition_table) {
        for(auto j : i.second) {
            tag = false;
            if (syscall_detection_points_.find(j.first) != syscall_detection_points_.end()) current_syscall_detection_point = syscall_detection_points_.at(j.first);
            else if (syscall_probes_.find(TRACEPOINT_SYSCALLS_PREFIX + j.first) != syscall_probes_.end()) {
                current_syscall_detection_point = new struct syscall_detection_point(j.first, TRACEPOINT_SYSCALLS_PREFIX + j.first);
                syscall_detection_points_.insert(make_pair(j.first, current_syscall_detection_point));
                tag = true;
            } else return false;

            if (final_DFA.is_stop_state(j.second)) {
                for(auto i:final_DFA.get_state_data(j.second)) stop_action+=i;
                syscall_probes_.at(current_syscall_detection_point->probe_name).add_transition(i.first,current_syscall_detection_point,j.second,stop_action,tag);
                stop_action.clear();
            } else syscall_probes_.at(current_syscall_detection_point->probe_name).add_transition(i.first,current_syscall_detection_point,j.second,tag);
        }
    }

    switch (oft) {
    case output_file_type::BPFTRACE:
        out.open(output_filename + BPFTRACE_FILE_SUFFIX, ios::out);
        break;
    case output_file_type::LIBBPF:
        out_auxiliary.open(output_filename + LIBBPF_C_FILE_SUFFIX, ios::out);
        out_auxiliary << "// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause" <<endl;
        out_auxiliary << "/* Copyright (c) 2020 Facebook */" << endl;
        out_auxiliary << "#include <stdio.h>" << endl;
        out_auxiliary << "#include <unistd.h>" << endl;
        out_auxiliary << "#include <sys/resource.h>" << endl;
        out_auxiliary << "#include <bpf/libbpf.h>" << endl;
        out_auxiliary << "#include <signal.h>" <<endl;
        out_auxiliary << "#include \"" << output_filename << ".skel.h\"\n" <<endl;
        out_auxiliary << "static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)" <<endl;
        out_auxiliary << "{" <<endl;
        out_auxiliary << "\treturn vfprintf(stderr, format, args);" <<endl;
        out_auxiliary << "}\n" <<endl;
        out_auxiliary << "static struct " << output_filename << "_bpf *skel;\n" <<endl;
        out_auxiliary << "static int handle_event(void *ctx, void *data, size_t data_sz)" <<endl;
        out_auxiliary << "{" <<endl;
        out_auxiliary << "\t// TO-DO" <<endl;
        out_auxiliary << "\treturn 0;" <<endl;
        out_auxiliary << "}\n" <<endl;
        out_auxiliary << "static volatile bool exiting = false;\n" <<endl;
        out_auxiliary << "static void sig_handler(int sig)" <<endl;
        out_auxiliary << "{" <<endl;
        out_auxiliary << "\texiting = true;" <<endl;
        out_auxiliary << "}\n" <<endl;
        out_auxiliary << "int main(int argc, char **argv)" <<endl;
        out_auxiliary << "{" <<endl;
        out_auxiliary << "\tstruct ring_buffer *rb = NULL;" <<endl;
        out_auxiliary << "\tint err;\n" <<endl;
        out_auxiliary << "\tlibbpf_set_strict_mode(LIBBPF_STRICT_ALL);" <<endl;
        out_auxiliary << "\t/* Set up libbpf errors and debug info callback */" <<endl;
        out_auxiliary << "\tlibbpf_set_print(libbpf_print_fn);\n" <<endl;
        out_auxiliary << "\t/* Open BPF application */" <<endl;
        out_auxiliary << "\tskel = " << output_filename << "_bpf__open();" <<endl;
        out_auxiliary << "\tif (!skel) {" <<endl;
        out_auxiliary << "\t\tfprintf(stderr, \"Failed to open BPF skeleton\\n\");" <<endl;
        out_auxiliary << "\t\treturn 1;" <<endl;
        out_auxiliary << "\t}\n" <<endl;
        out_auxiliary << "\t/* Cleaner handling of Ctrl-C */" <<endl;
        out_auxiliary << "\tsignal(SIGINT, sig_handler);" <<endl;
        out_auxiliary << "\tsignal(SIGTERM, sig_handler);\n" <<endl;
        out_auxiliary << "\t/* Load & verify BPF programs */" <<endl;
        out_auxiliary << "\terr = " << output_filename << "_bpf__load(skel);" <<endl;
        out_auxiliary << "\tif (err) {" <<endl;
        out_auxiliary << "\t\tfprintf(stderr, \"Failed to load and verify BPF skeleton\\n\");" <<endl;
        out_auxiliary << "\t\tgoto cleanup;" <<endl;
        out_auxiliary << "\t}\n" <<endl;
        out_auxiliary << "\t/* Set up ring buffer polling */" <<endl;
        out_auxiliary << "\trb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);" <<endl;
        out_auxiliary << "\tif (!rb) {" <<endl;
        out_auxiliary << "\t\terr = -1;" <<endl;
        out_auxiliary << "\t\tfprintf(stderr, \"Failed to create ring buffer\\n\");" <<endl;
        out_auxiliary << "\t\tgoto cleanup;" <<endl;
        out_auxiliary << "\t}\n" <<endl;
        out_auxiliary << "\t/* Attach tracepoint handler */" <<endl;
        out_auxiliary << "\terr = " << output_filename << "_bpf__attach(skel);" <<endl;
        out_auxiliary << "\tif (err) {" <<endl;
        out_auxiliary << "\t\tfprintf(stderr, \"Failed to attach BPF skeleton\\n\");" <<endl;
        out_auxiliary << "\t\tgoto cleanup;" <<endl;
        out_auxiliary << "\t}\n" <<endl;
        out_auxiliary << "\tprintf(\"Press Ctrl-C to stop.\\n\");\n" <<endl;
        out_auxiliary << "\t/* Process events */" <<endl;
        out_auxiliary << "\twhile (!exiting) {" <<endl;
        out_auxiliary << "\t\terr = ring_buffer__poll(rb, 100 /* timeout, ms */);" <<endl;
        out_auxiliary << "\t\t/* Ctrl-C will cause -EINTR */" <<endl;
        out_auxiliary << "\t\tif (err == -EINTR) {" <<endl;
        out_auxiliary << "\t\t\terr = 0;" <<endl;
        out_auxiliary << "\t\t\tbreak;" <<endl;
        out_auxiliary << "\t\t}" <<endl;
        out_auxiliary << "\t\tif (err < 0) {" <<endl;
        out_auxiliary << "\t\t\tfprintf(stderr, \"Error polling perf buffer: %d\\n\", err);" <<endl;
        out_auxiliary << "\t\t\tbreak;" <<endl;
        out_auxiliary << "\t\t}" <<endl;
        out_auxiliary << "\t\tsleep(1);" <<endl;
        out_auxiliary << "\t}\n" <<endl;
        out_auxiliary << "cleanup:" <<endl;
        out_auxiliary << "\tring_buffer__free(rb);" <<endl;
        out_auxiliary << "\t" << output_filename << "_bpf__destroy(skel);" <<endl;
        out_auxiliary << "\treturn -err;" <<endl;
        out_auxiliary << "}\n" <<endl;
        out_auxiliary.close();
        
        out.open(output_filename + LIBBPF_BPF_FILE_SUFFIX, ios::out);
        out << "// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause" <<endl;
        out << "/* Copyright (c) 2020 Facebook */" << endl;
        out << "#include <linux/bpf.h>" << endl;
        out << "#include <bpf/bpf_helpers.h>" << endl;
        out << "#include <sys/types.h>\n" << endl;
        out << "char LICENSE[] SEC(\"license\") = \"Dual BSD/GPL\";\n" << endl;
        out << "struct {" <<endl;
        out << "\t__uint(type, BPF_MAP_TYPE_HASH);" <<endl;
        out << "\t__type(key, pid_t);" <<endl;
        out << "\t__type(value, size_t);" <<endl;
        out << "\t__uint(max_entries, 1024 * 16);" <<endl;
        out << "} status SEC(\".maps\");\n" <<endl;
        break;
    default:
        break;
    }

    //先把要include的文件输出
    for (auto i : include_filenames_) out << ("#include" + i) << endl;
    //再输出BEGIN探针里面的内容
    if (BEGIN_probe_data_.size() > 0) {
        out << "BEGIN\n{" << endl;
        for (auto i : BEGIN_probe_data_) out << "\t" << i << endl;
        out << "}\n" << endl;
    }
    //再输出各个系统调用探针的内容
    for (auto i : syscall_probes_) out << (i.second).to_string(detection_atom_, oft) << endl;
    //最后输出END探针里面的内容
    if (END_probe_data_.size() > 0) {
        out << "END\n{" << endl;
        for (auto i : END_probe_data_) out << "\t" << i << endl;
        out << "}\n" << endl;
    }
    out.close();
    return true;
}
