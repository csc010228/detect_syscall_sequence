/*
 *
 *  translator.h
 *  把系统调用序列检测脚本翻译成bpftrace脚本
 *  Creator:Sichao Chen
 *  Create time:2022/3/4
 *
*/
#ifndef __TRANSLATOR_H
#define __TRANSLATOR_H

#include <iostream>
#include <map>
#include <string>
#include <set>
#include <list>
#include "automata.h"
#include "nfa.h"
#include "util.h"

using namespace std;

bool string_start_with(string str1, string str2);

//最终的输出文件类型
enum output_file_type {
    BPFTRACE,
    LIBBPF
};

//一个系统调用的检测节点
struct syscall_detection_point {
    syscall_detection_point() {
        name.clear();
        probe_name.clear();
        condition.clear();
        action.clear();
        father = nullptr;
    };

    syscall_detection_point(string name, string probe_name) : name(name), probe_name(probe_name) {
        condition.clear();
        action.clear();
        father = nullptr;
    };

    syscall_detection_point(string name, string probe_name, struct syscall_detection_point * father) : name(name), probe_name(probe_name), father(father) {
        condition.clear();
        action.clear();
    };

    string name;                //该检测节点的名字
    string probe_name;                   //探针名字
    string condition;        //过滤条件
    list<string> action;                  //动作
    struct syscall_detection_point * father;
};

//检测时的状态转移
struct state_transition {
    state_transition(state_index from_state, struct syscall_detection_point * transition, state_index to_state) : from_state(from_state), to_state(to_state), transition(transition) {

    };

    state_index from_state, to_state;
    struct syscall_detection_point * transition;
};

//系统调用检测的原子单位
enum syscall_detection_atom {
    THREAD,
    PROCESS
};

//系统调用探针的类型
enum syscall_probe_type {
    ENTER,
    EXIT
};

//一个系统调用探针
struct syscall_probe {
    syscall_probe(string probe_name) : probe_name(probe_name) {
        if (string_start_with(probe_name, "tracepoint:syscalls:sys_enter_")) type = syscall_probe_type::ENTER;
        else if (string_start_with(probe_name, "tracepoint:syscalls:sys_exit_")) type = syscall_probe_type::EXIT;
    };

    void add_transition(state_index from_state, struct syscall_detection_point * transition, state_index to_state, string stop_action, bool push_to_back) {
        if (push_to_back) transitions_and_stop_actions.push_back(make_pair(state_transition(from_state,transition, to_state), stop_action));
        else transitions_and_stop_actions.push_front(make_pair(state_transition(from_state, transition,to_state), stop_action));
    }

    void add_transition(state_index from_state, struct syscall_detection_point * transition, state_index to_state, bool push_to_back) {
        add_transition(from_state, transition, to_state, "", push_to_back);
    }

    string to_string(enum syscall_detection_atom detection_atom, enum output_file_type oft) {
        string res;
        switch (oft) {
        case output_file_type::BPFTRACE:
            res = to_string_bpftrace(detection_atom);
            break;
        case output_file_type::LIBBPF:
            res = to_string_libbpf(detection_atom);
            break;
        default:
            break;
        }
        return res;
    }

    string to_string_bpftrace(enum syscall_detection_atom detection_atom) {
        string res, action, atom, to_state_str;
        bool first_tag = true;
        size_t index = 0;

        if (type == syscall_probe_type::EXIT && transitions_and_stop_actions.size() == 0) return "";

        res = (probe_name + "\n{\n");

        switch(detection_atom) {
        case syscall_detection_atom::PROCESS:
            atom = "@states[pid]";
            break;
        case syscall_detection_atom::THREAD:
            atom = "@states[pid,tid]";
            break;
        default:
            break;
        }

        for(auto i : transitions_and_stop_actions) {
            if (first_tag) {
                first_tag = false;
                res += "\t";
            } else res += "\telse ";
            action.clear();
            for (auto j : i.first.transition->action) action += j;
            res += ("if(" + atom + "==" + std::to_string(i.first.from_state));
            if (i.first.transition->condition.size() > 0) res += (" && (" + i.first.transition->condition + ")");
            res += (")\n\t{\n");
            if (action.size() > 0) res+=("\t\t"+action+"\n");
            if (i.second.size()>0) {
                res += ("\t\t"+i.second+"\n");
                to_state_str = "0";
            } else to_state_str = std::to_string(i.first.to_state);
            res += ("\t\t" + atom + "=" + to_state_str + ";\n");
            res += "\t}\n";
        }
        if (!first_tag) res += "\telse\n\t{\n\t\t" + atom + "=0;\n\t}\n";
        else res += "\t" + atom + "=0;\n";

        res += "}\n";
        return res;
    };

    string to_string_libbpf(enum syscall_detection_atom detection_atom) {
        string res, action, atom, to_state_str;
        bool first_tag = true;
        size_t index = 0;

        if (type == syscall_probe_type::EXIT && transitions_and_stop_actions.size() == 0) return "";

        res = "SEC(\"" + replace_char(probe_name, ':', '/') + "\")\n";
        res += "int handle_accept4(void *ctx)\n{\n";

        res += "\tpid_t pid = bpf_get_current_pid_tgid() >> 32;\n";
        res += "\tsize_t *current_status_p = bpf_map_lookup_elem(&status, &pid);\n";
        res += "\tsize_t next_status;\n";

        // switch(detection_atom) {
        // case syscall_detection_atom::PROCESS:
        //     atom = "@states[pid]";
        //     break;
        // case syscall_detection_atom::THREAD:
        //     atom = "@states[pid,tid]";
        //     break;
        // default:
        //     break;
        // }

        for(auto i : transitions_and_stop_actions) {
            if (first_tag) {
                first_tag = false;
                res += "\t";
            } else res += "\telse ";
            action.clear();
            for (auto j : i.first.transition->action) action += j;
            res += ("if (*current_status_p == " + std::to_string(i.first.from_state));
            if (i.first.transition->condition.size() > 0) res += (" && (" + i.first.transition->condition + ")");
            res += (") {\n");
            if (action.size() > 0) res+=("\t\t"+action+"\n");
            if (i.second.size()>0) {
                res += ("\t\t"+i.second+"\n");
                to_state_str = "0";
            } else to_state_str = std::to_string(i.first.to_state);
            res += ("\t\tnext_status = " + to_state_str + ";\n\t}\n");
        }
        if (!first_tag) res += "\telse next_status = 0;\n";
        else res += "\tnext_status = 0;\n";

        res += "\tbpf_map_update_elem(&status, &pid, &next_status, BPF_ANY);\n\treturn 0;\n}\n";
        return res;
    };

    string probe_name;
    enum syscall_probe_type type;
    list<pair<struct state_transition, string> > transitions_and_stop_actions;
};

//解析系统调用序列检测文件的步骤
enum class source_file_parse_step {
    NONE,
    DEFINE_POINT,
    DEFINE_SEQUENCE,
    DEFINE_DO_IN_POINT,
    DEFINE_DO_IN_SEQUENCE,
    DEFINE_INCLUDES,
    DEFINE_BEGIN_PROBE,
    DEFINE_END_PROBE
};

//把系统调用检测语言转换成bpftrace的翻译器
class Translator {
private:
    //单例类对象
    static Translator * instance_;

    //构造函数
    Translator();

    //析构函数
    ~Translator();

    //系统调用检测的原子单位
    enum syscall_detection_atom detection_atom_;
    
    //要包含的头文件
    list<string> include_filenames_;

    //BEGIN探针的内容
    list<string> BEGIN_probe_data_;

    //END探针的内容
    list<string> END_probe_data_;

    //所有的系统调用的probe
    map<string, struct syscall_probe> syscall_probes_;

    //符号表
    map<string, struct syscall_detection_point * > syscall_detection_points_;

    //输入系统调用序列检测的脚本语言文件
    bool input_source_file(string source_filename, enum output_file_type oft);

    //输出翻译过后的bpftrace脚本语言文件或者libbpf文件
    bool output_bpftrace_file(string output_filename, enum output_file_type oft);

public:
    //单例模式不应该有克隆构造函数
    Translator(Translator & other) = delete;
    
    //单例模式不应该重载赋值运算符
    void operator=(const Translator &) = delete;

    //获取单例对象的方法
    static Translator * get_instance();

    //销毁单例类
    static void delete_instance();

    //最终得到的NFA
    NFA<string,string> * final_NFA_;

    //序列完成之后的动作
    list<string> sequence_actions_;

    //将系统调用序列检测的脚本语言转换成bpftrace脚本语言
    bool translate(string source_filename, string output_filename, enum output_file_type oft);
};

#endif //__TRANSLATOR_H
