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

#define is_digit(ch) ((ch>='A' && ch<='Z') || (ch>='a' && ch<='z'))
#define is_number(ch) (ch>='0' && ch<='9')

#define TMP_FILE_NAME "sequences.txt"

extern int parse(const char * filename);

//查看某一个字符串是否是合理的变量名
bool is_legal_var_name(string str)
{
    bool first_char=true;
    if(str.size()>0)
    {
        for(auto i:str)
        {
            if(first_char)
            {
                first_char=false;
                if(!(is_digit(i) || i=='_'))
                {
                    return false;
                }
                continue;
            }
            if(!(is_digit(i) || is_number(i) || i=='_'))
            {
                return false;
            }
        }
        return true;
    }
    return false;
}

//判断str1是否以str2开头
bool string_start_with(string str1,string str2)
{
    if(str1.size()>=str2.size())
    {
        for(size_t i=0;i<str2.size();i++)
        {
            if(str1[i]!=str2[i])
            {
                return false;
            }
        }
    }
    else
    {
        return false;
    }
    return true;
}

//去除字符串左右两边的空格
void trim(string & str)
{
    string blanks("\f\v\r\t\n ");
    str.erase(0,str.find_first_not_of(blanks));
    str.erase(str.find_last_not_of(blanks) + 1);
}

Translator * Translator::instance_=nullptr;

Translator::Translator()
{
    detection_atom_=syscall_detection_atom::THREAD;
    //获取所有的tracepoint:syscalls:sys_enter_*探针并进行初始化
    set<string> all_sys_enter_probes=get_all_tracepoint_syscalls_sys_enter(true);
    for(auto i:all_sys_enter_probes)
    {
        syscall_probes_.insert(make_pair(i,syscall_probe(i)));
    }
    //获取所有的tracepoint:syscalls:sys_exit_*探针并进行初始化
    set<string> all_sys_exit_probes=get_all_tracepoint_syscalls_sys_exit(false);
    for(auto i:all_sys_exit_probes)
    {
        syscall_probes_.insert(make_pair(i,syscall_probe(i)));
    }
}

Translator::~Translator()
{
    for(auto i:syscall_detection_points_)
    {
        delete i.second;
    };
}

Translator * Translator::get_instance()
{
    if(instance_==nullptr)
    {
        instance_=new Translator();
    }
    return instance_;
}

void Translator::delete_instance()
{
    if(instance_!=nullptr)
    {
        delete instance_;
        instance_=nullptr;
    }
}

bool Translator::translate(string source_filename,string bpftrace_filename)
{
    return (input_source_file(source_filename) && output_bpftrace_file(bpftrace_filename));
}

#define print_error(error_info) cout<<"Error:line "<<line_num<<" error:"<<(error_info)<<endl;goto out

bool Translator::input_source_file(string source_filename)
{
    ifstream in(source_filename);
    ofstream out;
    string line,current_detection_point_name,sequence_action,tmp;
    enum source_file_parse_step step=source_file_parse_step::NONE;
    struct syscall_detection_point * current_detection_point;
    bool res=false;
    size_t line_num=0,blank_pos;
    if(!in.is_open())
    {
        cout<<"Source file "+source_filename+" opening failed!"<<endl;
        return res;
    }
    out.open(TMP_FILE_NAME,ios::out);
    while(getline(in,line))
    {
        line_num++;
        trim(line);
        if(line.size()==0)
        {
            out<<endl;
            continue;
        }
        switch(step)
        {
            case source_file_parse_step::NONE:
                blank_pos=line.find(" ");
                if(string_start_with(line,"#tracepoint:syscalls:sys_") && blank_pos!=string::npos)
                {
                    current_detection_point=new struct syscall_detection_point(line.substr(blank_pos),line.substr(1,blank_pos-1));
                    trim(current_detection_point->name);
                    trim(current_detection_point->probe_name);
                    syscall_detection_points_.insert(make_pair(current_detection_point->name,current_detection_point));
                    if(syscall_probes_.find(current_detection_point->probe_name)==syscall_probes_.end())
                    {
                        print_error("Can not find syscall tracepoint "+current_detection_point->probe_name+"!");
                    }
                    if(!is_legal_var_name(current_detection_point->name))
                    {
                        print_error("Illegal point name "+current_detection_point->name+"!");
                    }
                    step=source_file_parse_step::DEFINE_POINT;
                }
                else if(line=="#sequence")
                {
                    step=source_file_parse_step::DEFINE_SEQUENCE;
                }
                else if(line=="#includes")
                {
                    step=source_file_parse_step::DEFINE_INCLUDES;
                }
                else if(line=="#BEGIN_probe")
                {
                    step=source_file_parse_step::DEFINE_BEGIN_PROBE;
                }
                else if(line=="#END_probe")
                {
                    step=source_file_parse_step::DEFINE_END_PROBE;
                }
                else if(string_start_with(line,"#atom "))
                {
                    line.erase(0,string("#atom ").size());
                    trim(line);
                    if(line=="process")
                    {
                        detection_atom_=syscall_detection_atom::PROCESS;
                    }
                    else if(line=="thread")
                    {
                        detection_atom_=syscall_detection_atom::THREAD;
                    }
                    else
                    {
                        print_error("Value after \"#atom\" can only be \"process\" or \"thread\"!");
                    }
                }
                else if(string_start_with(line,"#ignore "))
                {
                    line.erase(0,string("#ignore ").size());
                    trim(line);
                    while(line.size()!=0)
                    {
                        if(line.find(",")!=string::npos)
                        {
                            tmp=line.substr(0,line.find(","));
                            line.erase(0,line.find(",")+1);
                        }
                        else
                        {
                            tmp=line;
                            line="";
                        }
                        trim(tmp);
                        trim(line);
                        if(string_start_with(tmp,"sys_"))
                        {
                            tmp.erase(0,string("sys_").size());
                            if(syscall_probes_.find("tracepoint:syscalls:sys_enter_"+tmp)!=syscall_probes_.end())
                            {
                                syscall_probes_.erase("tracepoint:syscalls:sys_enter_"+tmp);
                            }
                            else
                            {
                                print_error("Can not find probe \"tracepoint:syscalls:sys_enter_"+tmp+"\"!");
                            }
                            if(syscall_probes_.find("tracepoint:syscalls:sys_exit_"+tmp)!=syscall_probes_.end())
                            {
                                syscall_probes_.erase("tracepoint:syscalls:sys_exit_"+tmp);
                            }
                            else
                            {
                                print_error("Can not find probe \"tracepoint:syscalls:sys_exit_"+tmp+"\"!");
                            }
                        }
                        else
                        {
                            print_error("Ignored syscalls tracepoint must start with \"sys_\"!");
                        }
                    }
                }
                else
                {
                    print_error("Can not parse line \""+line+"\"!");
                }
                out<<endl;
                break;
            case source_file_parse_step::DEFINE_POINT:
                if(line=="#end")
                {
                    step=source_file_parse_step::NONE;
                }
                else if(string_start_with(line,"#cond "))
                {
                    line=line.substr(string("#cond ").size());
                    trim(line);
                    current_detection_point->condition=line;
                }
                else if(line=="#do")
                {
                    step=source_file_parse_step::DEFINE_DO_IN_POINT;
                }
                else
                {
                    print_error("Can not parse line \""+line+"\"!");
                }
                out<<endl;
                break;
            case source_file_parse_step::DEFINE_DO_IN_POINT:
                if(line=="#end")
                {
                    step=source_file_parse_step::NONE;
                }
                else
                {
                    current_detection_point->action.push_back(line);
                }
                out<<endl;
                break;
            case source_file_parse_step::DEFINE_SEQUENCE:
                if(line=="#end")
                {
                    step=source_file_parse_step::NONE;
                    out<<endl;
                }
                else if(line=="#do")
                {
                    step=source_file_parse_step::DEFINE_DO_IN_SEQUENCE;
                    out<<endl;
                }
                else
                {
                    out<<line<<endl;
                }
                break;
            case source_file_parse_step::DEFINE_DO_IN_SEQUENCE:
                if(line=="#end")
                {
                    sequence_actions_.push_back(sequence_action);
                    sequence_action.clear();
                    step=source_file_parse_step::NONE;
                }
                else
                {
                    sequence_action+=line;
                }
                out<<endl;
                break;
            case source_file_parse_step::DEFINE_INCLUDES:
                if(line=="#end")
                {
                    step=source_file_parse_step::NONE;
                }
                else
                {
                    include_filenames_.push_back(line);
                }
                out<<endl;
                break;
            case source_file_parse_step::DEFINE_BEGIN_PROBE:
                if(line=="#end")
                {
                    step=source_file_parse_step::NONE;
                }
                else
                {
                    BEGIN_probe_data_.push_back(line);
                }
                out<<endl;
                break;
            case source_file_parse_step::DEFINE_END_PROBE:
                if(line=="#end")
                {
                    step=source_file_parse_step::NONE;
                }
                else
                {
                    END_probe_data_.push_back(line);
                }
                out<<endl;
                break;
            default:
                break;
        }
    }
    res=true;
out:
    in.close();
    out.close();
    return res;
}

bool Translator::output_bpftrace_file(string bpftrace_filename)
{
    ofstream out;
    struct syscall_detection_point * current_syscall_detection_point;
    DFA<string,string> final_DFA;
    string stop_action;
    bool tag=false;

    parse(TMP_FILE_NAME);
    final_DFA=final_NFA_->to_DFA();

    map<state_index,map<string,state_index> > dfa_state_transition_table=final_DFA.get_state_transition_table();
    for(auto i:dfa_state_transition_table)
    {
        for(auto j:(i.second))
        {
            tag=false;
            if(syscall_detection_points_.find(j.first)!=syscall_detection_points_.end())
            {
                current_syscall_detection_point=syscall_detection_points_.at(j.first);
            }
            else if(syscall_probes_.find("tracepoint:syscalls:"+j.first)!=syscall_probes_.end())
            {
                current_syscall_detection_point=new struct syscall_detection_point(j.first,"tracepoint:syscalls:"+j.first);
                syscall_detection_points_.insert(make_pair(j.first,current_syscall_detection_point));
                tag=true;
            }
            else
            {
                return false;
            }

            if(final_DFA.is_stop_state(j.second))
            {
                for(auto i:final_DFA.get_state_data(j.second))
                {
                    stop_action+=i;
                }
                syscall_probes_.at(current_syscall_detection_point->probe_name).add_transition(i.first,current_syscall_detection_point,j.second,stop_action,tag);
                stop_action.clear();
            }
            else
            {
                syscall_probes_.at(current_syscall_detection_point->probe_name).add_transition(i.first,current_syscall_detection_point,j.second,tag);
            }
        }
    }

    out.open(bpftrace_filename,ios::out);
    //先把要include的文件输出
    for(auto i:include_filenames_)
    {
        out<<("#include"+i)<<endl;
    }
    //再输出BEGIN探针里面的内容
    if(BEGIN_probe_data_.size()>0)
    {
        out<<"BEGIN\n{"<<endl;
        for(auto i:BEGIN_probe_data_)
        {
            out<<"\t"<<i<<endl;
        }
        out<<"}\n"<<endl;
    }
    //再输出各个系统调用探针的内容
    for(auto i:syscall_probes_)
    {
        out<<(i.second).to_string(detection_atom_)<<endl;
    }
    //最后输出BEGIN探针里面的内容
    if(END_probe_data_.size()>0)
    {
        out<<"END\n{"<<endl;
        for(auto i:END_probe_data_)
        {
            out<<"\t"<<i<<endl;
        }
        out<<"}\n"<<endl;
    }
    out.close();
    return true;
}
