/*
 *
 *  dfa.h
 *  确定性有限状态自动机
 *  Creator:Sichao Chen
 *  Create time:2022/2/28
 *
*/
#ifndef __DFA_H
#define __DFA_H

#include"automata.h"
#include<utility>

//确定性有穷状态自动机
template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
class DFA:public AUTOMATA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>
{
private:
    //当前状态
    state_index current_state_;

    //状态转移表
    map<state_index,map<AUTOMATA_STATE_TRANSITION,state_index> > state_transition_table_;

    //新增一个状态
    bool new_state(state_index state);

    //新增一条转移边
    bool new_transition(AUTOMATA_STATE_TRANSITION transition);

    //获取从某一个状态出发，经过某一条边能够到的的状态
    state_index get_to_state(state_index from_state,AUTOMATA_STATE_TRANSITION transition) const;
    
public:
    //新建一个空的DFA
    DFA();
    DFA(state_index start_state);

    //新增一条路径
    void add_path(state_index from_state,AUTOMATA_STATE_TRANSITION transition,state_index to_state);

    //最小化DFA
    void minimize();

    //重启DFA
    void reboot();

    //清空DFA
    void clear();

    //将单个数据输入DFA
    state_index input(AUTOMATA_STATE_TRANSITION transition);

    //将序列数据输入DFA
    state_index input(list<AUTOMATA_STATE_TRANSITION> & transfers);

    //获取DFA的状态转移表
    map<state_index,map<AUTOMATA_STATE_TRANSITION,state_index> > get_state_transition_table();

    //合并两个DFA
    //static DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> combine_DFAs(state_index start_state,DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> & dfa1,DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> & dfa2);
};

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::DFA()
{
    this->start_state_=START_STATE;
    new_state(START_STATE);
    reboot();
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::DFA(state_index start_state)
{
    this->start_state_=start_state;
    new_state(this->start_state_);
    reboot();
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
bool DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::new_state(state_index state)
{
    map<AUTOMATA_STATE_TRANSITION,state_index> new_state_transition_table_line;
    if(this->states_.find(state)==this->states_.end())
    {
        this->states_.insert(state);
        for(auto i:this->transitions_)
        /*{
            new_state_transition_table_line.insert(make_pair(i,this->start_state_));
        }*/
        state_transition_table_.insert(make_pair(state,new_state_transition_table_line));
        return true;
    }
    return false;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
bool DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::new_transition(AUTOMATA_STATE_TRANSITION transition)
{
    if(this->transitions_.find(transition)==this->transitions_.end())
    {
        this->transitions_.insert(transition);
        /*for(auto i:state_transition_table_)
        {
            i.second.insert(make_pair(transition,this->start_state_));
        }*/
        return true;
    }
    return false;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
void DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::add_path(size_t from_state,AUTOMATA_STATE_TRANSITION transition,size_t to_state)
{
    new_state(from_state);
    new_transition(transition);
    new_state(to_state);
    state_transition_table_[from_state][transition]=to_state;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
state_index DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::get_to_state(state_index from_state,AUTOMATA_STATE_TRANSITION transition) const
{
    /*if(state_transition_table_.find(from_state)==state_transition_table_.end() || state_transition_table_.at(from_state).find(transition)==state_transition_table_.at(from_state).end())
    {
        return this->start_state_;
    }
    return state_transition_table_.at(from_state).at(transition);*/
    if(state_transition_table_.find(from_state)==state_transition_table_.end() || state_transition_table_.at(from_state).find(transition)==state_transition_table_.at(from_state).end())
    {
        return this->start_state_;
    }
    return state_transition_table_.at(from_state).at(transition);
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
void DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::minimize()
{
    //目前只是简单地删除那些无法从初始状态达到的状态
    //stack<state_index> states_need_checked;
    //map<state_index,bool> state_remain_or_not;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
void DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::reboot()
{
    current_state_=this->start_state_;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
void DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::clear()
{
    this->stop_states_.clear();
    this->states_.clear();
    this->transitions_.clear();
    state_transition_table_.clear();
    this->state_datas_.clear();
    new_state(this->start_state_);
    reboot();
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
state_index DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::input(AUTOMATA_STATE_TRANSITION transition)
{
    current_state_=get_to_state(current_state_,transition).second;
    return current_state_;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
state_index DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::input(list<AUTOMATA_STATE_TRANSITION> & transfers)
{
    for(auto i:transfers)
    {
        input(i);
    }
    return current_state_;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
map<state_index,map<AUTOMATA_STATE_TRANSITION,state_index> > DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::get_state_transition_table()
{
    return state_transition_table_;
}

/*template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::combine_DFAs(state_index start_state,DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> & dfa1,DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> & dfa2)
{
    DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> res(start_state);
    map<pair<state_index,state_index>,state_index> old_new_state_map;
    state_index new_state=0,current_state;
    set<AUTOMATA_STATE_TRANSITION> new_transitions;
    set_union(dfa1.this->transitions_.begin(),dfa1.this->transitions_.end(),dfa2.this->transitions_.begin(),dfa2.this->transitions_.end(),inserter(new_transitions,new_transitions.begin()));
    for(auto i:dfa1.this->states_)
    {
        for(auto j:dfa2.this->states_)
        {
            if(i==dfa1.get_start_state() && j==dfa2.get_start_state())
            {
                current_state=start_state;
            }
            else
            {
                if(new_state==start_state)
                {
                    new_state++;
                }
                current_state=new_state++;
            }
            old_new_state_map.insert(make_pair(make_pair(i,j),current_state));
            if(dfa1.this->state_datas_.find(i)!=dfa1.this->state_datas_.end())
            {
                for(auto k:dfa1.this->state_datas_.at(i))
                {
                    res.add_state_data(current_state,k);
                }
            }
            if(dfa2.this->state_datas_.find(j)!=dfa2.this->state_datas_.end())
            {
                for(auto k:dfa2.this->state_datas_.at(j))
                {
                    res.add_state_data(current_state,k);
                }
            }
            if(dfa1.is_stop_state(i) || dfa2.is_stop_state(j))
            {
                res.add_stop_state(current_state);
            }
        }
    }
    for(auto i:old_new_state_map)
    {
        for(auto j:new_transitions)
        {
            res.add_path(i.second,j,old_new_state_map[make_pair(dfa1.get_to_state(i.first.first,j),dfa2.get_to_state(i.first.second,j))]);
        }
    }
    return res;
}*/

#endif //__DFA_H