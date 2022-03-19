/*
 *
 *  automata.h
 *  自动机有关
 *  Creator:Sichao Chen
 *  Create time:2022/3/7
 *
*/
#ifndef __AUTOMATA_H
#define __AUTOMATA_H

#include <vector>
#include <list>
#include <utility>
#include <map>
#include <set>
#include <algorithm>
#include <iterator>
#include<iostream>

using namespace std;

typedef size_t state_index;

//默认的起始状态的编号是0
#define START_STATE 0

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
class AUTOMATA
{
protected:
    //初始状态
    state_index start_state_;

    //终止状态集合
    set<state_index> stop_states_;

    //状态集合
    set<state_index> states_;

    //状态相关数据
    map<state_index,list<RELATED_DATA> > state_datas_;

    //转移边集合
    set<AUTOMATA_STATE_TRANSITION> transitions_;

    //新增一个状态
    virtual bool new_state(state_index state)=0;

    //新增一条转移边
    virtual bool new_transition(AUTOMATA_STATE_TRANSITION transition)=0;

    //更改自动机的起始状态
    void change_start_state(state_index new_start_state);

public:
    //新增一条路径
    virtual void add_path(state_index from_state,AUTOMATA_STATE_TRANSITION transition,state_index to_state)=0;

    //将某一个状态设置为终止状态
    void add_stop_state(state_index stop_state);

    //将某一个终止状态设置为非终止状态
    bool remove_stop_state(state_index stop_state);

    //获取一个自动机的起始状态
    state_index get_start_state() const;
    
    //获取一个自动机的终止状态
    set<state_index> get_stop_states() const;

    //判断某一个状态是否是终止状态
    bool is_stop_state(state_index stop_state) const;

    //给某一个状态添加相关数据
    void add_state_data(state_index state,RELATED_DATA action_func);

    //给某一个状态删除相关数据
    void remove_state_data(state_index state,RELATED_DATA action_func);

    //获取某一个状态上的相关数据
    list<RELATED_DATA> get_state_data(state_index state);

    //重启状态机
    virtual void reboot()=0;

    //清空状态机
    virtual void clear()=0;
};

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
void AUTOMATA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::add_stop_state(state_index stop_state)
{
    if(states_.find(stop_state)==states_.end())
    {
        new_state(stop_state);
    }
    stop_states_.insert(stop_state);
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
void AUTOMATA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::change_start_state(state_index new_start_state)
{
    if(states_.find(new_start_state)==states_.end())
    {
        new_state(new_start_state);
    }
    start_state_=new_start_state;
    reboot();
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
state_index AUTOMATA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::get_start_state() const
{
    return (start_state_);
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
set<state_index> AUTOMATA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::get_stop_states() const
{	
    return (stop_states_);
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
bool AUTOMATA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::is_stop_state(state_index stop_state) const
{
    return (stop_states_.find(stop_state)!=stop_states_.end());
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
void AUTOMATA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::add_state_data(state_index state,RELATED_DATA action_func)
{
    list<RELATED_DATA> action_funcs;
    if(states_.find(state)==states_.end())
    {
        new_state(state);
    }
    if(state_datas_.find(state)==state_datas_.end())
    {
        action_funcs.push_back(action_func);
        state_datas_.insert(make_pair(state,action_funcs));
    }
    else
    {
        for(auto i:state_datas_.at(state))
        {
            if(i==action_func)
            {
                return;
            }
        }
        state_datas_.at(state).push_back(action_func);
    }
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
bool AUTOMATA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::remove_stop_state(state_index stop_state)
{
    if(stop_states_.find(stop_state)==stop_states_.end())
    {
        return false;
    }
    stop_states_.erase(stop_state);
    return true;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
void AUTOMATA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::remove_state_data(state_index state,RELATED_DATA action_func)
{
    if(state_datas_.find(state)!=state_datas_.end())
    {
        state_datas_.at(state).remove(action_func);
    }
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
list<RELATED_DATA> AUTOMATA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::get_state_data(state_index state)
{
    list<RELATED_DATA> empty;

    if(state_datas_.find(state)==state_datas_.end())
    {
        return empty;
    }

    return state_datas_.at(state);
}

#endif //__AUTOMATA_H
