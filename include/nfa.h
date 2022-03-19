/*
 *
 *  nfa.h
 *  非确定性有限状态自动机
 *  Creator:Sichao Chen
 *  Create time:2022/3/7
 *
*/
#ifndef __NFA_H
#define __NFA_H

#include"automata.h"
#include"dfa.h"
#include<stack>

//非确定性有穷状态自动机
template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
class NFA:public AUTOMATA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>
{
private:
    //当前状态集合
    set<state_index> current_states_;

    //状态转移表
    map<state_index,map<AUTOMATA_STATE_TRANSITION,set<state_index> > > state_transition_table_;

    //新增一个状态
    bool new_state(state_index state);

    //删除一个状态
    bool delete_state(state_index state);

    //新增一条转移边
    bool new_transition(AUTOMATA_STATE_TRANSITION transition);

    //删除一条路径
    bool remove_path(state_index from_state,AUTOMATA_STATE_TRANSITION transition,state_index to_state);

    //获取从某一个状态出发，经过某一条边能够到的的状态集合
    set<state_index> get_to_state(state_index from_state,AUTOMATA_STATE_TRANSITION transition) const;
    
public:
    //新建一个空的NFA
    NFA();
    NFA(state_index start_state);

    //把一个NFA删除，变成空的，只有一个起始状态的NFA
    void clear();

    //新增一条路径
    void add_path(state_index from_state,AUTOMATA_STATE_TRANSITION transition,state_index to_state);

    //合并两个状态,其中state_2会被删除
    void combine_states(state_index state_1,state_index state_2);

    //重启NFA
    void reboot();

    //将单个数据输入NFA
    set<state_index> input(AUTOMATA_STATE_TRANSITION transition);

    //将序列数据输入NFA
    set<state_index> input(list<AUTOMATA_STATE_TRANSITION> & transfers);

    //把当前的NFA和另一个NFA并联
    map<state_index,state_index> parallel_connect_NFA(NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> & another_nfa);

    //把当前的NFA的state和另一个NFA的起始状态通过边transfer进行串联，从而变成一个大的NFA
    map<state_index,state_index> series_connect_NFA(state_index state,NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> & another_nfa);

    //把NFA转换成DFA
    DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> to_DFA() const;
};

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::NFA()
{
    this->start_state_=START_STATE;
    new_state(START_STATE);
    reboot();
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::NFA(state_index start_state)
{
    this->start_state_=start_state;
    new_state(this->start_state_);
    reboot();
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
void NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::clear()
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
bool NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::new_state(state_index state)
{
    map<AUTOMATA_STATE_TRANSITION,set<state_index > > new_state_transition_table_line;
    set<state_index> no_states;
    if(this->states_.find(state)==this->states_.end())
    {
        this->states_.insert(state);
        for(auto i:this->transitions_)
        {
            new_state_transition_table_line.insert(make_pair(i,no_states));
        }
        state_transition_table_.insert(make_pair(state,new_state_transition_table_line));
        return true;
    }
    return false;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
bool NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::delete_state(state_index state)
{
    if(this->states_.find(state)==this->states_.end() || state==this->start_state_)
    {
        return false;
    }
    this->states_.erase(state);
    state_transition_table_.erase(state);
    this->remove_stop_state(state);
    this->state_datas_.erase(state);
    for(auto i:state_transition_table_)
    {
        for(auto j:(i.second))
        {
            for(auto k:(j.second))
            {
                if(k==state)
                {
                    remove_path(i.first,j.first,k);
                }
            }
        }
    }
    return true;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
bool NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::new_transition(AUTOMATA_STATE_TRANSITION transition)
{
    set<state_index> no_states;
    if(this->transitions_.find(transition)==this->transitions_.end())
    {
        this->transitions_.insert(transition);
        for(auto i:state_transition_table_)
        {
            //i.second.insert(make_pair(transition,no_states));
            state_transition_table_.at(i.first).insert(make_pair(transition,no_states));
        }
        return true;
    }
    return false;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
bool NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::remove_path(state_index from_state,AUTOMATA_STATE_TRANSITION transition,state_index to_state)
{
    set<state_index> tmp=get_to_state(from_state,transition);
    if(tmp.find(to_state)==tmp.end())
    {
        return false;
    }
    state_transition_table_.at(from_state).at(transition).erase(to_state);
    return true;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
void NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::add_path(size_t from_state,AUTOMATA_STATE_TRANSITION transition,size_t to_state)
{
    new_state(from_state);
    new_transition(transition);
    new_state(to_state);
    state_transition_table_.at(from_state).at(transition).insert(to_state);
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
void NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::combine_states(state_index state_1,state_index state_2)
{
    state_index from_state,to_state;
    bool tag=false;
    if(state_1==state_2 || this->states_.find(state_1)==this->states_.end() || this->states_.find(state_2)==this->states_.end())
    {
        return;
    }
    for(auto i:state_transition_table_)
    {
        for(auto j:(i.second))
        {
            for(auto k:get_to_state(i.first,j.first))
            {
                from_state=i.first;
                if(from_state==state_2)
                {
                    from_state=state_1;
                    tag=true;
                }
                to_state=k;
                if(to_state==state_2)
                {
                    to_state=state_1;
                    tag=true;
                }
                if(tag)
                {
                    add_path(from_state,j.first,to_state);
                    tag=false;
                }
            }
        }
    }
    if(state_2==this->start_state_)
    {
        this->change_start_state(state_1);
    }
    if(this->is_stop_state(state_2))
    {
        this->add_stop_state(state_1);
    }
    if(this->state_datas_.find(state_2)!=this->state_datas_.end())
    {
        for(auto i:this->state_datas_.at(state_2))
        {
            this->add_state_data(state_1,i);
        }
    }
    delete_state(state_2);
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
set<state_index> NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::get_to_state(state_index from_state,AUTOMATA_STATE_TRANSITION transition) const
{
    set<state_index> no_states;
    if(state_transition_table_.find(from_state)==state_transition_table_.end() || state_transition_table_.at(from_state).find(transition)==state_transition_table_.at(from_state).end() || state_transition_table_.at(from_state).at(transition).size()==0)
    {
        return no_states;
    }
    return state_transition_table_.at(from_state).at(transition);
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
void NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::reboot()
{
    current_states_.clear();
    current_states_.insert(this->start_state_);
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
set<state_index> NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::input(AUTOMATA_STATE_TRANSITION transition)
{
    set<state_index> old_current_states=current_states_,tmp;
    current_states_.clear();
    for(auto i:old_current_states)
    {
        tmp=get_to_state(i,transition);;
        set_union(current_states_.begin(),current_states_.end(),tmp.begin(),tmp.end(),inserter(current_states_,current_states_.begin()));
    }
    if(current_states_.size()==0)
    {
        reboot();
    }
    return current_states_;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
set<state_index> NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::input(list<AUTOMATA_STATE_TRANSITION> & transfers)
{
    for(auto i:transfers)
    {
        input(i);
    }
    return current_states_;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
map<state_index,state_index> NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::parallel_connect_NFA(NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> & another_nfa)
{
    return series_connect_NFA(this->start_state_,another_nfa);
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
map<state_index,state_index> NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::series_connect_NFA(state_index state,NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> & another_nfa)
{
    map<state_index,state_index> old_new_state_index_map;
    state_index tmp=0;
    for(auto i:another_nfa.states_)
    {
        if(i!=another_nfa.get_start_state())
        {
            while(this->states_.find(tmp)!=this->states_.end())
            {
                tmp++;
            }
            this->new_state(tmp);
            old_new_state_index_map.insert(make_pair(i,tmp));
        }
        else
        {
            old_new_state_index_map.insert(make_pair(i,state));
        }
        if(another_nfa.is_stop_state(i))
        {
            this->add_stop_state(old_new_state_index_map.at(i));
        }
    }
    for(auto i:another_nfa.state_datas_)
    {
        for(auto j:(i.second))
        {
            this->add_state_data(old_new_state_index_map[i.first],j);
        }
    }
    for(auto i:another_nfa.state_transition_table_)
    {
        for(auto j:(i.second))
        {
            for(auto k:(j.second))
            {
                add_path(old_new_state_index_map[i.first],j.first,old_new_state_index_map[k]);
            }
        }
    }
    return old_new_state_index_map;
}

template<typename AUTOMATA_STATE_TRANSITION,typename RELATED_DATA>
DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> NFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA>::to_DFA() const
{
    map<set<state_index>,state_index> old_new_state_index_map;
    stack<set<state_index> > new_state_indexs_not_checked;
    set<state_index> from_states,to_states,tmp;
    state_index dfa_state=0;
    DFA<AUTOMATA_STATE_TRANSITION,RELATED_DATA> res(dfa_state);
    tmp.insert(this->start_state_);
    old_new_state_index_map.insert(make_pair(tmp,dfa_state));
    new_state_indexs_not_checked.push(tmp);
    if(this->is_stop_state(this->start_state_))
    {
        res.add_stop_state(dfa_state);
    }
    dfa_state++;
    while(!new_state_indexs_not_checked.empty())
    {
        from_states=new_state_indexs_not_checked.top();
        new_state_indexs_not_checked.pop();
        for(auto i:this->transitions_)
        {
            to_states.clear();
            for(auto j:from_states)
            {
                tmp=get_to_state(j,i);
                set_union(to_states.begin(),to_states.end(),tmp.begin(),tmp.end(),inserter(to_states,to_states.begin()));
            }
            if(to_states.size()!=0)
            {
                if(old_new_state_index_map.find(to_states)==old_new_state_index_map.end())
                {
                    old_new_state_index_map.insert(make_pair(to_states,dfa_state));
                    new_state_indexs_not_checked.push(to_states);
                    for(auto k:to_states)
                    {
                        if(this->is_stop_state(k))
                        {
                            res.add_stop_state(dfa_state);
                            break;
                        }
                    }
                    dfa_state++;
                }
                res.add_path(old_new_state_index_map.at(from_states),i,old_new_state_index_map.at(to_states));
            }
        }
    }
    for(auto i:old_new_state_index_map)
    {
        for(auto j:(i.first))
        {
            if(this->state_datas_.find(j)!=this->state_datas_.end())
            {
                for(auto k:(this->state_datas_).at(j))
                {
                    res.add_state_data(i.second,k);
                }
            }
        }
    }
    return res;
}

#endif //__NFA_H
