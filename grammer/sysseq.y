%{
#include<stdio.h>
#include<ctype.h>
#include<set>
#include"nfa.h"
#include"translator.h"

//在lex.yy.c里定义，会被yyparse()调用。在此声明消除编译和链接错误。
extern int yylex(void); 

// 在此声明，消除yacc生成代码时的告警
extern int yyparse(void); 

// 该函数在y.tab.c里会被调用，需要在此定义
void yyerror(const char *s)
{
	printf("[error] %s\n", s);
}

extern FILE * yyin;
int parse(const char * filename)
{
    yyin=fopen(filename,"r");
    return yyparse();
}

%}

%union
{
    struct nfa_info_struct
    {
        void * nfa_ptr;
        void * pre_nfa_states;
        size_t next_nfa_state;
    }nfa_info;
    struct
    {
        bool is_nfa;
        union
        {
            const char * id_name;
            struct nfa_info_struct nfa_info;
        };
    }attr_nfa_node;
    const char * attr_id;
}
%token<attr_id> ID
%token PTR L_PAREN R_PAREN MULTI ADD OR SEMIC

%type<nfa_info> seqs seq nfa or_nfa
%type<attr_nfa_node> nfa_node
%%
seqs        :   seqs seq {
    $$=$1;
    ((NFA<string,string> *)($$.nfa_ptr))->parallel_connect_NFA(*((NFA<string,string> *)($2.nfa_ptr)));
    delete ((NFA<string,string> *)($2.nfa_ptr));
    Translator::get_instance()->final_NFA_=((NFA<string,string> *)($$.nfa_ptr));
}
            |   seq {
    $$=$1;Translator::get_instance()->final_NFA_=((NFA<string,string> *)($$.nfa_ptr));
}
            ;
seq         :   nfa SEMIC {
    string action=Translator::get_instance()->sequence_actions_.front();
    $$=$1;
    for(auto i:*((set<size_t> *)$$.pre_nfa_states))
    {
        ((NFA<string,string> *)($$.nfa_ptr))->add_stop_state(i);
        ((NFA<string,string> *)($$.nfa_ptr))->add_state_data(i,action);
    }
    Translator::get_instance()->sequence_actions_.pop_front();
}
            ;
nfa         :   nfa PTR or_nfa {
    $$=$1;
    set<size_t> * new_pre_nfa_states=new set<size_t>;
    map<state_index,state_index> old_new_state_index_map;
    for(auto i:*((set<size_t> *)$$.pre_nfa_states))
    {
        old_new_state_index_map=((NFA<string,string> *)($$.nfa_ptr))->series_connect_NFA(i,*((NFA<string,string> *)($3.nfa_ptr)));
        for(auto j:*((set<size_t> *)$3.pre_nfa_states))
        {
            new_pre_nfa_states->insert(old_new_state_index_map.at(j));
        }
        $$.next_nfa_state=$$.next_nfa_state+$3.next_nfa_state;
    }
    delete ((NFA<string,string> *)($3.nfa_ptr));
    delete ((set<size_t> *)$3.pre_nfa_states);
    delete (set<size_t> *)$$.pre_nfa_states;
    $$.pre_nfa_states=new_pre_nfa_states;
}
            |   or_nfa {
    $$=$1;
}
            ;
or_nfa      :   or_nfa OR nfa_node {
    $$=$1;
    if($3.is_nfa)
    {
        map<state_index,state_index> old_new_state_index_map=((NFA<string,string> *)($$.nfa_ptr))->parallel_connect_NFA(*((NFA<string,string> *)($3.nfa_info.nfa_ptr)));
        for(auto i:*((set<size_t> *)$3.nfa_info.pre_nfa_states))
        {
            ((set<size_t> *)$$.pre_nfa_states)->insert(old_new_state_index_map.at(i));
        }
        $$.next_nfa_state=$$.next_nfa_state+$3.nfa_info.next_nfa_state;
        delete ((NFA<string,string> *)($3.nfa_info.nfa_ptr));
        delete ((set<size_t> *)$3.nfa_info.pre_nfa_states);
    }
    else
    {
        ((NFA<string,string> *)($$.nfa_ptr))->add_path(0,string($3.id_name),$$.next_nfa_state);
        ((set<size_t> *)$$.pre_nfa_states)->insert($$.next_nfa_state);
        $$.next_nfa_state=$$.next_nfa_state+1;
    }
}
            |   nfa_node {
    if($1.is_nfa)
    {
        $$=$1.nfa_info;
    }
    else
    {
        $$.next_nfa_state=2;
        $$.pre_nfa_states=(void *)(new set<size_t>);
        ((set<size_t> *)$$.pre_nfa_states)->insert(1);
        $$.nfa_ptr=(void *)(new NFA<string,string>(0));
        ((NFA<string,string> *)($$.nfa_ptr))->add_path(0,string($1.id_name),1);
    }
}
            ;
nfa_node    :   ID {
    $$.is_nfa=false;
    $$.id_name=$1;
}
            |   L_PAREN nfa R_PAREN {
    $$.is_nfa=true;$$.nfa_info=$2;
}
            |   nfa_node MULTI {
    if($1.is_nfa)
    {
        $$=$1;
        for(auto i:*((set<size_t> *)$$.nfa_info.pre_nfa_states))
        {
            ((NFA<string,string> *)($$.nfa_info.nfa_ptr))->combine_states(0,i);
        }
        ((set<size_t> *)$$.nfa_info.pre_nfa_states)->clear();
    }
    else
    {
        $$.is_nfa=true;
        $$.nfa_info.next_nfa_state=1;
        $$.nfa_info.nfa_ptr=(void *)(new NFA<string,string>(0));
        ((NFA<string,string> *)($$.nfa_info.nfa_ptr))->add_path(0,string($1.id_name),0);
        $$.nfa_info.pre_nfa_states=(void *)(new set<size_t>);
    }
    ((set<size_t> *)$$.nfa_info.pre_nfa_states)->insert(0);
}
            |   nfa_node ADD {
    if($1.is_nfa)
    {
        $$=$1;
    }
    else
    {
        $$.is_nfa=true;
        $$.nfa_info.next_nfa_state=2;
        $$.nfa_info.nfa_ptr=(void *)(new NFA<string,string>(0));
        ((NFA<string,string> *)($$.nfa_info.nfa_ptr))->add_path(0,string($1.id_name),1);
        $$.nfa_info.pre_nfa_states=(void *)(new set<size_t>);
        ((set<size_t> *)$$.nfa_info.pre_nfa_states)->insert(1);
    }
    ((set<size_t> *)$$.nfa_info.pre_nfa_states)->insert(0);
}
            ;
%%