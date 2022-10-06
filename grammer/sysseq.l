%option noyywrap
%{
#include<stdio.h>
//#define YYSTYPE char *
//extern YYSTYPE yylval; // 必须放在#include "y.tab.h"前面
#include "y.tab.h"
%}
delim           [\f\v\r\t\n ]
ws              [delim]+
letter          [a-zA-Z]
digit           [0-9]
id              (_|{letter})(_|{letter}|{digit})*
number          {digit}+
%%
{ws}            ;
{id}            {yylval.attr_id=strdup(yytext);return(ID);}
"->"            return(PTR);
"*"             return(MULTI);
"+"             return(ADD);
"|"             return(OR);
"("             return(L_PAREN);
")"             return(R_PAREN);
";"             return(SEMIC);
%%