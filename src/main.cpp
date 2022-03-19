#include "dfa.h"
#include "nfa.h"
#include "translator.h"
#include <iostream>

using namespace std;

int main(int argc,char *argv[])
{
    Translator * translator=Translator::get_instance();
    if(argc<3)
    {
        cout<<"Not enough parameters!"<<endl;
        return -1;
    }
    translator->translate(string(argv[1]),string(argv[2]));
    return 0;
}
