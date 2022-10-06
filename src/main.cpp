#include "dfa.h"
#include "nfa.h"
#include "translator.h"
#include <iostream>

using namespace std;

int main(int argc, char *argv[]) {
    Translator * translator = Translator::get_instance();
    string oft_string;
    enum output_file_type oft;
    if (argc < 4) {
        cout<<"Not enough parameters!"<<endl;
        return -1;
    }
    oft_string = string(argv[2]);
    if (oft_string == "--bpftrace") oft = output_file_type::BPFTRACE;
    else if (oft_string == "--libbpf") oft = output_file_type::LIBBPF;
    else return -1;
    translator->translate(string(argv[1]), string(argv[3]), oft);
    return 0;
}
