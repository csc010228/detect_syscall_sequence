/*
 *
 *  util.cpp
 *  通用函数
 *  Creator:Sichao Chen
 *  Create time:2022/10/6
 *
*/
#include "util.h"

bool string_start_with(string str1, string str2) {
    if (str1.size() >= str2.size()) {
        for (size_t i = 0 ; i < str2.size() ; i++) {
            if (str1[i] != str2[i]) return false;
        }
    } else return false;
    return true;
}

void trim(string & str) {
    string blanks("\f\v\r\t\n ");
    str.erase(0, str.find_first_not_of(blanks));
    str.erase(str.find_last_not_of(blanks) + 1);
}

string replace_char(string str, char source, char target) {
    string res = str;
    for (auto & ch : res) {
        if (ch == source) ch = target;
    }
    return res;
}