/*
 *
 *  util.h
 *  通用函数
 *  Creator:Sichao Chen
 *  Create time:2022/10/6
 *
*/
#ifndef __UTIL_H
#define __UTIL_H

#include <string>

using namespace std;

//判断str1是否以str2开头
bool string_start_with(string str1, string str2);

//去除字符串左右两边的空格
void trim(string & str);

//字符替换
string replace_char(string str, char source, char target);

//获取字符串某一个字符后面的子字符串
string get_string_after_char(string str, char ch);

#endif //__UTIL_H
