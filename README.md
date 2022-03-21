# Detect syscall sequence

## 简介

**该项目允许用户通编写过简单的脚本语言（我管他叫做dss语言，即detect syscall sequence）实现对若干个指定的系统调用序列进行检测。**

## 原理

* 本项目可以看作是一个简单的编译器，它会根据给定的dss语言，将每一个系统调用序列都转换成一个NFA，然后将所有的NFA合并成一个大的NFA，然后再将其转换成DFA，最后将这个DFA语言翻译成bpftrace的bt文件，最后就可以使用bpftrace运行该bt文件，实现若干系统调用序列的检测

## 语法

1. 如果需要在最终的bt文件中包含某些头文件，那么可以把它们放在`#includes`和`#end`之间，需要注意的是`#includes`和`#end`都需要独立一行。例如：

   ```
   #includes
   	<asm/signal.h>
   #end
   ```

2. 可以使用`#atom`来更改检测系统调用序列的基本单元，可取的值有：

   * `process`（进程）
   * `thread`（线程）

   例如：

   ```
   #atom process
   ```

   如果不显示指定的话，那么默认的检测的基本单元是线程

3. 如果需要在最终的bt文件的`BEGIN`探针中包含内容的话，那么可以把它们放在`#BEGIN_probe`和`#end`之间，需要注意的是`#BEGIN_probe`和`#end`都需要独立一行。例如：

   ```
   #BEGIN_probe
       printf("Tracing sliver implant... Hit Ctrl-C to end.\n");
   	printf("%-9s %-20s %-10s %-10s %-20s\n", "TIME", "IMPLANT", "PID", "TID", "COMMAND");
   #end
   ```

4. 如果需要在最终的bt文件的`END`探针中包含内容的话，那么可以把它们放在`#END_probe`和`#end`之间，需要注意的是`#END_probe`和`#end`都需要独立一行。例如：

   ```
   #END_probe
       printf("Tracing sliver implant end.\n");
   #end
   ```

5. 如果在本次检测中，有一些系统调用是不需要检测的，你可以使用`#ignore`将它们忽略，这样的话这些系统调用就不会对本次检测造成影响，例如：

   ```
   #ignore sys_openat,sys_close
   ```

   上面的例子就表示在本次检测中会忽略`tracepoint:syscalls:sys_enter_openat`，`tracepoint:syscalls:sys_exit_openat`，`tracepoint:syscalls:sys_enter_close`，`tracepoint:syscalls:sys_exit_close`这四个探针

6. 系统调用序列的检测的单元是一个一个的检测节点，定义一个检测节点如下：

   ```
   #tracepoint:syscalls:sys_enter_epoll_pwait ep
       #cond args->epfd==4 && args->maxevents==128
       #do
       	printf("FIND ep!\n");
   #end
   ```

   * 第一行的`#tracepoint:syscalls:sys_enter_epoll_pwait`是该检测节点的所属的系统调用探针的名字，而`ep`是这个检测节点的名字

     你可以在同一个系统调用探针上定义多个检测节点

   * 第二行的`#cond`以及后面的内容是这个检测节点被触发的条件，这个部分是可选的、

   * 第三行的`#do`到最后一行的`#end`之间的内容是当这个检测节点被触发的时候会执行的动作

7. 一个系统调用序列的定义方式如下：

   ```
   #sequence
       read->read->
       sys_enter_newfstatat->sys_enter_newfstatat->sys_enter_getcwd+->sys_enter_newfstatat->
       sys_enter_openat->sys_enter_epoll_ctl->sys_enter_getdents64->
       (sys_enter_newfstatat)*->
       sys_enter_getdents64->sys_enter_close->
       write->write->
       epoll_pwait->epoll_pwait;
   #do
       time("%H:%M:%S  ");
       printf("%-20s %-10d %-10d %-20s\n",comm,pid,tid,"ls");
   #end
   ```

   * 第一行的`#sequence`是定义系统调用序列的开始，它需要独立一行

   * 从第二行开始到`#do`之间的内容是由检测节点组成的检测序列，在这里，你既可以使用自己定义的，带有额外触发条件和触发动作的检测节点（例如上面的`read`，`write`，`epoll_pwait`），也可以使用默认的系统调用探针作为检测节点（只需要把系统调用名前面加上`sys_enter_`或者`sys_exit_`即可）

   * 使用`->`运算符把两个序列连接在一起，也可以使用`*`表示匹配该序列零次或多次，使用`+`表示匹配该序列零次或一次，使用`|`表示两个序列只需要匹配其中一个即可。它们的运算符优先级如下：

     `*`==`+`>`|`>`->`

   * `#do`到`#end`之间的内容是当匹配上该序列之后会执行的动作

   你可以定义多个系统调用序列，同时检测它们

## 使用方法

* 只需要拷贝源代码，然后进入项目文件夹之后，输入`make`进行编译，会得到一个`dss`可执行文件，按照如下方式执行即可：

  ```she
  ./dss example.txt test.bt
  ```

  其中`example.txt`是要dss语言的源文件名，`test.bt`是最终要生成的bt文件名
