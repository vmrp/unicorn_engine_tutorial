# 使用unicorn-engine开发模拟器

## 什么是unicorn引擎

Unicorn是基于qemu开发的一个CPU模拟器，支持常见的各种指令集，能在各种系统上运行。

GITHUB项目地址：https://github.com/unicorn-engine/unicorn

官网地址：https://www.unicorn-engine.org/

一个中文API文档：https://github.com/kabeor/Micro-Unicorn-Engine-API-Documentation

它只是一个CPU模拟器，所以它的API非常简洁，它提供了各种编程语言的绑定，你可以选择喜欢编程语言进行开发，被加载到unicorn中执行的程序对内存的每一次读写，每一条指令的执行都在你的掌控之中，并且被unicorn加载运行的程序对这一切是完全无感知的


## 准备工作

写这篇文章的目的是帮助理解我的开源模拟器 [vmrp](https://github.com/zengming00/vmrp) 的工作原理，因此这里介绍的是windows下用c语言开发arm模拟器，网络上其它的unicorn文章也仅仅只描述了简单的应用，对于一些关键的核心问题并没有给出答案

使用到的GCC编译器：
https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/8.1.0/threads-posix/sjlj/x86_64-8.1.0-release-posix-sjlj-rt_v6-rev0.7z

使用的unicorn下载地址：
https://github.com/unicorn-engine/unicorn/releases/download/1.0.2/unicorn-1.0.2-win32.zip

需要特别注意的是必需使用1.0.2以上版本的unicorn，因为我在使用unicorn开发模拟器时unicorn还处于1.0.1版本，1.0.1版本存在一个奇怪的BUG导致模拟器出现程序跑飞的情况，在1.0.2版本发布后再次尝试才终于成功。

另外使用unicorn一定会涉及到汇编和反汇编知识，如果有这方面的知识理解起来会更容易


## helloworld

高级编程语言会有类、对象等概念，这些概念是为了方便人脑的思考，总结出来的一种编程习惯，CPU只知道如何处理最简单的指令，无论程序有多复杂编译后给CPU执行的都是最简单的一条条指令，通常一个CPU指令集也就几十条指令而已，计算机所有的功能都是通过这几十条指令完成的，汇编语言其实就是每一条指令的直接使用和一些约定的编程规范

你可以简单的把一条指令理解为编程语言中的一个函数

让我们通过几条指令来做一个加法运算

```asm
mov r0,1       // 将数字1送入寄存器r0
mov r1,2       // 将数字2送入寄存器r1
add r2,r0,r1   // 将r0+r1的运算结果送入寄存器r2
```
这里推荐一个学习arm汇编的工具：https://github.com/linouxis9/ARMStrong

为了方便演示，简化代码，下面的代码假设每一步都是成功的，所以没有错误处理的部分，实际应用时应该对unicorn api的返回值做判断
```c
#include <stdio.h>
#include <stdint.h>
#include "./unicorn-1.0.2-win32/include/unicorn/unicorn.h"

// 指令数据在内存中的地址，你可以放在内存地址范围内的任何一个地方，
// 但是每个CPU架构都有一些特殊的内存地址区间是有特殊作用的，
// 并且unicorn要求地址必需4k对齐，因此这里我用的是0x8000
#define ADDRESS 0x8000

int main() {
    uc_engine *uc;
    uint32_t r2;

    // 汇编代码           指令
    // mov r0,1        0xE3A00001
    // mov r1,2        0xE3A01002
    // add r2,r0,r1    0xE0802001
    uint32_t code[] = {0xE3A00001, 0xE3A01002, 0xE0802001};

    // 将unicorn初始化为arm架构的arm指令集模式
    uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);

    // 申请一块内存空间，由于unicorn要求地址必需4k对齐，所以这里申请了4K的内存，权限为全部权限（可读、可写、可执行）
    uc_mem_map(uc, ADDRESS, 1024 * 4, UC_PROT_ALL);

    // 将指令数据写入到模拟器内存
    uc_mem_write(uc, ADDRESS, code, sizeof(code));

    // 让模拟器从指定的地址开始运行，到指定的地址停止运行
    uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(code), 0, 0);

    // 从模拟器中读取r2寄存器的值
    uc_reg_read(uc, UC_ARM_REG_R2, &r2);
    printf("r2 = %d\n", r2);
    uc_close(uc);
    return 0;
}
```

编译方法：

```
gcc -g -Wall -m32 -o main 1.c ./unicorn-1.0.2-win32/unicorn.dll 
```

注意运行时要把unicorn.dll和main.exe放在一起

```
$ ./main.exe 
r2 = 3
```

可以看到，只需几个api调用就可以将unicorn运用起来，事实上在我的模拟器中使用到的unicorn api也只比上面这个例子多几个而已，unicorn真的是一个非常强大又极其简单的工具




## 大小端字节序

大小端字节序是指一个大于1字节的数据在内存中的存放顺序，如果不搞清楚这个问题可能会在以后的编程中遇到难解的问题

大端模式，是指数据的高字节保存在内存的低地址中，而数据的低字节保存在内存的高地址中，这样的存储模式有点儿类似于把数据当作字符串顺序处理:地址由小向大增加，而数据从高位往低位放;这和我们的阅读习惯一致。

小端模式，是指数据的高字节保存在内存的高地址中，而数据的低字节保存在内存的低地址中，这种存储模式将地址的高低和数据位权有效地结合起来，高地址部分权值高，低地址部分权值低。

可以看到，我在代码里存放指令数据里是这样写的
```
uint32_t code[] = {0xE3A00001, 0xE3A01002, 0xE0802001};
```

同样的代码编译为大端字节序时在内存中是这样的
```
E3 A0 00 01    E3 A0 10 02    E0 80 20 01
```
而编译为小端字节序时在内存中是这样的
```
01 00 A0 E3    02 10 A0 E3    01 20 80 E0
```

字节序的问题只会影响我们对内存的特殊读写，通常ARM都是小端模式，x86也是小端


## ARM模式和THUMB模式

ARM模式每条指令占用4个字节，而THUMB模式每条指令只占用2个字节，两种模式的指令是可以同时出现在同一个可执行文件中的，主要原因是使用thumb模式编译的文件会比arm模式减少大约30%的体积，在嵌入式设备中是很可观的，缺点自然是效率不如arm模式高。

两种模式的代码之间通常是由带'x'后辍的跳转指令自动切换arm与thumb，直接混合在一起是无法运行的


## 函数

无论高级语言有多强大的语法，汇编层面最多只到函数，函数本质就是能够复用的一堆指令，因此和上面第一个例子并没有多大的区别，不同的地方在于一个函数必需要按照严格的约定编写，这样才能让其它人调用你的函数，或者你调用别人写的函数，如果不按约定随便乱来，那么互相调用将必定出问题。

这样的约定规则叫做ABI(Application Binary Interface)，由于这套规则比较复杂，我只举例其中最简单最常用的规则:

- 函数的参数小于等于4个，那么按顺序依次放入r0-r3寄存器
    void fn(a,b,c,d){}
    参数a的值放入r0寄存器，参数d的值放入r3寄存器

- 如果函数有返回值，那么放在r0寄存器

- 函数内部如果使用了额外的寄存器，那么在使用前应该备份，使用后应该恢复原本的值

以一个简单的函数举例：
```c
int add(int a, int b) {
    return a + b;
}
```

编译后是这样的：
```asm
add r0,r0,r1  // 完成a+b的操作并设置返回值
bx lr         // 返回（跳转到lr寄存器指向的地址）
```

函数调用必定涉及跳转指令，ARM指令中'B'开头的指令是管跳转的，带上不同的后辍又有不同的功能，在函数调用中最常见的是bx和blx指令，其中'x'后辍指的是自动切换ARM模式和thumb模式，'l'后辍是指跳转前将下一条指令的地址保存到lr寄存器中，函数的跳转正是由blx和bx lr配合完成的

## 函数参数传递

在上面提到函数的参数小于等于4个时，参数是按顺序依次放入r0-r3寄存器，返回值也是放入r0寄存器

arm寄存器是32位的（arm64是64位），无论传递的是char还是int或者float类型，只要小于等于32位都是直接占用一整个寄存器

那64位类型是怎么传递的呢？答案是用两个寄存器，由于这里只介绍最简单最常见的参数传递，所以这样的参数传递规则我们跳过

重点是指针类型，通过指针类型我们可以传递任何的数据，指针表示的是一个内存地址，因此无论你是char指针还是int指针它都是32位的（与寄存器相同），所以指针作为参数传递时也是直接占用一整个寄存器

除基本数据类型外还有结构和数组，这两者实际上都是内存块，都可以通过指针访问到，因此用指针类型就能传递

有基本数据类型和指针就足够我们进行数据的交换了，它们都满足直接占用一整个寄存器的条件，因此函数调用最简单的规则就是使用r0-r3这四个寄存器，C语言编程时如果也是按这种规则设计函数，那么它的效率也是最高的

超出简单规则之外的参数传递方式需要深入去研究，关键词是ATPCS和AAPCS

## 位置无关代码

与位置相关的代码指的是将内存地址写死在了程序里面，这样的程序在任何一个设备上都要求在相同的内存地址才能够正确执行，这样做的好处是程序的运行效率更高。

相反，位置无关代码指的是一段代码无论加载到内存中的什么位置它都能够正常执行，技术原理就是使用相对位置，或者是采用一个寄存器来表示一个基础地址，其它任何操作都基于这个给定的基地址，通常这个寄存器是r9，这样做的好处是能够实现代码的动态加载。

- 在gcc编译时加入-fpic选项即可生成位置无关代码

那么，要使用相对位置肯定就得知道自己在什么位置，怎么做呢？当然是程序指针寄存器，在ARM中叫PC

由于 ARM 体系结构采用了多级流水线技术， 对于 ARM 指令集而言， PC 总是指向当前指令的下两条指令的地址，即 PC 的值为当前指令的地址值加 8 个字节。
```asm
0x1000 mov r0,pc   // 执行后r0的值并不是当前地址，而是0x1008
0x1004 mov r1,1
0x1008 mov r1,2
```


## 函数案例

这是我精心设计的一个小片段，实现的是如下的功能，通过这个案例能很好的理解位置无关代码与函数调用
```c
int add(int a, int b) {
    return a + b;
}
add(add(11,22),33);
```

```asm
      地址       指令
1  / 0x8000  mov r2,pc      // r2得到当前地址+8的值0x8008
  |  0x8004  add r3,r2,8    // 由r2的值加上程序固定的偏移量就能得到add函数的相对地址
  |  0x8008  add r4,r2,16   // 同理，计算得到一个能绕过add函数的相对地址
   \ 0x800C  bx r4          // 绕过add函数，直接去到0x8018

2  / 0x8010  add r0,r0,r1   // add 函数
   \ 0x8014  bx lr          // 返回到调用处的下一条指令

3  / 0x8018  mov r0,11      // 给add函数传参数a
  |  0x801C  mov r1,22      // 给add函数传参数b
   \ 0x8020  blx r3         // 调用add函数

4  / 0x8024  mov r1,33      // 因为add返回值是通过r0传回的，因此第二次调用时只需传参数b
   \ 0x8028  blx r3         // 再次调用add函数

5    0x802C  mov r0,r0      // 这句相当于什么都没做
```
执行顺序是1=>3=>2=>4=>2=>5，其中第1步正是位置无关代码的关键实现原理

```c
#define ADDRESS 0x8000
int main() {
    uc_engine *uc;
    uint32_t r0;

    // 地址     汇编代码           指令
    // 0x8000  mov r2,pc         0xE1A0200F
    // 0x8004  add r3,r2,8       0xE2823008
    // 0x8008  add r4,r2,16      0xE2824010
    // 0x800C  bx r4             0xE12FFF14
    // 0x8010  add r0,r0,r1      0xE0800001
    // 0x8014  bx lr             0xE12FFF1E
    // 0x8018  mov r0,11         0xE3A0000B
    // 0x801C  mov r1,22         0xE3A01016
    // 0x8020  blx r3            0xE12FFF33
    // 0x8024  mov r1,33         0xE3A01021
    // 0x8028  blx r3            0xE12FFF33
    // 0x802C  mov r0,r0         0xE1A00000
    uint32_t code[] = {0xE1A0200F, 0xE2823008, 0xE2824010, 0xE12FFF14, 0xE0800001, 0xE12FFF1E, 0xE3A0000B, 0xE3A01016, 0xE12FFF33, 0xE3A01021, 0xE12FFF33, 0xE1A00000};

    uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    uc_mem_map(uc, ADDRESS, 1024 * 4, UC_PROT_ALL);
    uc_mem_write(uc, ADDRESS, code, sizeof(code));
    uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(code), 0, 0);
    uc_reg_read(uc, UC_ARM_REG_R0, &r0);
    printf("r0 = %d\n", r0);
    uc_close(uc);
    return 0;
}
```
运行后得到结果 r0 = 66



## 使用unicorn调用函数

使用unicorn的目的当然是为了能够调与目标程序进行通信，既然是通信，那么肯定是双向的，你可以调用目标程序，那反过来目标程序也一定要能够调用你，我们先来看怎么调用目标程序里面的函数

在上个例子中我们知道在0x8010地址处有一个add函数，现在我们来封装它，使它成为一个本地函数供我们的代码使用

```c
#define ADDRESS 0x8000
int32_t add(uc_engine *uc, int32_t a, int32_t b) {
    uint32_t r0, lr;

    // 传参数
    uc_reg_write(uc, UC_ARM_REG_R0, &a);
    uc_reg_write(uc, UC_ARM_REG_R1, &b);

    // 根据函数的调用机制，要求我们必需设置一个返回点，这个返回点正是函数执行完毕的标志
    // 由于函数内部会执行到内存中的什么位置我们是不确定的（在我们这个例子中我们当然知道它会执行到哪里）
    // 并且在uc_emu_start()中也有一个停止点，这个停止点非常强硬，如果pc指针到达这个地址程序就会立刻终止
    // 因此这个地址必需是一个目标函数永远不可能执行到的点，而且这个地址又必需是在已映射的内存范围内
    // 在我这个例子中add函数永远不可能执行到ADDRESS地址，所以我将停止点设置成了ADDRESS，因此当add函数内部经由bx lr返回后
    // pc指针将会到达uc_emu_start()设置的停止点，模拟器才能停止运行，回到我们的代码
    lr = ADDRESS;
    uc_reg_write(uc, UC_ARM_REG_LR, &lr);

    // 在unicorn 1.0.2之前uc_emu_start()在特殊情况下不会在pc==stopAddr时立即停止
    uc_emu_start(uc, 0x8010, lr, 0, 0);  

    uc_reg_read(uc, UC_ARM_REG_R0, &r0); // 获取返回值
    return r0;
}

int main() {
    uc_engine *uc;
    uint32_t code[] = {0xE1A0200F, 0xE2823008, 0xE2824010, 0xE12FFF14, 0xE0800001, 0xE12FFF1E, 0xE3A0000B, 0xE3A01016, 0xE12FFF33, 0xE3A01021, 0xE12FFF33, 0xE1A00000};

    uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    uc_mem_map(uc, ADDRESS, 1024 * 4, UC_PROT_ALL);
    uc_mem_write(uc, ADDRESS, code, sizeof(code));
    printf("%d\n", add(uc, 24, 37));  // 输出61
    printf("%d\n", add(uc, 86, 753)); // 输出839   
    uc_close(uc);
    return 0;
}
```

## 拦截函数调用

上一个案例讲述了由我们调用目标函数的方法，实际上目标函数内部是有可能会有一些系统调用的，系统调用正是双向通信中对方调用我们，该怎么做呢？

还是以之前的函数案例来研究，我们发现在0x8020和0x8028处都调用了add函数，这个函数的地址我们是知道的，如果能实现把add函数调用替换成调用我们另外实现的一个add函数，那不就相当于目标程序调用了系统函数？

CPU是按照PC寄存器指向的地址来执行代码的，因此当PC寄存器指向add函数的地址时，就是我们下手的时机

这里需要增加一个新的unicorn API调用uc_hook_add()，通过这个API实现控制目标程序的各种行为，比如内存读写、指令执行，以及获取unicorn本身的运行状态

```c
#define ADDRESS 0x8000

void add(uc_engine *uc) {
    int32_t a, b, ret;
    uint32_t lr;

    // 获取参数值
    uc_reg_read(uc, UC_ARM_REG_R0, &a);
    uc_reg_read(uc, UC_ARM_REG_R1, &b);

    ret = a + b + 1;

    // 设置返回值
    uc_reg_write(uc, UC_ARM_REG_R0, &ret);

    // 模拟实现bx lr的功能
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);
    uc_reg_write(uc, UC_ARM_REG_PC, &lr);
}

void hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    if (0x8010 == (uint32_t)address) {  // 当模拟器内执行到add函数地址时，进入我们的add函数进行处理
        add(uc);
    }
}

int main() {
    uc_engine *uc;
    uc_hook hh;
    uint32_t r0;

    uint32_t code[] = {0xE1A0200F, 0xE2823008, 0xE2824010, 0xE12FFF14, 0xE0800001, 0xE12FFF1E, 0xE3A0000B, 0xE3A01016, 0xE12FFF33, 0xE3A01021, 0xE12FFF33, 0xE1A00000};

    uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    uc_mem_map(uc, ADDRESS, 1024 * 4, UC_PROT_ALL);
    uc_mem_write(uc, ADDRESS, code, sizeof(code));

    // 这里我在整个代码地址范围内加上单条指令的hook，每次执行这个地址范围内的指令前都会回调我们的hook函数
    // 如果你可以很明确的知道在哪个地址范围内需要hook，设置一个准确的地址范围能提升程序的运行效率
    uc_hook_add(uc, &hh, UC_HOOK_CODE, hook, NULL, ADDRESS, ADDRESS + sizeof(code));

    uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(code), 0, 0);

    uc_reg_read(uc, UC_ARM_REG_R0, &r0);
    printf("r0 = %d\n", r0);
    uc_close(uc);
    return 0;
}
```

由于我们实现的add函数每次都会额外+1，所以原本的结果应该是66现在变成了68

之前：(11+22)+33=66

之后：(11+22+1)+33+1=68

## 内存管理


## 可变参数的函数调用






























