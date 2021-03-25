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