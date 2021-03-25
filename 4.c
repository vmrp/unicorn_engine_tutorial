#include <stdio.h>
#include <stdint.h>
#include "./unicorn-1.0.2-win32/include/unicorn/unicorn.h"

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