#include <stdio.h>
#include <stdint.h>
#include "./unicorn-1.0.2-win32/include/unicorn/unicorn.h"

#define ADDRESS 0x8000

int32_t add(uc_engine *uc, int32_t a, int32_t b) {
    uint32_t r0, lr;

    // 传参数
    uc_reg_write(uc, UC_ARM_REG_R0, &a);
    uc_reg_write(uc, UC_ARM_REG_R1, &b);

    // 根据函数的调用机制，要求我们必需设置一个返回点，这个返回点正是函数执行完毕的标志
    // 由于函数内部会执行到内存中的什么位置我们是不确定的（在我们这个例子中我们当然知道它会执行到哪里）
    // 并且在uc_emu_start()中也有一个停止点，这个停止点非常强硬，如果pc指针与这个值相同程序就会立刻终止
    // 因此这个地址必需是一个目标函数永远不可能执行到的点，而且这个地址又必需是在已映射的内存范围内
    // 因为在这个例子中add函数永远不可能执行到ADDRESS地址，因此当add函数内部经由bx lr返回后
    // pc指针到达uc_emu_start()设置的停止点，模拟器才能停止运行
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