#include <stdio.h>
#include <stdint.h>
#include "./unicorn-1.0.2-win32/include/unicorn/unicorn.h"

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