#include <iostream>
#include "ppc/ppc_recomp_shared.h"

#include "memory.h"

int main() {
    auto buffer = new uint8_t[0xFFFFFFFF];
    PPCContext ctx;
    ctx.r1.u32 = 0xFFFFFFFF;
    ctx.r13.u32 = 0x0;
    ctx.fpscr.loadFromHost();

   _xstart(ctx, buffer);

   return 0;
}
