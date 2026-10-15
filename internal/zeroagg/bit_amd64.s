#include "textflag.h"
TEXT ·CanonicalBit(SB), NOSPLIT, $0-10
 MOVBLZX v+0(FP), AX
 MOVW AX, ret+8(FP)
 RET
