// Compile-time knobs and 16-bit call-return register overrides used by CompileBlock.cpp.
#pragma once

#include <cstdint>

// Register values a 16-bit (NE) trap bridge may apply after a host call returns.
struct FarRegisterOverrides {
    bool setEs = false, setBx = false, setCx = false, setDx = false, setSi = false, setDi = false;
    uint16_t es = 0, bx = 0, cx = 0, dx = 0, si = 0, di = 0;
    void Reset() { *this = FarRegisterOverrides{}; }
};

extern FarRegisterOverrides g_farRegisterOverrides;
extern int g_jitMaxBlockSize;     // 0 = the compiler's default
extern bool g_jitDisableChaining;
extern bool g_jitEagerFlags;      // HLEKIT_JIT_EAGER_FLAGS: re-seed host flags at every instruction
