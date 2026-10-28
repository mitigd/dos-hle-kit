// The x86 translation compiler: Zydis decodes a basic block, AsmJit emits host x86-64 code.
// Static FPU helpers and diagnostics used by the emitted code live here too.
#include "../JitEngine.h"
#include "../JitPlatform.h"
#include "../JitLog.h"
#include "../Common/Log.h"
#include <asmjit/asmjit.h>
#include <Zydis/Zydis.h>
#include <string>
#include <cstring>
#include <cmath>
#include <iostream>
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif
// FPU rounding is emitted inline in JIT blocks.
// Fast-path knobs, settable from the environment (see Engine.cpp).
extern int  g_jitMaxBlockSize;
extern bool g_jitEagerFlags;
extern bool g_jitDisableChaining;

#ifndef NDEBUG
static constexpr bool kJitChainStatsEnabled = true;
#else
static constexpr bool kJitChainStatsEnabled = false;
#endif

// ============================================================

using namespace asmjit;
using namespace asmjit::x86;

// ---------------------------------------------------------------------------
// Host calling convention.
//
// Generated blocks call back into C++ helpers.  Win64 passes the first four
// integer arguments in RCX/RDX/R8/R9; SysV (Linux/macOS) passes the first six
// in RDI/RSI/RDX/RCX/R8/R9.  Blocks are emitted against the Win64 registers and
// EmitHostAbiArgs() moves them into the SysV positions immediately before the
// call, so every existing call site keeps its Win64-shaped setup code.
//
// The move order matters: each register is read before the move that overwrites
// it (RDX is saved into RSI before R8 lands in RDX; RCX into RDI before R9
// lands in RCX), so no argument is clobbered in transit.
//
// Floating-point arguments are deliberately NOT handled here.  Win64 assigns
// XMM slots positionally alongside integer slots, while SysV counts the integer
// and SSE sequences independently, so a mixed signature such as
// HostFsin(double, uint16_t*) puts its pointer in RDX on Win64 but RDI on SysV.
// Those sites are mapped by hand where they are emitted.
//
// Also note RSI/RDI are callee-saved on Win64 but caller-saved on SysV: any
// site holding live guest state in them across a host call must save them
// itself (see the DOS VRAM string-operation helpers).
// ---------------------------------------------------------------------------
static inline void EmitHostAbiArgs(x86::Assembler &a)
{
#ifndef _WIN32
    a.mov(rdi, rcx); // arg1
    a.mov(rsi, rdx); // arg2
    a.mov(rdx, r8);  // arg3
    a.mov(rcx, r9);  // arg4
#else
    (void)a;
#endif
}


class JitAsmErrorHandler final : public ErrorHandler
{
public:
    Error error = kErrorOk;
    std::string message;

    void handleError(Error err, const char* text, BaseEmitter*) override
    {
        if (error != kErrorOk)
            return;
        error = err;
        message = text ? text : DebugUtils::errorAsString(err);
    }
};

static bool JitConsumeDeferredTrapReturn(JitEngine* engine)
{
    return engine->ConsumeDeferredTrapReturn();
}

static bool HostVerifySelector(JitEngine* engine, uint32_t selector, uint32_t write)
{
    return engine->VerifySelectorAccess((uint16_t)selector, write != 0);
}

static void HostCpuid(JitEngine::CpuContext *ctx)
{
    uint32_t inputEax = ctx->eax;
    uint32_t inputEcx = ctx->ecx;

    int cpuInfo[4] = {0};
#ifdef _MSC_VER
    __cpuidex(cpuInfo, inputEax, inputEcx);
#else
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __cpuid_count(inputEax, inputEcx, eax, ebx, ecx, edx);
    cpuInfo[0] = static_cast<int>(eax);
    cpuInfo[1] = static_cast<int>(ebx);
    cpuInfo[2] = static_cast<int>(ecx);
    cpuInfo[3] = static_cast<int>(edx);
#endif

    if (inputEax == 0)
    {
        ctx->eax = 0xd;        // highest basic CPUID leaf
        ctx->ebx = 0x756e6547; // "Genu"
        ctx->edx = 0x49656e69; // "ineI"
        ctx->ecx = 0x6c65746e; // "ntel"
    }
    else if (inputEax == 1)
    {
        ctx->eax = 0x306c4; // Haswell model signature
        ctx->ebx = 0x00000800;
        ctx->ecx = 0xced82203; // Haswell feature flags
        ctx->edx = 0x78bfbfd;  // Haswell feature flags
    }
    else if (inputEax == 2)
    {
        ctx->eax = 0x41060101;
        ctx->ebx = 0x00000000;
        ctx->ecx = 0x00000000;
        ctx->edx = 0x00000000;
    }
    else if (inputEax >= 3 && inputEax <= 0xd)
    {
        ctx->eax = 0;
        ctx->ebx = 0;
        ctx->ecx = 0;
        ctx->edx = 0;
    }
    else
    {
        ctx->eax = cpuInfo[0];
        ctx->ebx = cpuInfo[1];
        ctx->ecx = cpuInfo[2];
        ctx->edx = cpuInfo[3];
    }
}

static double HostAtan2(double y, double x)
{
    return std::atan2(y, x);
}

static void HostSetFpuDivideByZeroStatus(double divisor, uint16_t* fpuStatus)
{
    if (!fpuStatus) return;
    if (divisor == 0.0) {
        *fpuStatus |= 0x0004; // ZE: divide-by-zero exception flag
    }
}

static void StoreFloat80(uint8_t *destination, double value)
{
    uint64_t bits = 0;
    memcpy(&bits, &value, sizeof(bits));

    const uint16_t sign = (bits >> 63) ? 0x8000u : 0;
    const uint16_t doubleExponent = (uint16_t)((bits >> 52) & 0x7FFu);
    const uint64_t fraction = bits & 0x000FFFFFFFFFFFFFULL;
    uint16_t extendedExponent = sign;
    uint64_t significand = 0;

    if (doubleExponent == 0x7FFu)
    {
        extendedExponent |= 0x7FFFu;
        significand = fraction
                          ? (0xC000000000000000ULL | (fraction << 11))
                          : 0x8000000000000000ULL;
    }
    else if (doubleExponent != 0)
    {
        extendedExponent |= (uint16_t)(doubleExponent - 1023 + 16383);
        significand = 0x8000000000000000ULL | (fraction << 11);
    }
    else if (fraction != 0)
    {
        int highestBit = 51;
        while ((fraction & (1ULL << highestBit)) == 0)
            --highestBit;

        const int unbiasedExponent = highestBit - 1074;
        extendedExponent |= (uint16_t)(unbiasedExponent + 16383);
        significand = fraction << (63 - highestBit);
    }

    memcpy(destination, &significand, sizeof(significand));
    memcpy(destination + 8, &extendedExponent, sizeof(extendedExponent));
}

static uint16_t HostFxam(double val)
{
    uint16_t c = 0;
    bool sign = std::signbit(val);
    if (sign)
        c |= (1 << 9);
    int fpClass = std::fpclassify(val);
    switch (fpClass)
    {
    case FP_NAN:
        c |= (1 << 8);
        break;
    case FP_INFINITE:
        c |= (1 << 8) | (1 << 10);
        break;
    case FP_ZERO:
        c |= (1 << 14);
        break;
    case FP_SUBNORMAL:
        c |= (1 << 10) | (1 << 14);
        break;
    case FP_NORMAL:
    default:
        c |= (1 << 10);
        break;
    }
    return c;
}

static double HostFcos(double val, uint16_t *fpuStatus)
{
    if (std::abs(val) >= 9223372036854775808.0)
    {
        if (fpuStatus)
            *fpuStatus |= (1 << 10);
        return val;
    }
    else
    {
        if (fpuStatus)
            *fpuStatus &= ~(1 << 10);
        return std::cos(val);
    }
}

// x87 FPREM: returns ST0 mod ST1 (remainder with truncation toward zero)
static double HostFprem(double st0, double st1)
{
    // C2=0 (complete) handled by caller
    return std::fmod(st0, st1);
}

// x87 F2XM1: returns 2^ST0 - 1
static double HostF2xm1(double st0)
{
    return std::pow(2.0, st0) - 1.0;
}

// x87 FSCALE: returns ST0 * 2^trunc(ST1)
static double HostFscale(double st0, double st1)
{
    return st0 * std::pow(2.0, std::trunc(st1));
}

// x87 FYL2X: returns ST(1) * log2(ST(0))
static double HostFyl2x(double st1, double st0)
{
    return st1 * std::log2(st0);
}

// x87 FPTAN: returns tan(ST(0)), sets C2 if argument out of range
static double HostFptan(double val, uint16_t *fpuStatus)
{
    if (std::abs(val) >= 9223372036854775808.0)
    {
        if (fpuStatus)
            *fpuStatus |= (1 << 10);
        return val;
    }
    else
    {
        if (fpuStatus)
            *fpuStatus &= ~(1 << 10);
        return std::tan(val);
    }
}

static double HostFsin(double val, uint16_t *fpuStatus)
{
    if (std::abs(val) >= 9223372036854775808.0)
    {
        if (fpuStatus)
            *fpuStatus |= (1 << 10);
        return val;
    }
    else
    {
        if (fpuStatus)
            *fpuStatus &= ~(1 << 10);
        return std::sin(val);
    }
}

static void LogFicom(double st0, int32_t memVal)
{
    LOG_INFO << "[JIT FICOM] ST(0)=" << st0 << " MEM=" << memVal << "\n";
}

static void LogIndirectCall(JitEngine *engine, uint32_t target, uint32_t retAddr)
{
    uint32_t trapIndex = 0;
    if (engine->IsTrapAddress(target, trapIndex))
    {
        LOG_INFO << "[JIT] Indirect Call to TRAP 0x" << std::hex << target << " (Index " << trapIndex << ") from " << retAddr << std::dec << "\n";
    }
    else
    {
        LOG_INFO << "[JIT] Indirect Call to 0x" << std::hex << target << " from " << retAddr << std::dec << "\n";
    }
}

// Runtime helper: resolve (selector, offset) to linear address for 16-bit NE/MZ.
// Called from JIT-compiled code via asmjit.
static uint32_t JitGetLinearAddress(JitEngine *engine, uint16_t selector, uint32_t offset)
{
    auto *ctx = (JitEngine::CpuContext *)engine->GetEngineContext();
    ctx->csBase = engine->GetLinearAddress(selector, 0);
    return ctx->csBase + offset;
}

// DAS adjusts AL after packed-BCD subtraction.  Return adjusted EAX in the
// low dword and EFLAGS in the high dword; OF is undefined, so preserve it.
static uint64_t JitDas(uint32_t eax, uint32_t eflags)
{
    const uint8_t oldAl = (uint8_t)eax;
    const bool oldCf = (eflags & 0x001u) != 0;
    const bool oldAf = (eflags & 0x010u) != 0;
    uint8_t al = oldAl;
    bool af = false;
    bool cf = false;

    if ((oldAl & 0x0F) > 9 || oldAf) {
        al = (uint8_t)(al - 0x06);
        af = true;
    }
    if (oldAl > 0x99 || oldCf) {
        al = (uint8_t)(al - 0x60);
        cf = true;
    }

    constexpr uint32_t kDasFlags = 0x001u | 0x010u | 0x004u | 0x040u | 0x080u;
    eflags &= ~kDasFlags;
    if (cf) eflags |= 0x001u;
    if (af) eflags |= 0x010u;
    if (al == 0) eflags |= 0x040u;
    if (al & 0x80) eflags |= 0x080u;
    uint8_t bits = al;
    bits ^= bits >> 4;
    bits ^= bits >> 2;
    bits ^= bits >> 1;
    if ((bits & 1) == 0) eflags |= 0x004u;

    eax = (eax & 0xFFFFFF00u) | al;
    return ((uint64_t)eflags << 32) | eax;
}

static void JitWriteDosVram(JitEngine* engine, uint32_t linearAddress, uint32_t byteCount, uint32_t guestEip)
{
    engine->WriteDosVram(linearAddress, byteCount, guestEip);
}

static void JitReadDosVram(JitEngine* engine, uint32_t linearAddress, uint32_t byteCount)
{
    engine->ReadDosVram(linearAddress, byteCount);
}

// AAA adjusts unpacked BCD after addition. Only AF and CF are defined; all
// other flags retain their prior values.
static uint64_t JitAaa(uint32_t eax, uint32_t eflags)
{
    uint16_t ax = (uint16_t)eax;
    const bool adjust = ((ax & 0x000F) > 9) || ((eflags & 0x010u) != 0);

    if (adjust) {
        ax = (uint16_t)(ax + 0x0106);
        eflags |= 0x001u | 0x010u; // CF, AF
    } else {
        eflags &= ~(0x001u | 0x010u); // CF, AF
    }

    ax &= 0xFF0Fu;
    eax = (eax & 0xFFFF0000u) | ax;
    return ((uint64_t)eflags << 32) | eax;
}

// Runtime helper: memory-indirect far jump. Resolves [segment:offset] guest memory
// to a far pointer (4 bytes: IP, CS), then sets the code selector, base, and EIP.
// Called from JIT-compiled code with the linear address already computed.
static void JitFarJumpMemIndirectLinear(JitEngine *engine, uint32_t linearAddr)
{
    auto *ctx = (JitEngine::CpuContext *)engine->GetEngineContext();
    uint8_t *mem = (uint8_t *)engine->GetPointer(linearAddr);
    uint16_t ip = 0, cs = 0;
    if (mem && linearAddr < engine->GetMemorySize() - 3)
    {
        ip = *(uint16_t *)mem;
        cs = *(uint16_t *)(mem + 2);
    }
    ctx->cs = cs;
    ctx->csBase = engine->GetLinearAddress(cs, 0);
    ctx->eip = engine->GetLinearAddress(cs, ip);
}

// Runtime helper: memory-indirect far CALL.
// Reads [linearAddr] far pointer (4 bytes: IP, CS), pushes return CS:IP
// onto guest stack (SS:SP via ctx->ssBase), then sets context.cs and eip.
static void JitFarCallMemIndirectLinear(JitEngine *engine, uint32_t linearAddr,
                                          uint32_t retIP, uint16_t retCS)
{
    auto *ctx = (JitEngine::CpuContext *)engine->GetEngineContext();
    uint8_t *mem = (uint8_t *)engine->GetPointer(0);
    uint16_t ip = 0, cs = 0;
    if (mem && linearAddr < engine->GetMemorySize() - 3)
    {
        ip = *(uint16_t *)(mem + linearAddr);
        cs = *(uint16_t *)(mem + linearAddr + 2);
    }

    // Push return CS:IP onto guest stack (16-bit, via SS:SP)
    uint32_t sp = (ctx->esp - 2) & 0xFFFF;
    uint32_t stackLinear = ctx->ssBase + sp;
    if (mem && stackLinear + 1 < engine->GetMemorySize())
    {
        *(uint16_t *)(mem + stackLinear) = retCS;
    }
    sp = (sp - 2) & 0xFFFF;
    stackLinear = ctx->ssBase + sp;
    if (mem && stackLinear + 1 < engine->GetMemorySize())
    {
        *(uint16_t *)(mem + stackLinear) = (uint16_t)retIP;
    }
    ctx->esp = sp;

    ctx->cs = cs;
    ctx->csBase = engine->GetLinearAddress(cs, 0);
    ctx->eip = engine->GetLinearAddress(cs, ip);
}

static void JitApplyFarRegisterOverrides(JitEngine::CpuContext *ctx, JitEngine *engine)
{
    if (g_farRegisterOverrides.setEs)
    {
        ctx->es = g_farRegisterOverrides.es;
        ctx->esBase = engine->GetLinearAddress(g_farRegisterOverrides.es, 0);
        LOG_DEBUG << "[JIT DEBUG] Apply ES=0x" << std::hex << ctx->es << " Base=0x" << ctx->esBase << std::dec << std::endl;
    }
    if (g_farRegisterOverrides.setBx)
        ctx->ebx = (ctx->ebx & 0xFFFF0000) | g_farRegisterOverrides.bx;
    if (g_farRegisterOverrides.setCx)
        ctx->ecx = (ctx->ecx & 0xFFFF0000) | g_farRegisterOverrides.cx;
    if (g_farRegisterOverrides.setDx)
        ctx->edx = (ctx->edx & 0xFFFF0000) | g_farRegisterOverrides.dx;
    if (g_farRegisterOverrides.setSi)
        ctx->esi = (ctx->esi & 0xFFFF0000) | g_farRegisterOverrides.si;
    if (g_farRegisterOverrides.setDi)
        ctx->edi = (ctx->edi & 0xFFFF0000) | g_farRegisterOverrides.di;
    g_farRegisterOverrides.Reset();
}

void *JitEngine::CompileBlock(uint32_t startEip)
{
    BlockLogHelper log;
    struct ExitPatch {
        uint32_t targetEip;
        Label pointerLabel;
        Label slowPathLabel;
    };
    std::vector<ExitPatch> exitPatches;
    // Check if we are in the trap page
    if (startEip >= trapPageBase && startEip < trapPageBase + 0x10000)
    {
        uint32_t trapIndex = (startEip - trapPageBase) / 8;
        if (trapIndex < traps.size())
        {
            const auto &trap = traps[trapIndex];
            log.buffer << "[JIT] Compiling API Bridge for " << trap.library << "!" << trap.function << "\n";

            CodeHolder code;
            code.init(jitRuntime.environment());
            x86::Assembler a(&code);
            JitAsmErrorHandler asmError;
            a.setErrorHandler(&asmError);
            Label trapEpilogue = a.newLabel();

            // Prologue: Save non-volatile registers
            a.push(r15);
            a.push(r14);
            a.push(r13);
            a.push(r12);

            // Incoming arguments: (CpuContext*, uint8_t* guestMemory, JitEngine*).
#ifdef _WIN32
            a.mov(r15, rcx); // CpuContext*
            a.mov(r14, rdx); // uint8_t* guestMemory
            a.mov(r13, r8);  // JitEngine* engine
#else
            a.mov(r15, rdi); // CpuContext*
            a.mov(r14, rsi); // uint8_t* guestMemory
            a.mov(r13, rdx); // JitEngine* engine
#endif

            if (isNE)
            {
                // ── 16-bit NE trap bridge ──
                // Stack layout: [IP(2)] [CS(2)] [arg0(2)] [arg1(2)] ...
                // Host stub expects a single pointer to a reversed uint32_t[16] array containing arguments.
                // Alloc 32 bytes shadow space + 64 bytes for reversed array = 96 bytes.
                // After 4 pushes (-32), RSP is 8 mod 16. allocSize must be
                // 8 mod 16 to align RSP to 0 mod 16 before the host stub call.
                uint32_t allocSize = 104;  // 96 rounded up to 8 mod 16
                a.sub(rsp, allocSize);

                // r10 = Guest Stack Pointer (Host Address) = guestMemory + ssBase + (esp & 0xFFFF)
                a.mov(r10d, dword_ptr(r15, offsetof(CpuContext, esp)));
                a.movzx(r10d, r10w);
                a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                a.add(r10, r14);
                a.add(r10, r11);

                // Save original 16-bit return address (IP:CS) before host stub may ChainExec
                a.movzx(r12d, word_ptr(r10, 0));  // IP
                a.movzx(eax, word_ptr(r10, 2));   // CS
                a.shl(eax, 16);
                a.or_(r12d, eax);                 // r12d = IP | (CS << 16)

                // Read args from guest stack, reverse them, and store into the array at [rsp + 32]
                for (uint32_t i = 0; i < 16; i++)
                {
                    if (i < trap.argCount)
                    {
                        int argOffset = 4 + (trap.argCount - 1 - i) * 2;
                        a.movzx(eax, word_ptr(r10, argOffset));
                        a.mov(dword_ptr(rsp, 32 + i * 4), eax);
                    }
                    else
                    {
                        a.mov(dword_ptr(rsp, 32 + i * 4), 0);
                    }
                }

                // Pass pointer to the reversed array in the first argument register.
#ifdef _WIN32
                a.lea(rcx, dword_ptr(rsp, 32));
#else
                a.lea(rdi, dword_ptr(rsp, 32));
#endif

                a.cld(); // restore host ABI direction flag before calling host stub
                if (trap.hostStub) {
                    a.call((uint64_t)trap.hostStub);
                } else {
                    // Fallback trap for an import we have no implementation for.
                    // Returning zero is what that trap promises; emitting the
                    // call anyway would jump the guest to address 0.
                    a.xor_(eax, eax);
                }
                a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);

                a.sub(rsp, 32);
                a.mov(rcx, r13);
                a.mov(rax, (uint64_t)JitConsumeDeferredTrapReturn);
                EmitHostAbiArgs(a);
                a.call(rax);
                a.add(rsp, 32);
                Label neReturnNow = a.newLabel();
                a.test(al, al);
                a.jz(neReturnNow);

                a.add(rsp, allocSize);
                a.jmp(trapEpilogue);

                // Apply 16-bit call-return register overrides
                a.bind(neReturnNow);
                a.mov(rcx, r15); // ctx
                a.mov(rdx, r13); // engine
                a.mov(rax, (uint64_t)JitApplyFarRegisterOverrides);
                EmitHostAbiArgs(a);
                a.call(rax);

                a.add(rsp, allocSize);

                // Restore return address from saved IP:CS (r12d = IP | CS<<16)
                // Save current ESP for adjustment below
                a.mov(r10d, dword_ptr(r15, offsetof(CpuContext, esp)));
                a.movzx(r10d, r10w);
                // Unpack: r9d = CS, r8d = IP
                a.mov(r9d, r12d);
                a.shr(r9d, 16);
                a.mov(r8d, r12d);
                a.movzx(r8d, r8w);
                a.mov(word_ptr(r15, offsetof(CpuContext, cs)), r9w);

                // Resolve linear address via helper
                a.sub(rsp, 40);
                a.mov(rcx, r13);  // engine*
                a.mov(edx, r9d);  // CS
                // r8d already holds IP from unpack above
                a.mov(rax, (uint64_t)JitGetLinearAddress);
                EmitHostAbiArgs(a);
                a.call(rax);
                a.add(rsp, 40);
                a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), eax);

                // Adjust ESP: ret addr(4) + argCount*2 for stdcall, or just 4 for cdecl
                uint32_t nePopSize = 4 + (trap.isCdecl ? 0 : trap.argCount * 2);
                a.lea(r10d, dword_ptr(r10d, nePopSize));
                a.movzx(r10d, r10w);
                a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r10d);
            }
            else
            {
                // ── 32-bit PE trap bridge (existing) ──
                // Win64 takes 4 arguments in registers and needs 32 bytes of shadow
                // space; SysV takes 6 and needs none.  Everything past that is
                // written to the outgoing stack area, which starts right at RSP on
                // SysV but above the shadow space on Win64.
#ifdef _WIN32
                const uint32_t kRegisterArgs = 4;
                const uint32_t kStackArgBase = 32;
#else
                const uint32_t kRegisterArgs = 6;
                const uint32_t kStackArgBase = 0;
#endif
                uint32_t stackArgs = (trap.argCount > kRegisterArgs) ? (trap.argCount - kRegisterArgs) : 0;
                uint32_t allocSize = kStackArgBase + stackArgs * 8;
                // After 4 pushes (-32), RSP is 8 mod 16. allocSize must be
                // 8 mod 16 so the sub brings RSP to 0 mod 16 for the call.
                if ((allocSize % 16) != 8)
                    allocSize += 8;
                a.sub(rsp, allocSize);

                a.mov(r10d, dword_ptr(r15, offsetof(CpuContext, esp)));
                a.add(r10, r14);
                a.mov(r12d, dword_ptr(r10, 0));  // save original return address

                // Guest arguments are 32-bit; each is zero-extended into its
                // argument register (a 32-bit mov clears the upper half).
#ifdef _WIN32
                static const x86::Gp kArgRegs[] = {ecx, edx, r8d, r9d};
#else
                static const x86::Gp kArgRegs[] = {edi, esi, edx, ecx, r8d, r9d};
#endif
                for (uint32_t i = 0; i < trap.argCount; i++)
                {
                    int argOffset = 4 + i * 4;
                    if (i < kRegisterArgs)
                        a.mov(kArgRegs[i], dword_ptr(r10, argOffset));
                    else
                    {
                        a.mov(eax, dword_ptr(r10, argOffset));
                        a.mov(qword_ptr(rsp, kStackArgBase + (i - kRegisterArgs) * 8), rax);
                    }
                }
#ifndef _WIN32
                // A variadic host stub reads AL for the count of SSE arguments;
                // every guest argument here is an integer.
                a.xor_(eax, eax);
#endif

                a.cld(); // restore host ABI direction flag before calling host stub
                if (trap.hostStub) {
                    a.call((uint64_t)trap.hostStub);
                } else {
                    // Fallback trap for an import we have no implementation for.
                    // Returning zero is what that trap promises; emitting the
                    // call anyway would jump the guest to address 0.
                    a.xor_(eax, eax);
                }
                a.add(rsp, allocSize);
                a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);

                // allocSize is already unwound here, so RSP is back at the bridge
                // body (16n + 8) and needs 40 to realign -- unlike the 16-bit path
                // above, which still holds allocSize and uses 32.
                a.sub(rsp, 40);
                a.mov(rcx, r13);
                a.mov(rax, (uint64_t)JitConsumeDeferredTrapReturn);
                EmitHostAbiArgs(a);
                a.call(rax);
                a.add(rsp, 40);
                a.test(al, al);
                a.jnz(trapEpilogue);

                // Read 32-bit return address (use saved original, not stack which may
                // have been modified by ChainExec)
                a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));
                a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), r12d);

                uint32_t popSize = 4;
                if (!trap.isCdecl)
                    popSize += trap.argCount * 4;
                a.lea(r8d, dword_ptr(r8d, popSize));
                a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
            }

            // Epilogue
            a.bind(trapEpilogue);
            a.cld();
            a.pop(r12);
            a.pop(r13);
            a.pop(r14);
            a.pop(r15);
            a.ret();

            if (asmError.error != kErrorOk)
            {
                log.isError = true;
                log.buffer << "[JIT] AsmJit trap emit error at guest EIP 0x"
                           << std::hex << startEip << ": " << asmError.message
                           << " (" << std::dec << asmError.error << ")\n";
                return nullptr;
            }

            void *fnPtr = nullptr;
            Error err = jitRuntime.add(&fnPtr, &code);
            if (err)
            {
                log.isError = true;
                log.buffer << "[JIT] AsmJit trap finalize error at guest EIP 0x"
                           << std::hex << startEip << ": "
                           << DebugUtils::errorAsString(err) << " ("
                           << std::dec << err << ")\n";
                return nullptr;
            }
            CachedBlock tblock = {fnPtr, nullptr}; // Trap bridges must return through C++ loop
            StoreBlock(startEip, startEip + 1, tblock, {});
            return fnPtr;
        }
        else
        {
            log.isError = true;
            log.buffer << "[JIT] ERROR: Trap page address 0x" << std::hex << startEip
                       << " has trapIndex " << trapIndex << " but only " << std::dec << traps.size() << " traps registered\n";
            return nullptr;
        }
    }

    log.buffer << "[JIT] Compiling block at 0x" << std::hex << startEip << std::dec << "\n";

    CodeHolder code;
    code.init(jitRuntime.environment());
    x86::Assembler a(&code);
    JitAsmErrorHandler asmError;
    a.setErrorHandler(&asmError);

    // Prologue: Save non-volatile registers
    a.push(rbx);
    a.push(rbp);
    a.push(rdi);
    a.push(rsi);
    a.push(r12);
    a.push(r13);
    a.push(r14);
    a.push(r15);

    // Incoming arguments: (CpuContext*, uint8_t* guestMemory, JitEngine*).
#ifdef _WIN32
    a.mov(r15, rcx); // R15 = Context pointer
    a.mov(r14, rdx); // R14 = Guest memory base
    a.mov(r13, r8);  // R13 = JitEngine*
#else
    a.mov(r15, rdi); // R15 = Context pointer
    a.mov(r14, rsi); // R14 = Guest memory base
    a.mov(r13, rdx); // R13 = JitEngine*
#endif

    // Restore guest Flags
    a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eflags)));
    a.push(r8);
    a.popfq();

    // Hot entry point for chained blocks (skips prologue register save/restore).
    // r15, r14, r13 are preserved from the chaining block.
    Label hotEntry = a.newLabel();
    a.bind(hotEntry);

    // Lambda: emit block-end logic with direct chaining if target is already cached.
    auto emitReturnToRunLoop = [&]()
    {
        a.cld(); // Clear guest Direction Flag to restore host ABI contract before returning to C++
        a.pop(r15);
        a.pop(r14);
        a.pop(r13);
        a.pop(r12);
        a.pop(rsi);
        a.pop(rdi);
        a.pop(rbp);
        a.pop(rbx);
        a.ret();
    };

    // Capture host flags into r11 and publish them as the guest's, preserving IF
    // and DF from CpuContext.
    //
    // CLD/STD/CLI/STI edit CpuContext::eflags directly and never touch the host
    // flags register — IF cannot even be mirrored there from user mode. A plain
    // "pushfq -> eflags" therefore erases them. That is invisible with one
    // instruction per block, because a block that ends by hitting the size limit
    // returns through emitReturnToRunLoop, which does not republish flags at all.
    // In a multi-instruction block ending on a branch it silently drops the DF
    // that an earlier STD set, and the next STOS/MOVS then walks the wrong way.
    //
    // Leaves r11 holding the raw host flags, which the chaining paths restore.
    auto emitPublishGuestFlags = [&]()
    {
        a.pushfq();
        a.pop(r11);
        a.mov(r10d, dword_ptr(r15, offsetof(CpuContext, eflags)));
        a.and_(r10d, 0x600);  // keep guest IF (0x200) and DF (0x400)
        a.mov(r9d, r11d);
        a.and_(r9d, ~0x600);  // everything else comes from the host flags
        a.or_(r9d, r10d);
        a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r9d);
    };

    auto emitBlockEnd = [&](uint32_t targetEip)
    {
        a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), targetEip);
        // Save guest flags (set by last arithmetic/comparison before branch)
        emitPublishGuestFlags();

        if (!g_jitDisableChaining)
        {
            Label pendingInterruptSlowPath = a.newLabel();
            Label stopRequestSlowPath = a.newLabel();
            Label budgetSlowPath = a.newLabel();
            Label slowPath = a.newLabel();

            // Do not stay inside chained code when a safepoint is required.
            a.cmp(byte_ptr(r15, offsetof(CpuContext, pendingInt)), 0xFF);
            a.jne(pendingInterruptSlowPath);
            a.cmp(byte_ptr(r13, offsetof(JitEngine, smcPending)), 0);   // code was written: resync first
            a.jne(stopRequestSlowPath);
            a.cmp(byte_ptr(r13, offsetof(JitEngine, isRunning)), 0);
            a.je(stopRequestSlowPath);
            a.cmp(dword_ptr(r15, offsetof(CpuContext, chainBudget)), 0);
            a.je(budgetSlowPath);
            a.dec(dword_ptr(r15, offsetof(CpuContext, chainBudget)));
            if constexpr (kJitChainStatsEnabled) {
                a.inc(qword_ptr(r13, offsetof(JitEngine, chainHotJumps)));
            }

            // Safepoint checks clobber host flags. Restore guest flags before hot jump.
            a.push(r11);
            a.popfq();

            // Load from patchable pointer and jump
            Label targetPtrLabel = a.newLabel();
            a.mov(rax, qword_ptr(targetPtrLabel));
            a.jmp(rax);

            a.bind(pendingInterruptSlowPath);
            if constexpr (kJitChainStatsEnabled) {
                a.inc(qword_ptr(r13, offsetof(JitEngine, chainSlowPendingInterruptExits)));
            }
            a.jmp(slowPath);

            a.bind(stopRequestSlowPath);
            if constexpr (kJitChainStatsEnabled) {
                a.inc(qword_ptr(r13, offsetof(JitEngine, chainSlowStopRequestExits)));
            }
            a.jmp(slowPath);

            a.bind(budgetSlowPath);
            if constexpr (kJitChainStatsEnabled) {
                a.inc(qword_ptr(r13, offsetof(JitEngine, chainSlowBudgetExits)));
            }
            a.jmp(slowPath);

            a.bind(slowPath);
            emitReturnToRunLoop();

            // Embed pointer variable inside the code stream
            a.bind(targetPtrLabel);
            a.embedUInt64(0);

            // Record this patchable exit
            exitPatches.push_back({targetEip, targetPtrLabel, slowPath});
        }
        else
        {
            if constexpr (kJitChainStatsEnabled) {
                a.inc(qword_ptr(r13, offsetof(JitEngine, chainSlowCacheMisses)));
            }
            emitReturnToRunLoop();
        }
    };

    std::unordered_map<uint32_t, Label> localBlockLabels;
    auto emitLocalBackEdge = [&](uint32_t targetEip, Label targetLabel)
    {
        Label pendingInterruptSlowPath = a.newLabel();
        Label stopRequestSlowPath = a.newLabel();
        Label budgetSlowPath = a.newLabel();
        Label slowPath = a.newLabel();

        a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), targetEip);
        emitPublishGuestFlags();

        if (g_jitDisableChaining)
        {
            emitReturnToRunLoop();
            return;
        }

        a.cmp(byte_ptr(r15, offsetof(CpuContext, pendingInt)), 0xFF);
        a.jne(pendingInterruptSlowPath);
        a.cmp(byte_ptr(r13, offsetof(JitEngine, smcPending)), 0);
        a.jne(stopRequestSlowPath);
        a.cmp(byte_ptr(r13, offsetof(JitEngine, isRunning)), 0);
        a.je(stopRequestSlowPath);
        a.cmp(dword_ptr(r15, offsetof(CpuContext, chainBudget)), 0);
        a.je(budgetSlowPath);
        a.dec(dword_ptr(r15, offsetof(CpuContext, chainBudget)));
        if constexpr (kJitChainStatsEnabled) {
            a.inc(qword_ptr(r13, offsetof(JitEngine, chainHotJumps)));
        }

        a.push(r11);
        a.popfq();
        a.jmp(targetLabel);

        a.bind(pendingInterruptSlowPath);
        if constexpr (kJitChainStatsEnabled) {
            a.inc(qword_ptr(r13, offsetof(JitEngine, chainSlowPendingInterruptExits)));
        }
        a.jmp(slowPath);

        a.bind(stopRequestSlowPath);
        if constexpr (kJitChainStatsEnabled) {
            a.inc(qword_ptr(r13, offsetof(JitEngine, chainSlowStopRequestExits)));
        }
        a.jmp(slowPath);

        a.bind(budgetSlowPath);
        if constexpr (kJitChainStatsEnabled) {
            a.inc(qword_ptr(r13, offsetof(JitEngine, chainSlowBudgetExits)));
        }
        a.jmp(slowPath);

        a.bind(slowPath);
        emitReturnToRunLoop();
    };

    uint32_t currentEip = startEip;
    bool blockEnded = false;
    int instructionCount = 0;
    const int MAX_BLOCK_SIZE = g_jitMaxBlockSize > 0 ? g_jitMaxBlockSize : 100;

    ZydisDecoder decoder;
    if (isNE || isMZ)
    {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_REAL_16, ZYDIS_STACK_WIDTH_16);
    }
    else
    {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    }
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    // Debug: Disassemble block 0x401ffc
    if (startEip == 0x401ffc)
    {
        LOG_INFO << "[JitEngine] Disassembling block 0x401ffc (Potential Crash Site):" << std::endl;
        ZydisDisassembledInstruction instr2;
        uint32_t offset = 0;
        while (ZYAN_SUCCESS(ZydisDisassembleIntel(
            ZYDIS_MACHINE_MODE_LEGACY_32,
            0,
            guestMemory + startEip + offset,
            15,
            &instr2)))
        {
            LOG_INFO << "  0x" << std::hex << (startEip + offset) << ": " << instr2.text << std::dec << std::endl;
            offset += instr2.info.length;
            if (instr2.info.mnemonic == ZYDIS_MNEMONIC_RET ||
                instr2.info.mnemonic == ZYDIS_MNEMONIC_JMP ||
                offset > 64)
                break;
        }
    }

    auto getRegOffset = [](ZydisRegister reg) -> int
    {
        switch (reg)
        {
        case ZYDIS_REGISTER_EAX:
        case ZYDIS_REGISTER_AX:
        case ZYDIS_REGISTER_AL:
            return offsetof(CpuContext, eax);
        case ZYDIS_REGISTER_AH:
            return offsetof(CpuContext, eax) + 1;
        case ZYDIS_REGISTER_EBX:
        case ZYDIS_REGISTER_BX:
        case ZYDIS_REGISTER_BL:
            return offsetof(CpuContext, ebx);
        case ZYDIS_REGISTER_BH:
            return offsetof(CpuContext, ebx) + 1;
        case ZYDIS_REGISTER_ECX:
        case ZYDIS_REGISTER_CX:
        case ZYDIS_REGISTER_CL:
            return offsetof(CpuContext, ecx);
        case ZYDIS_REGISTER_CH:
            return offsetof(CpuContext, ecx) + 1;
        case ZYDIS_REGISTER_EDX:
        case ZYDIS_REGISTER_DX:
        case ZYDIS_REGISTER_DL:
            return offsetof(CpuContext, edx);
        case ZYDIS_REGISTER_DH:
            return offsetof(CpuContext, edx) + 1;
        case ZYDIS_REGISTER_ESI:
        case ZYDIS_REGISTER_SI:
            return offsetof(CpuContext, esi);
        case ZYDIS_REGISTER_EDI:
        case ZYDIS_REGISTER_DI:
            return offsetof(CpuContext, edi);
        case ZYDIS_REGISTER_EBP:
        case ZYDIS_REGISTER_BP:
            return offsetof(CpuContext, ebp);
        case ZYDIS_REGISTER_ESP:
        case ZYDIS_REGISTER_SP:
            return offsetof(CpuContext, esp);
        case ZYDIS_REGISTER_CS:
            return offsetof(CpuContext, cs);
        case ZYDIS_REGISTER_DS:
            return offsetof(CpuContext, ds);
        case ZYDIS_REGISTER_ES:
            return offsetof(CpuContext, es);
        case ZYDIS_REGISTER_SS:
            return offsetof(CpuContext, ss);
        case ZYDIS_REGISTER_FS:
            return offsetof(CpuContext, fs);
        case ZYDIS_REGISTER_GS:
            return offsetof(CpuContext, gs);
        default:
            return -1;
        }
    };

    auto getFpuStackIndex = [](ZydisRegister reg) -> int
    {
        switch (reg)
        {
        case ZYDIS_REGISTER_ST0:
            return 0;
        case ZYDIS_REGISTER_ST1:
            return 1;
        case ZYDIS_REGISTER_ST2:
            return 2;
        case ZYDIS_REGISTER_ST3:
            return 3;
        case ZYDIS_REGISTER_ST4:
            return 4;
        case ZYDIS_REGISTER_ST5:
            return 5;
        case ZYDIS_REGISTER_ST6:
            return 6;
        case ZYDIS_REGISTER_ST7:
            return 7;
        default:
            return -1;
        }
    };

    auto getSegBaseOffset = [](ZydisRegister reg) -> int
    {
        switch (reg)
        {
        case ZYDIS_REGISTER_CS:
            return offsetof(CpuContext, csBase);
        case ZYDIS_REGISTER_DS:
            return offsetof(CpuContext, dsBase);
        case ZYDIS_REGISTER_ES:
            return offsetof(CpuContext, esBase);
        case ZYDIS_REGISTER_SS:
            return offsetof(CpuContext, ssBase);
        case ZYDIS_REGISTER_FS:
            return offsetof(CpuContext, fsBase);
        case ZYDIS_REGISTER_GS:
            return offsetof(CpuContext, gsBase);
        default:
            return -1;
        }
    };

    auto resolveEffectiveAddressIntoR8 = [&](const ZydisDecodedOperandMem &mem) -> bool
    {
        a.mov(r8d, (uint32_t)mem.disp.value);
        if (mem.base != ZYDIS_REGISTER_NONE)
        {
            int off = getRegOffset(mem.base);
            if (off == -1)
                return false;
            if (isNE || isMZ)
            {
                a.movzx(r10d, word_ptr(r15, off));
                a.lea(r8d, dword_ptr(r8d, r10d));
            }
            else
            {
                a.mov(r10d, dword_ptr(r15, off));
                a.lea(r8d, dword_ptr(r8d, r10d));
            }
        }
        if (mem.index != ZYDIS_REGISTER_NONE)
        {
            int off = getRegOffset(mem.index);
            if (off == -1)
                return false;
            if (isNE || isMZ)
            {
                a.movzx(r10d, word_ptr(r15, off));
            }
            else
            {
                a.mov(r10d, dword_ptr(r15, off));
            }
            if (mem.scale > 1)
            {
                // Use SHL if possible, but actually LEA with scale is better
                // For IMUL replacement (imul clobbers flags), we can use SHL if we save/restore flags,
                // but LEA is the most robust way to avoid clobbering.
                // AsmJit's Mem class handle scale if passed properly.
                // We'll calculate the index contribution using LEA.
                if (mem.scale == 2)
                    a.lea(r10d, dword_ptr(r10d, r10d));
                else if (mem.scale == 4)
                    a.lea(r10d, dword_ptr(0, r10d, 2));
                else if (mem.scale == 8)
                    a.lea(r10d, dword_ptr(0, r10d, 3));
            }
            a.lea(r8d, dword_ptr(r8d, r10d));
        }
        return true;
    };

    auto resolveMemoryIntoR8 = [&](const ZydisDecodedOperandMem &mem) -> bool
    {
        if (!resolveEffectiveAddressIntoR8(mem))
            return false;
        if (isNE || isMZ)
        {
            a.movzx(r8d, r8w);
        }
        if (mem.segment == ZYDIS_REGISTER_FS)
        {
            a.mov(r10d, dword_ptr(r15, offsetof(CpuContext, fsBase)));
            a.lea(r8d, dword_ptr(r8d, r10d));
        }
        else if (mem.segment == ZYDIS_REGISTER_GS)
        {
            a.mov(r10d, dword_ptr(r15, offsetof(CpuContext, gsBase)));
            a.lea(r8d, dword_ptr(r8d, r10d));
        }
        else if (isMZ)
        {
            // Real-mode: segment base = seg * 16
            ZydisRegister seg = mem.segment;
            if (seg == ZYDIS_REGISTER_NONE)
            {
                if (mem.base == ZYDIS_REGISTER_BP || mem.base == ZYDIS_REGISTER_EBP ||
                    mem.base == ZYDIS_REGISTER_SP || mem.base == ZYDIS_REGISTER_ESP)
                {
                    seg = ZYDIS_REGISTER_SS;
                }
                else
                {
                    seg = ZYDIS_REGISTER_DS;
                }
            }
            int off = getRegOffset(seg);
            if (off != -1)
            {
                a.movzx(r10d, word_ptr(r15, off));
                // seg * 16, via LEA rather than SHL. Guest flags live in the
                // host flags register for the whole block — conditional jumps
                // emit a bare a.jz/a.jb and read them directly — so any scratch
                // arithmetic here silently rewrites the guest's flags. A SHL
                // between a CMP and its Jcc sends the branch the wrong way.
                // resolveEffectiveAddressIntoR8 above avoids IMUL/SHL for
                // exactly this reason; this path has to match it.
                a.lea(r10d, dword_ptr(0, r10d, 3)); // seg * 8
                a.lea(r10d, dword_ptr(r10d, r10d)); // seg * 16
                a.lea(r8d, dword_ptr(r8d, r10d));
            }
        }
        else if (isNE)
        {
            ZydisRegister seg = mem.segment;
            if (seg == ZYDIS_REGISTER_NONE)
            {
                if (mem.base == ZYDIS_REGISTER_BP || mem.base == ZYDIS_REGISTER_EBP ||
                    mem.base == ZYDIS_REGISTER_SP || mem.base == ZYDIS_REGISTER_ESP)
                {
                    seg = ZYDIS_REGISTER_SS;
                }
                else
                {
                    seg = ZYDIS_REGISTER_DS;
                }
            }
            int off = getSegBaseOffset(seg);
            if (off != -1)
            {
                a.mov(r10d, dword_ptr(r15, off));
                a.lea(r8d, dword_ptr(r8d, r10d));
            }
        }
        return true;
    };

    // Mirror a guest store that landed in the 0xA0000 VGA aperture into the
    // planar shadow buffers. On EGA/VGA the byte the CPU stores is not pixel
    // data: the map mask, set/reset and bit mask registers decide which of the
    // four planes receive which bits, and the renderer reads those planes - not
    // guest memory. Every store site that can reach video memory calls this.
    // Emit it *after* the store, so guestMemory already holds the raw byte
    // WriteDosVram reads back.
    //
    // addr32 holds the linear guest address; it must not be eax/ecx/edx.  All
    // volatile registers are preserved because callers keep loop counters,
    // segment bases and store values live across this sequence.
    auto emitDosVramMirror = [&](const asmjit::x86::Gp &addr32, int byteCount)
    {
        if (!isMZ)
            return;

        Label skip = a.newLabel();
        a.pushfq();
        a.cmp(addr32, 0xA0000);
        a.jb(skip);
        a.cmp(addr32, 0xB0000);
        a.jae(skip);

        a.push(rax);
        a.push(rcx);
        a.push(rdx);
        a.push(r8);
        a.push(r9);
        a.push(r10);
        a.push(r11);
        // These helpers run inside STOS/MOVS sequences, where RSI/RDI hold the
        // live guest string pointers. They are callee-saved on Win64 but
        // caller-saved on SysV, so on SysV the host call may clobber them.
#ifndef _WIN32
        a.push(rsi);
        a.push(rdi);
#endif

        a.mov(edx, addr32); // arg 2, before rcx/r8 are overwritten below
        // Stack alignment at this point depends on how the surrounding handler
        // got here (STOS/MOVS run inside a pushfq), so align explicitly rather
        // than assuming the usual "sub rsp, 40" cadence holds.
        a.mov(rax, rsp);
        a.and_(rsp, -16);
        a.sub(rsp, 48); // 32 bytes shadow space + a slot for the saved rsp
        a.mov(qword_ptr(rsp, 32), rax);
        a.mov(rcx, (uint64_t)this);
        a.mov(r8d, (uint32_t)byteCount);
        a.mov(r9d, currentEip); // which guest instruction stored this byte
        a.mov(rax, (uint64_t)JitWriteDosVram);
        EmitHostAbiArgs(a);
        a.call(rax);
        a.mov(rsp, qword_ptr(rsp, 32));

#ifndef _WIN32
        a.pop(rdi);
        a.pop(rsi);
#endif
        a.pop(r11);
        a.pop(r10);
        a.pop(r9);
        a.pop(r8);
        a.pop(rdx);
        a.pop(rcx);
        a.pop(rax);

        a.bind(skip);
        a.popfq();
    };

    // The read-side counterpart. Any guest read of the aperture reloads the
    // EGA latches, and the byte the CPU gets back is the Read Map Select plane
    // rather than whatever raw byte guestMemory happens to hold. Both are done
    // by ReadDosVram, which also refreshes guestMemory so the load that follows
    // this sequence picks up the plane byte. Emit it *before* the load.
    auto emitDosVramLatch = [&](const asmjit::x86::Gp &addr32, int byteCount)
    {
        if (!isMZ)
            return;

        Label skip = a.newLabel();
        a.pushfq();
        a.cmp(addr32, 0xA0000);
        a.jb(skip);
        a.cmp(addr32, 0xB0000);
        a.jae(skip);

        a.push(rax);
        a.push(rcx);
        a.push(rdx);
        a.push(r8);
        a.push(r9);
        a.push(r10);
        a.push(r11);
        // These helpers run inside STOS/MOVS sequences, where RSI/RDI hold the
        // live guest string pointers. They are callee-saved on Win64 but
        // caller-saved on SysV, so on SysV the host call may clobber them.
#ifndef _WIN32
        a.push(rsi);
        a.push(rdi);
#endif

        a.mov(edx, addr32); // arg 2, before rcx/r8 are overwritten below
        a.mov(rax, rsp);
        a.and_(rsp, -16);
        a.sub(rsp, 48); // 32 bytes shadow space + a slot for the saved rsp
        a.mov(qword_ptr(rsp, 32), rax);
        a.mov(rcx, (uint64_t)this);
        a.mov(r8d, (uint32_t)byteCount);
        a.mov(rax, (uint64_t)JitReadDosVram);
        EmitHostAbiArgs(a);
        a.call(rax);
        a.mov(rsp, qword_ptr(rsp, 32));

#ifndef _WIN32
        a.pop(rdi);
        a.pop(rsi);
#endif
        a.pop(r11);
        a.pop(r10);
        a.pop(r9);
        a.pop(r8);
        a.pop(rdx);
        a.pop(rcx);
        a.pop(rax);

        a.bind(skip);
        a.popfq();
    };

    auto emitFpuPush = [&]()
    {
        // Shift mm[0..6] -> mm[1..7]
        for (int i = 6; i >= 0; i--)
        {
            int srcOff = offsetof(CpuContext, mm[0]) + i * 8;
            int dstOff = offsetof(CpuContext, mm[0]) + (i + 1) * 8;
            a.movq(xmm0, qword_ptr(r15, srcOff));
            a.movq(qword_ptr(r15, dstOff), xmm0);
        }
    };

    auto emitFpuPop = [&]()
    {
        // Shift mm[1..7] -> mm[0..6]
        for (int i = 0; i < 7; i++)
        {
            int srcOff = offsetof(CpuContext, mm[0]) + (i + 1) * 8;
            int dstOff = offsetof(CpuContext, mm[0]) + i * 8;
            a.movq(xmm0, qword_ptr(r15, srcOff));
            a.movq(qword_ptr(r15, dstOff), xmm0);
        }
    };

    auto emitFpuPrecisionRounding = [&](Xmm destReg)
    {
        Label skipRounding = a.newLabel();
        a.pushfq();
        a.push(rax);
        a.push(rcx);
        a.push(rdx);

        a.movzx(edx, word_ptr(r15, offsetof(CpuContext, fpuControl)));
        a.test(edx, 0x300);
        a.jnz(skipRounding); // Skip if not single-precision
        
        a.sub(rsp, 16);
        a.stmxcsr(dword_ptr(rsp, 0));
        a.mov(eax, dword_ptr(rsp, 0));
        a.mov(ecx, edx);
        a.and_(ecx, 0x0C00);
        a.shl(ecx, 3);
        a.and_(eax, ~0x6000);
        a.or_(eax, ecx);
        a.mov(dword_ptr(rsp, 4), eax);
        a.ldmxcsr(dword_ptr(rsp, 4));
        
        a.cvtsd2ss(destReg, destReg);
        a.cvtss2sd(destReg, destReg);
        
        a.ldmxcsr(dword_ptr(rsp, 0));
        a.add(rsp, 16);
        
        a.bind(skipRounding);
        a.pop(rdx);
        a.pop(rcx);
        a.pop(rax);
        a.popfq();
    };

    bool pendingReseed = false;   // the prologue / chain entry already loaded the guest flags
    while (!blockEnded && instructionCount < MAX_BLOCK_SIZE)
    {
        Label currentLabel = a.newLabel();
        localBlockLabels.emplace(currentEip, currentLabel);
        a.bind(currentLabel);

        uint8_t *guestCodePtr = GetPointer(currentEip);
        if (!guestCodePtr)
        {
            log.isError = true;
            log.buffer << "[JIT] ERROR: Invalid guest pointer at 0x" << std::hex << currentEip << std::dec << "\n";
            return nullptr;
        }

        ZydisDecodedInstruction instr;
        ZydisDecodedOperand operands[10];
        if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder, guestCodePtr, 15, &instr, operands)))
        {
            log.isError = true;
            log.buffer << "[JIT] ERROR: Failed to decode at 0x" << std::hex << currentEip << std::dec << "\n";
            return nullptr;
        }

        // Log instruction (only when the compile log is on: formatting every
        // instruction was a measurable share of retranslation time under SMC)
        if (jitlog::g_level >= 1)
        {
            char buffer[256];
            ZydisFormatterFormatInstruction(&formatter, &instr, operands, instr.operand_count_visible, buffer, sizeof(buffer), currentEip, nullptr);
            log.buffer << "[JIT]   0x" << std::hex << currentEip << std::dec << ": " << buffer << "\n";
        }

        // Guest flags live in the host flags register for the whole block: the
        // prologue pops them in, conditional jumps read them with a bare
        // a.jz/a.jb, and the epilogue pushes them back. So a guest instruction
        // that architecturally leaves flags alone must not let the translator's
        // own scratch arithmetic — segment-base math, stack pointer updates,
        // helper-call setup — reach the flags register. It does today in many
        // handlers (PUSH/POP do `add r10, r11`, calls do `sub rsp, 40`), which
        // silently rewrites the guest's flags and sends a later Jcc in the same
        // block the wrong way. Single-instruction blocks hide this completely,
        // because every block reloads flags from CpuContext on entry.
        //
        // Rather than audit every handler, save and restore around any guest
        // instruction that Zydis says touches no flags at all.
        //
        // Block-ending instructions are excluded: their handlers return or jump
        // away, which would strand the pushfq and leave the epilogue's register
        // pops reading the saved flags off the stack.
        // Does this instruction need the host flags register to hold the guest
        // flags on entry? Yes if it reads any flag, writes only some of them
        // (the handler publishes the host register, so the untouched ones must
        // be right), or ends the block / leaves through a publishing path. No if
        // it touches no flags, or unconditionally overwrites all six status
        // flags. Shifts and rotates always re-seed: a zero count leaves flags
        // as they were.
        bool needsHostFlags = true;
        if (!g_jitEagerFlags && instr.cpu_flags && instr.cpu_flags->tested == 0 &&
            instr.meta.branch_type == ZYDIS_BRANCH_TYPE_NONE)
        {
            constexpr uint32_t kStatus = ZYDIS_CPUFLAG_CF | ZYDIS_CPUFLAG_PF | ZYDIS_CPUFLAG_AF |
                                         ZYDIS_CPUFLAG_ZF | ZYDIS_CPUFLAG_SF | ZYDIS_CPUFLAG_OF;
            const uint32_t written = instr.cpu_flags->modified | instr.cpu_flags->set_0 |
                                     instr.cpu_flags->set_1 | instr.cpu_flags->undefined;
            switch (instr.mnemonic)
            {
            case ZYDIS_MNEMONIC_INT: case ZYDIS_MNEMONIC_INT3: case ZYDIS_MNEMONIC_INTO:
            case ZYDIS_MNEMONIC_IRET: case ZYDIS_MNEMONIC_IRETD: case ZYDIS_MNEMONIC_IN:
            case ZYDIS_MNEMONIC_OUT: case ZYDIS_MNEMONIC_HLT: case ZYDIS_MNEMONIC_PUSHF:
            case ZYDIS_MNEMONIC_PUSHFD: case ZYDIS_MNEMONIC_POPF: case ZYDIS_MNEMONIC_POPFD:
            case ZYDIS_MNEMONIC_SAHF: case ZYDIS_MNEMONIC_LAHF:
            case ZYDIS_MNEMONIC_SHL: case ZYDIS_MNEMONIC_SHR: case ZYDIS_MNEMONIC_SAR:
            case ZYDIS_MNEMONIC_SHLD: case ZYDIS_MNEMONIC_SHRD:
            case ZYDIS_MNEMONIC_ROL: case ZYDIS_MNEMONIC_ROR: case ZYDIS_MNEMONIC_RCL:
            case ZYDIS_MNEMONIC_RCR:
                break;
            default:
                needsHostFlags = written != 0 && (written & kStatus) != kStatus;
                break;
            }
        }
        if (pendingReseed && needsHostFlags)
        {
            a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, eflags)));
            a.push(r11);
            a.popfq();
        }
        pendingReseed = false;

        // With lazy re-seeding nothing relies on host flags surviving a
        // flag-neutral instruction (the next instruction that needs them reloads
        // them from CpuContext), so the save/restore below is only kept for
        // HLEKIT_JIT_EAGER_FLAGS.
        const bool preserveHostFlags =
            g_jitEagerFlags &&
            instr.cpu_flags &&
            (instr.cpu_flags->modified | instr.cpu_flags->set_0 |
             instr.cpu_flags->set_1 | instr.cpu_flags->undefined) == 0 &&
            instr.meta.branch_type == ZYDIS_BRANCH_TYPE_NONE &&
            instr.mnemonic != ZYDIS_MNEMONIC_INT &&
            instr.mnemonic != ZYDIS_MNEMONIC_INT3 &&
            instr.mnemonic != ZYDIS_MNEMONIC_INTO &&
            instr.mnemonic != ZYDIS_MNEMONIC_IRET &&
            instr.mnemonic != ZYDIS_MNEMONIC_IRETD &&
            instr.mnemonic != ZYDIS_MNEMONIC_OUT &&
            instr.mnemonic != ZYDIS_MNEMONIC_IN &&
            instr.mnemonic != ZYDIS_MNEMONIC_HLT;
        if (preserveHostFlags)
        {
            a.pushfq();
            // Keep the 16-byte alignment handlers assume when they do the usual
            // "sub rsp, 40" before calling a C helper; pushfq alone would flip it.
            a.sub(rsp, 8);
        }

        switch ((int)instr.mnemonic)
        {
        case ZYDIS_MNEMONIC_CLI:
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eflags)));
            a.and_(r8d, ~0x200); // Clear IF (bit 9)
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
            break;

        case ZYDIS_MNEMONIC_STI:
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eflags)));
            a.or_(r8d, 0x200); // Set IF (bit 9)
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
            break;

        case ZYDIS_MNEMONIC_CLD:
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eflags)));
            a.and_(r8d, ~0x400); // Clear DF (bit 10)
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
            break;

        case ZYDIS_MNEMONIC_STD:
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eflags)));
            a.or_(r8d, 0x400); // Set DF (bit 10)
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
            break;

        case ZYDIS_MNEMONIC_NOP:
            // Do nothing
            break;

        case ZYDIS_MNEMONIC_HLT:
        case ZYDIS_MNEMONIC_INT3:
            // A kit trap byte (IDT stub, NativeFunction, seam return; int3 at ring 3). End the
            // block with EIP still on it: the backend turns it into Exit::Hlt / Exit::Debug and
            // the kit's OnTrap/OnInt machinery runs the service. hlt has no other effect.
            emitPublishGuestFlags();
            a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), currentEip);
            emitReturnToRunLoop();
            blockEnded = true;
            break;

        case ZYDIS_MNEMONIC_FFREE:
        {
            int stIndex = getFpuStackIndex(operands[0].reg.value);
            if (stIndex >= 0 && stIndex < 8)
            {
                a.movzx(r8d, word_ptr(r15, offsetof(CpuContext, fpuStatus)));
                a.shr(r8d, 11);
                a.and_(r8d, 7);
                a.add(r8d, stIndex);
                a.and_(r8d, 7); // r8d = phys_index

                a.shl(r8d, 1); // phys_index * 2
                a.mov(r9d, 3);
                a.mov(rcx, r8); // shift count must be in ecx/rcx
                a.shl(r9d, cl);

                a.movzx(r8d, word_ptr(r15, offsetof(CpuContext, fpuTag)));
                a.or_(r8d, r9d);
                a.mov(word_ptr(r15, offsetof(CpuContext, fpuTag)), r8w);
            }
        }
        break;

        case ZYDIS_MNEMONIC_CPUID:
            a.mov(rcx, r15);
            a.sub(rsp, 40); // 16-align + shadow space
            a.mov(rax, (uint64_t)HostCpuid);
            EmitHostAbiArgs(a);
            a.call(rax);
            a.add(rsp, 40);
            break;

        case ZYDIS_MNEMONIC_RDTSC:
            // CPUID leaf 1 advertises TSC; pass the host counter through.
            // RDTSC leaves flags untouched and rax/rdx are scratch here.
            a.rdtsc();
            a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);
            a.mov(dword_ptr(r15, offsetof(CpuContext, edx)), edx);
            break;

        case ZYDIS_MNEMONIC_VERR:
        case ZYDIS_MNEMONIC_VERW:
        {
            // ZF=1 if the selector is readable (VERR) / writable (VERW), else ZF=0.
            // No other flags change.
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off == -1) goto unimplemented;
                a.movzx(edx, word_ptr(r15, off));
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (!resolveMemoryIntoR8(operands[0].mem)) return nullptr;
                a.movzx(edx, word_ptr(r14, r8));
            }
            else
                goto unimplemented;

            a.sub(rsp, 40);
            a.mov(rcx, r13);
            a.mov(r8d, instr.mnemonic == ZYDIS_MNEMONIC_VERW ? 1 : 0);
            a.mov(rax, (uint64_t)HostVerifySelector);
            EmitHostAbiArgs(a);
            a.call(rax);
            a.add(rsp, 40);

            a.movzx(eax, al);
            a.shl(eax, 6);
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eflags)));
            a.and_(r8d, ~0x40u);
            a.or_(r8d, eax);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);

            // Load into the host CPU as well so a following Jcc sees ZF.
            a.push(r8);
            a.popfq();
        }
        break;

        case ZYDIS_MNEMONIC_FNINIT:
            a.mov(word_ptr(r15, offsetof(CpuContext, fpuControl)), 0x037F);
            a.mov(word_ptr(r15, offsetof(CpuContext, fpuStatus)), 0);
            a.mov(word_ptr(r15, offsetof(CpuContext, fpuTag)), 0xFFFF);
            break;

        case ZYDIS_MNEMONIC_INT1:
        {
            // ICEBP: hardcoded interrupt 1, same mechanism as INT imm8
            uint32_t nextEip = currentEip + instr.length;
            // The interrupt frame carries the flags as of this point; publish the host flags
            // first (the kit's interrupt path reads CpuContext::eflags, not the host's RFLAGS).
            emitPublishGuestFlags();
            a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), nextEip);
            a.mov(byte_ptr(r15, offsetof(CpuContext, pendingInt)), 1);
            a.pop(r15);
            a.pop(r14);
            a.pop(r13);
            a.pop(r12);
            a.pop(rsi);
            a.pop(rdi);
            a.pop(rbp);
            a.pop(rbx);
            a.ret();
            blockEnded = true;
        }
        break;

        case ZYDIS_MNEMONIC_INT:
        {
            // INT imm8 in MZ mode: save next EIP, set pendingInt, return from block
            uint8_t intno = (uint8_t)operands[0].imm.value.u;
            uint32_t nextEip = currentEip + instr.length;
            // The pushed EFLAGS must be current: the kit dispatches the interrupt in C++ after
            // the block returns, so publish the host flags before leaving.
            emitPublishGuestFlags();
            a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), nextEip);
            a.mov(byte_ptr(r15, offsetof(CpuContext, pendingInt)), intno);
            a.pop(r15);
            a.pop(r14);
            a.pop(r13);
            a.pop(r12);
            a.pop(rsi);
            a.pop(rdi);
            a.pop(rbp);
            a.pop(rbx);
            a.ret();
            blockEnded = true;
        }
        break;

        case ZYDIS_MNEMONIC_IN:
        {
            // IN acc, port : operand[0]=data (AL/AX/EAX), operand[1]=port (DX or imm8).
            // Handled by exiting the block and letting the run loop call
            // the kit's I/O read path, mirroring the INT dispatch path.
            uint8_t width = (uint8_t)(operands[0].size / 8);
            uint32_t nextEip = currentEip + instr.length;

            if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                a.mov(word_ptr(r15, offsetof(CpuContext, pendingIoPort)),
                      (uint16_t)operands[1].imm.value.u);
            } else if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       operands[1].reg.value == ZYDIS_REGISTER_DX) {
                a.mov(r8w, word_ptr(r15, offsetof(CpuContext, edx)));
                a.mov(word_ptr(r15, offsetof(CpuContext, pendingIoPort)), r8w);
            } else {
                goto unimplemented;
            }

            emitPublishGuestFlags();
            a.mov(byte_ptr(r15, offsetof(CpuContext, pendingIoWidth)), width);
            a.mov(byte_ptr(r15, offsetof(CpuContext, pendingIo)), 1);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), nextEip);
            emitReturnToRunLoop();
            blockEnded = true;
        }
        break;

        case ZYDIS_MNEMONIC_OUT:
        {
            // OUT port, acc : operand[0]=port (DX or imm8), operand[1]=data (AL/AX/EAX).
            uint8_t width = (uint8_t)(operands[1].size / 8);
            uint32_t nextEip = currentEip + instr.length;

            if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                a.mov(word_ptr(r15, offsetof(CpuContext, pendingIoPort)),
                      (uint16_t)operands[0].imm.value.u);
            } else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       operands[0].reg.value == ZYDIS_REGISTER_DX) {
                a.mov(r8w, word_ptr(r15, offsetof(CpuContext, edx)));
                a.mov(word_ptr(r15, offsetof(CpuContext, pendingIoPort)), r8w);
            } else {
                goto unimplemented;
            }

            int valOff = getRegOffset(operands[1].reg.value);
            if (valOff == -1) goto unimplemented;
            if (width == 1) {
                a.movzx(r8d, byte_ptr(r15, valOff));
                a.mov(dword_ptr(r15, offsetof(CpuContext, pendingIoValue)), r8d);
            } else if (width == 2) {
                a.movzx(r8d, word_ptr(r15, valOff));
                a.mov(dword_ptr(r15, offsetof(CpuContext, pendingIoValue)), r8d);
            } else if (width == 4) {
                a.mov(r8d, dword_ptr(r15, valOff));
                a.mov(dword_ptr(r15, offsetof(CpuContext, pendingIoValue)), r8d);
            } else {
                goto unimplemented;
            }

            emitPublishGuestFlags();
            a.mov(byte_ptr(r15, offsetof(CpuContext, pendingIoWidth)), width);
            a.mov(byte_ptr(r15, offsetof(CpuContext, pendingIo)), 2);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), nextEip);
            emitReturnToRunLoop();
            blockEnded = true;
        }
        break;

        case ZYDIS_MNEMONIC_FLD:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int srcIndex = getFpuStackIndex(operands[0].reg.value);
                if (srcIndex >= 0)
                {
                    int srcOffset = offsetof(CpuContext, mm[0]) + srcIndex * sizeof(uint64_t);
                    // Capture old ST(i) before the push shifts logical stack slots.
                    a.movq(xmm1, qword_ptr(r15, srcOffset));
                    emitFpuPush();
                    a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm1);
                }
                else
                    goto unimplemented;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    emitFpuPush();
                    if (operands[0].size == 80)
                    {
                        // FLDT: Load 80-bit extended precision
                        a.sub(rsp, 16);
                        a.mov(rax, qword_ptr(r14, r8, 0));
                        a.mov(qword_ptr(rsp), rax);
                        a.mov(ax, word_ptr(r14, r8, 0, 8));
                        a.mov(word_ptr(rsp, 8), ax);
                        // Convert tbyte -> double via host x87
                        a.fld(tword_ptr(rsp));
                        a.fstp(qword_ptr(rsp));
                        a.movsd(xmm0, qword_ptr(rsp));
                        a.add(rsp, 16);
                        a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);

                        /*
                        // Debug Log
                        a.sub(rsp, 64);
                        a.movsd(qword_ptr(rsp, 32), xmm0);
                        a.mov(r8d, r8d); // offset
                        a.mov(edx, r8d); // Pass addr as 2nd arg
                        a.mov(rax, (uint64_t)LogFldAddr);
                        a.call(rax);
                        a.movsd(xmm0, qword_ptr(rsp, 32));
                        a.add(rsp, 64);
                        */
                    }
                    else if (operands[0].size == 32)
                    {
                        a.movss(xmm0, dword_ptr(r14, r8, 0));
                        a.cvtss2sd(xmm0, xmm0);
                        a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
                    }
                    else
                    {
                        a.movsd(xmm0, qword_ptr(r14, r8, 0));
                        a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
                    }
                }
                else
                    return nullptr;
            }
            break;

        case ZYDIS_MNEMONIC_FST:
        case ZYDIS_MNEMONIC_FSTP:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
                    if (operands[0].size == 32)
                    {
                        a.cvtsd2ss(xmm0, xmm0);
                        a.movss(dword_ptr(r14, r8, 0), xmm0);
                    }
                    else if (operands[0].size == 64)
                    {
                        a.movsd(qword_ptr(r14, r8, 0), xmm0);
                    }
                    else if (operands[0].size == 80)
                    {
                        // StoreFloat80(uint8_t*, double): Win64 puts the double in
                        // XMM1 because it occupies the second positional slot;
                        // SysV counts SSE args separately, so it stays in XMM0.
#ifdef _WIN32
                        a.lea(rcx, ptr(r14, r8));
                        a.movsd(xmm1, xmm0);
#else
                        a.lea(rdi, ptr(r14, r8));
#endif
                        a.sub(rsp, 40);
                        a.mov(rax, (uint64_t)&StoreFloat80);
                        a.call(rax);
                        a.add(rsp, 40);
                    }
                    else
                    {
                        goto unimplemented;
                    }
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int stIndex = getFpuStackIndex(operands[0].reg.value);
                if (stIndex >= 0 && stIndex <= 7)
                {
                    a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
                    a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0]) + stIndex * 8), xmm0);
                }
            }
            if (instr.mnemonic == ZYDIS_MNEMONIC_FSTP)
            {
                emitFpuPop();
            }
            break;

        case ZYDIS_MNEMONIC_FADDP:
        {
            int dstIndex = 1;
            for (uint8_t i = 0; i < instr.operand_count; ++i)
            {
                if (operands[i].type != ZYDIS_OPERAND_TYPE_REGISTER)
                    continue;
                int idx = getFpuStackIndex(operands[i].reg.value);
                if (idx > 0)
                {
                    dstIndex = idx;
                    break;
                }
            }
            int dstOff = offsetof(CpuContext, mm[0]) + dstIndex * 8;
            a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            a.movq(xmm1, qword_ptr(r15, dstOff));
            a.addsd(xmm1, xmm0);
            emitFpuPrecisionRounding(xmm1);
            a.movq(qword_ptr(r15, dstOff), xmm1);
            emitFpuPop();
        }
            break;

        case ZYDIS_MNEMONIC_FSUBP:
        {
            int dstIndex = 1;
            for (uint8_t i = 0; i < instr.operand_count; ++i)
            {
                if (operands[i].type != ZYDIS_OPERAND_TYPE_REGISTER)
                    continue;
                int idx = getFpuStackIndex(operands[i].reg.value);
                if (idx > 0)
                {
                    dstIndex = idx;
                    break;
                }
            }
            int dstOff = offsetof(CpuContext, mm[0]) + dstIndex * 8;
            a.movq(xmm1, qword_ptr(r15, dstOff));
            a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            a.subsd(xmm1, xmm0);
            emitFpuPrecisionRounding(xmm1);
            a.movq(qword_ptr(r15, dstOff), xmm1);
            emitFpuPop();
        }
            break;

        case ZYDIS_MNEMONIC_FMULP:
        {
            int dstIndex = 1;
            for (uint8_t i = 0; i < instr.operand_count; ++i)
            {
                if (operands[i].type != ZYDIS_OPERAND_TYPE_REGISTER)
                    continue;
                int idx = getFpuStackIndex(operands[i].reg.value);
                if (idx > 0)
                {
                    dstIndex = idx;
                    break;
                }
            }
            int dstOff = offsetof(CpuContext, mm[0]) + dstIndex * 8;
            a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            a.movq(xmm1, qword_ptr(r15, dstOff));
            a.mulsd(xmm1, xmm0);
            emitFpuPrecisionRounding(xmm1);
            a.movq(qword_ptr(r15, dstOff), xmm1);
            emitFpuPop();
        }
            break;

        case ZYDIS_MNEMONIC_FDIVP:
        {
            int dstIndex = 1;
            for (uint8_t i = 0; i < instr.operand_count; ++i)
            {
                if (operands[i].type != ZYDIS_OPERAND_TYPE_REGISTER)
                    continue;
                int idx = getFpuStackIndex(operands[i].reg.value);
                if (idx > 0)
                {
                    dstIndex = idx;
                    break;
                }
            }
            int dstOff = offsetof(CpuContext, mm[0]) + dstIndex * 8;
            a.movq(xmm1, qword_ptr(r15, dstOff));
            a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            a.divsd(xmm1, xmm0);
            emitFpuPrecisionRounding(xmm1);
            a.movq(qword_ptr(r15, dstOff), xmm1);
            // HostSetFpuDivideByZeroStatus(double, uint16_t*): the pointer is the second
            // positional slot (RDX) on Win64, but the first *integer*
            // argument (RDI) on SysV. The double stays in XMM0 for both.
            #ifdef _WIN32
            // HostFptan(double, uint16_t*): the pointer is the second
            // positional slot (RDX) on Win64, but the first *integer*
            // argument (RDI) on SysV. The double stays in XMM0 for both.
            #ifdef _WIN32
            // HostFcos(double, uint16_t*): the pointer is the second
            // positional slot (RDX) on Win64, but the first *integer*
            // argument (RDI) on SysV. The double stays in XMM0 for both.
            #ifdef _WIN32
            // HostFsin(double, uint16_t*): the pointer is the second
            // positional slot (RDX) on Win64, but the first *integer*
            // argument (RDI) on SysV. The double stays in XMM0 for both.
            #ifdef _WIN32
            a.lea(rdx, ptr(r15, offsetof(CpuContext, fpuStatus)));
            #else
            a.lea(rdi, ptr(r15, offsetof(CpuContext, fpuStatus)));
            #endif
            #else
            a.lea(rdi, ptr(r15, offsetof(CpuContext, fpuStatus)));
            #endif
            #else
            a.lea(rdi, ptr(r15, offsetof(CpuContext, fpuStatus)));
            #endif
            #else
            a.lea(rdi, ptr(r15, offsetof(CpuContext, fpuStatus)));
            #endif
            a.sub(rsp, 40);
            a.mov(rax, (uint64_t)&HostSetFpuDivideByZeroStatus);
            a.call(rax);
            a.add(rsp, 40);
            emitFpuPop();
        }
            break;

        case ZYDIS_MNEMONIC_FSUBRP:
        {
            int dstIndex = 1;
            for (uint8_t i = 0; i < instr.operand_count; ++i)
            {
                if (operands[i].type != ZYDIS_OPERAND_TYPE_REGISTER)
                    continue;
                int idx = getFpuStackIndex(operands[i].reg.value);
                if (idx > 0)
                {
                    dstIndex = idx;
                    break;
                }
            }
            int dstOff = offsetof(CpuContext, mm[0]) + dstIndex * 8;
            // FSUBRP: ST(i) = ST(0) - ST(i), then pop
            a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            a.movq(xmm1, qword_ptr(r15, dstOff));
            a.subsd(xmm0, xmm1); // xmm0 = xmm0 - xmm1
            emitFpuPrecisionRounding(xmm0);
            a.movq(qword_ptr(r15, dstOff), xmm0);
            emitFpuPop();
        }
            break;

        case ZYDIS_MNEMONIC_FDIVRP:
        {
            int dstIndex = 1;
            for (uint8_t i = 0; i < instr.operand_count; ++i)
            {
                if (operands[i].type != ZYDIS_OPERAND_TYPE_REGISTER)
                    continue;
                int idx = getFpuStackIndex(operands[i].reg.value);
                if (idx > 0)
                {
                    dstIndex = idx;
                    break;
                }
            }
            int dstOff = offsetof(CpuContext, mm[0]) + dstIndex * 8;
            // FDIVRP: ST(i) = ST(0) / ST(i), then pop
            a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            a.movq(xmm1, qword_ptr(r15, dstOff));
            a.divsd(xmm0, xmm1); // xmm0 = xmm0 / xmm1
            emitFpuPrecisionRounding(xmm0);
            a.movq(qword_ptr(r15, dstOff), xmm0);
            emitFpuPop();
        }
            break;

        case ZYDIS_MNEMONIC_FCOMI:
        case ZYDIS_MNEMONIC_FCOMIP:
        case ZYDIS_MNEMONIC_FUCOMI:
        case ZYDIS_MNEMONIC_FUCOMIP:
        {
            uint32_t stOffset = offsetof(CpuContext, mm[1]);
            if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int stIndex = getFpuStackIndex(operands[1].reg.value);
                if (stIndex >= 0)
                {
                    stOffset = offsetof(CpuContext, mm[0]) + stIndex * sizeof(uint64_t);
                }
            }
            a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            a.movq(xmm1, qword_ptr(r15, stOffset));

            /*
            // Debug logging
            a.sub(rsp, 64);
            a.movsd(qword_ptr(rsp, 32), xmm0);
            a.movsd(qword_ptr(rsp, 40), xmm1);
            a.mov(rax, (uint64_t)LogFcomip);
            a.call(rax);
            a.movsd(xmm0, qword_ptr(rsp, 32));
            a.movsd(xmm1, qword_ptr(rsp, 40));
            a.add(rsp, 64);
            */

            a.ucomisd(xmm0, xmm1);
            a.pushfq();
            a.pop(r8);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);

            // CRITICAL: Restore flags to host CPU so conditional jumps work!
            a.push(r8);
            a.popfq();

            if (instr.mnemonic == ZYDIS_MNEMONIC_FCOMIP || instr.mnemonic == ZYDIS_MNEMONIC_FUCOMIP)
            {
                emitFpuPop();
            }
        }
        break;

        case ZYDIS_MNEMONIC_FLDZ:
            emitFpuPush();
            a.xorpd(xmm0, xmm0);
            a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
            break;

        case ZYDIS_MNEMONIC_FLD1:
            emitFpuPush();
            a.mov(rax, (uint64_t)0x3FF0000000000000ULL);
            a.movq(xmm0, rax);
            a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
            break;

        case ZYDIS_MNEMONIC_FCHS:
            // Flip sign bit of ST(0) using XOR
            a.mov(r9, (uint64_t)0x8000000000000000ULL); // Sign bit mask
            a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            a.movq(xmm1, r9);
            a.pxor(xmm0, xmm1); // XOR to flip sign bit
            a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
            break;

        case ZYDIS_MNEMONIC_FXCH:
        {
            int stIndex = 1; // Default to ST(1)
            // Zydis versions differ in whether implicit ST0 appears first.
            for (uint8_t i = 0; i < instr.operand_count; ++i)
            {
                if (operands[i].type != ZYDIS_OPERAND_TYPE_REGISTER)
                    continue;
                int idx = getFpuStackIndex(operands[i].reg.value);
                if (idx > 0)
                {
                    stIndex = idx;
                    break;
                }
            }
            if (stIndex >= 1 && stIndex <= 7)
            {
                int otherOff = offsetof(CpuContext, mm[0]) + stIndex * 8;
                // Swap mm[0] with mm[stIndex]
                a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
                a.movq(xmm1, qword_ptr(r15, otherOff));
                a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm1);
                a.movq(qword_ptr(r15, otherOff), xmm0);
            }
        }
        break;

        case ZYDIS_MNEMONIC_FABS:
            // Absolute value of ST(0)
            a.mov(r9, (uint64_t)0x7FFFFFFFFFFFFFFFULL); // Clears sign bit
            a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            a.movq(xmm1, r9);
            a.pand(xmm0, xmm1); // AND with mask to clear sign bit
            a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
            break;

        case ZYDIS_MNEMONIC_FSQRT:
            // ST(0) = sqrt(ST(0))
            a.movsd(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            a.sqrtsd(xmm0, xmm0);
            a.movsd(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
            break;

        case ZYDIS_MNEMONIC_FADD:
        case ZYDIS_MNEMONIC_FSUB:
        case ZYDIS_MNEMONIC_FSUBR:
        case ZYDIS_MNEMONIC_FMUL:
        case ZYDIS_MNEMONIC_FDIV:
        case ZYDIS_MNEMONIC_FDIVR:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
                    if (operands[0].size == 32)
                    {
                        a.movss(xmm1, dword_ptr(r14, r8, 0));
                        a.cvtss2sd(xmm1, xmm1);
                    }
                    else if (operands[0].size == 64)
                    {
                        a.movsd(xmm1, qword_ptr(r14, r8, 0));
                    }
                    else
                    {
                        // Fallback for tbyte/unknown
                        a.movsd(xmm1, qword_ptr(r14, r8, 0));
                    }
                    switch (instr.mnemonic)
                    {
                    case ZYDIS_MNEMONIC_FADD:
                        a.addsd(xmm0, xmm1);
                        break;
                    case ZYDIS_MNEMONIC_FSUB:
                        a.subsd(xmm0, xmm1);
                        break;
                    case ZYDIS_MNEMONIC_FSUBR:
                        a.subsd(xmm1, xmm0);
                        a.movaps(xmm0, xmm1);
                        break;
                    case ZYDIS_MNEMONIC_FMUL:
                        LOG_INFO << "[JIT COMPILE] FMUL at 0x" << std::hex << currentEip
                                 << " operand size=" << std::dec << operands[0].size
                                 << " type=" << operands[0].type << std::endl;
                        a.mulsd(xmm0, xmm1);
                        break;
                    case ZYDIS_MNEMONIC_FDIV:
                        a.divsd(xmm0, xmm1);
                        break;
                    case ZYDIS_MNEMONIC_FDIVR:
                        a.divsd(xmm1, xmm0);
                        a.movaps(xmm0, xmm1);
                        break;
                    default:
                        break;
                    }
                    emitFpuPrecisionRounding(xmm0);
                    a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int dstIndex = getFpuStackIndex(operands[0].reg.value);
                int srcIndex = getFpuStackIndex(operands[1].reg.value);
                if (dstIndex >= 0 && dstIndex < 8 && srcIndex >= 0 && srcIndex < 8)
                {
                    a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0]) + dstIndex * 8));
                    a.movq(xmm1, qword_ptr(r15, offsetof(CpuContext, mm[0]) + srcIndex * 8));
                    switch (instr.mnemonic)
                    {
                    case ZYDIS_MNEMONIC_FADD:
                        a.addsd(xmm0, xmm1);
                        break;
                    case ZYDIS_MNEMONIC_FSUB:
                        a.subsd(xmm0, xmm1);
                        break;
                    case ZYDIS_MNEMONIC_FSUBR:
                        a.subsd(xmm1, xmm0);
                        a.movaps(xmm0, xmm1);
                        break;
                    case ZYDIS_MNEMONIC_FMUL:
                        a.mulsd(xmm0, xmm1);
                        break;
                    case ZYDIS_MNEMONIC_FDIV:
                        a.divsd(xmm0, xmm1);
                        break;
                    case ZYDIS_MNEMONIC_FDIVR:
                        a.divsd(xmm1, xmm0);
                        a.movaps(xmm0, xmm1);
                        break;
                    default:
                        break;
                    }
                    emitFpuPrecisionRounding(xmm0);
                    a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0]) + dstIndex * 8), xmm0);
                }
            }
            break;
        case ZYDIS_MNEMONIC_FIADD:
        case ZYDIS_MNEMONIC_FIMUL:
        case ZYDIS_MNEMONIC_FIDIV:
        case ZYDIS_MNEMONIC_FIDIVR:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
                    a.xorps(xmm1, xmm1);

                    if (operands[0].size == 16)
                    {
                        a.movsx(r9d, word_ptr(r14, r8));
                        a.cvtsi2sd(xmm1, r9d);
                    }
                    else if (operands[0].size == 32)
                    {
                        a.cvtsi2sd(xmm1, dword_ptr(r14, r8));
                    }
                    else
                    {
                        return nullptr;
                    }

                    switch (instr.mnemonic)
                    {
                    case ZYDIS_MNEMONIC_FIADD:
                        a.addsd(xmm0, xmm1);
                        break;
                    case ZYDIS_MNEMONIC_FIMUL:
                        a.mulsd(xmm0, xmm1);
                        break;
                    case ZYDIS_MNEMONIC_FIDIV:
                        a.divsd(xmm0, xmm1);
                        break;
                    case ZYDIS_MNEMONIC_FIDIVR:
                        a.divsd(xmm1, xmm0);
                        a.movsd(xmm0, xmm1);
                        break;
                    default:
                        break;
                    }

                    a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
                }
                else
                {
                    return nullptr;
                }
            }
            else
            {
                goto unimplemented;
            }
            break;

        case ZYDIS_MNEMONIC_FISUB:
        case ZYDIS_MNEMONIC_FISUBR:
            // FISUB: ST0 = ST0 - (double)mem_int
            // FISUBR: ST0 = (double)mem_int - ST0
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    // Load ST0 (treated as 64-bit double-precision)
                    a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));

                    // Break false hardware dependency on the destination register
                    a.xorps(xmm1, xmm1);

                    // Convert signed memory integer operand to double-precision float
                    if (operands[0].size == 16)
                    {
                        a.movsx(r9d, word_ptr(r14, r8));
                        a.cvtsi2sd(xmm1, r9d);
                    }
                    else if (operands[0].size == 32)
                    {
                        a.cvtsi2sd(xmm1, dword_ptr(r14, r8));
                    }
                    else
                    {
                        return nullptr;
                    }

                    // Perform subtraction
                    if (instr.mnemonic == ZYDIS_MNEMONIC_FISUB)
                    {
                        a.subsd(xmm0, xmm1);
                    }
                    else
                    {
                        a.subsd(xmm1, xmm0);
                        a.movsd(xmm0, xmm1); // Use scalar move semantics
                    }

                    // Write back the updated ST0
                    a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
                }
                else
                {
                    return nullptr;
                }
            }
            else
            {
                goto unimplemented;
            }
            break;

        case ZYDIS_MNEMONIC_FILD:
            emitFpuPush();
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[0].size == 16)
                        a.movsx(r9d, word_ptr(r14, r8, 0));
                    else if (operands[0].size == 32)
                        a.mov(r9d, dword_ptr(r14, r8, 0));
                    else
                        a.mov(r9, qword_ptr(r14, r8, 0)); // 64-bit int

                    if (operands[0].size <= 32)
                        a.cvtsi2sd(xmm0, r9d);
                    else
                        a.cvtsi2sd(xmm0, r9);

                    a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
                }
                else
                    return nullptr;
            }
            break;

        case ZYDIS_MNEMONIC_FIST:
        case ZYDIS_MNEMONIC_FISTP:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
                    a.movzx(r10d, word_ptr(r15, offsetof(CpuContext, fpuControl)));
                    a.shr(r10d, 10);
                    a.and_(r10d, 3);

                    Label roundDown = a.newLabel();
                    Label roundUp = a.newLabel();
                    Label roundChop = a.newLabel();
                    Label rounded = a.newLabel();
                    a.cmp(r10d, 1);
                    a.je(roundDown);
                    a.cmp(r10d, 2);
                    a.je(roundUp);
                    a.cmp(r10d, 3);
                    a.je(roundChop);
                    a.roundsd(xmm0, xmm0, 0); // nearest-even
                    a.jmp(rounded);
                    a.bind(roundDown);
                    a.roundsd(xmm0, xmm0, 1); // toward -infinity
                    a.jmp(rounded);
                    a.bind(roundUp);
                    a.roundsd(xmm0, xmm0, 2); // toward +infinity
                    a.jmp(rounded);
                    a.bind(roundChop);
                    a.roundsd(xmm0, xmm0, 3); // toward zero
                    a.bind(rounded);

                    if (operands[0].size == 16)
                    {
                        a.cvttsd2si(r9d, xmm0);
                        a.mov(word_ptr(r14, r8, 0), r9w);
                    }
                    else if (operands[0].size == 32)
                    {
                        a.cvttsd2si(r9d, xmm0);
                        a.mov(dword_ptr(r14, r8, 0), r9d);
                    }
                    else if (operands[0].size == 64)
                    {
                        a.cvttsd2si(r9, xmm0);
                        a.mov(qword_ptr(r14, r8, 0), r9);
                    }
                    if (instr.mnemonic == ZYDIS_MNEMONIC_FISTP)
                        emitFpuPop();
                }
                else
                    return nullptr;
            }
            break;

        case ZYDIS_MNEMONIC_FCOM:
        case ZYDIS_MNEMONIC_FCOMP:
        case ZYDIS_MNEMONIC_FCOMPP:
        case ZYDIS_MNEMONIC_FICOM:
        case ZYDIS_MNEMONIC_FICOMP:
        {
            // FICOM / FICOMP (Integer Compare)
            if (instr.mnemonic == ZYDIS_MNEMONIC_FICOM || instr.mnemonic == ZYDIS_MNEMONIC_FICOMP)
            {
                if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    if (resolveMemoryIntoR8(operands[0].mem))
                    {
                        a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));

                        // Convert Integer to Double
                        if (operands[0].size == 16)
                        {
                            a.movsx(eax, word_ptr(r14, r8, 0)); // Sign-extend 16-bit to 32-bit
                            a.cvtsi2sd(xmm1, eax);
                        }
                        else if (operands[0].size == 32)
                        {
                            a.cvtsi2sd(xmm1, dword_ptr(r14, r8, 0));
                        }
                        else
                        {
                            // Fallback for unexpected size
                            a.cvtsi2sd(xmm1, dword_ptr(r14, r8, 0));
                        }

                        // Debug logging
                        a.sub(rsp, 64);
                        a.movsd(qword_ptr(rsp, 32), xmm0);
                        a.movsd(qword_ptr(rsp, 40), xmm1);
                        a.mov(rax, (uint64_t)LogFicom);
                        a.call(rax);
                        a.movsd(xmm0, qword_ptr(rsp, 32));
                        a.movsd(xmm1, qword_ptr(rsp, 40));
                        a.add(rsp, 64);

                        a.ucomisd(xmm0, xmm1);
                    }
                    else
                        return nullptr;
                }
                else
                    return nullptr; // FICOM requires memory
            }
            // FCOM / FCOMP / FCOMPP (Float Compare)
            else
            {
                uint32_t stOffset = offsetof(CpuContext, mm[1]);
                if (instr.operand_count >= 1)
                {
                    for (uint8_t i = 0; i < instr.operand_count; ++i)
                    {
                        if (operands[i].type != ZYDIS_OPERAND_TYPE_REGISTER)
                            continue;
                        int stIndex = getFpuStackIndex(operands[i].reg.value);
                        if (stIndex > 0)
                        {
                            stOffset = offsetof(CpuContext, mm[0]) + stIndex * 8;
                            break;
                        }
                    }
                }
                if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    if (resolveMemoryIntoR8(operands[0].mem))
                    {
                        a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
                        if (operands[0].size == 32)
                        {
                            a.movss(xmm1, dword_ptr(r14, r8, 0));
                            a.cvtss2sd(xmm1, xmm1);
                        }
                        else
                        {
                            a.movsd(xmm1, qword_ptr(r14, r8, 0));
                        }
                        a.ucomisd(xmm0, xmm1);
                    }
                    else
                        return nullptr;
                }
                else
                {
                    a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
                    a.movq(xmm1, qword_ptr(r15, stOffset));
                    a.ucomisd(xmm0, xmm1);
                }
            }

            // Set FPU Status Word bits C0, C2, C3
            // C0 = bit 8, C2 = bit 10, C3 = bit 14
            // ucomisd sets:
            //   > : CF=0, PF=0, ZF=0  => C3=0, C2=0, C0=0
            //   < : CF=1, PF=0, ZF=0  => C3=0, C2=0, C0=1
            //   = : CF=0, PF=0, ZF=1  => C3=1, C2=0, C0=0
            // Un : CF=1, PF=1, ZF=1  => C3=1, C2=1, C0=1

            a.pushfq();
            a.pop(rax);
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, fpuStatus)));
            a.and_(r8d, 0xFFFFBAFF); // Clear C3, C2, C0 (mask: bits 14, 10, 8)

            // ZF (bit 6) -> C3 (bit 14)
            // PF (bit 2) -> C2 (bit 10)
            // CF (bit 0) -> C0 (bit 8)

            a.xor_(ecx, ecx);
            a.test(al, 0x40);
            a.setnz(cl);
            a.shl(ecx, 14);
            a.or_(r8d, ecx); // ZF -> C3
            a.xor_(ecx, ecx);
            a.test(al, 0x04);
            a.setnz(cl);
            a.shl(ecx, 10);
            a.or_(r8d, ecx); // PF -> C2
            a.xor_(ecx, ecx);
            a.test(al, 0x01);
            a.setnz(cl);
            a.shl(ecx, 8);
            a.or_(r8d, ecx); // CF -> C0

            a.mov(word_ptr(r15, offsetof(CpuContext, fpuStatus)), r8w);

            if (instr.mnemonic == ZYDIS_MNEMONIC_FCOMP || instr.mnemonic == ZYDIS_MNEMONIC_FCOMPP ||
                instr.mnemonic == ZYDIS_MNEMONIC_FICOMP)
            {
                emitFpuPop();
            }
            if (instr.mnemonic == ZYDIS_MNEMONIC_FCOMPP)
            {
                emitFpuPop();
            }
        }
        break;

        case ZYDIS_MNEMONIC_FTST:
            // FTST: compare ST0 with +0.0, set FPU status C0/C2/C3, no pop
            {
                a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
                a.xorpd(xmm1, xmm1); // +0.0
                a.ucomisd(xmm0, xmm1);

                // Clear EAX and load low EFLAGS byte into AH (bits 8-15 of EAX)
                a.xor_(eax, eax);
                a.lahf();

                // Mask to isolate C3 (ZF/bit 14), C2 (PF/bit 10), and C0 (CF/bit 8)
                a.and_(eax, 0x4500);

                // Safely load the 16-bit FPU status word
                a.movzx(r8d, word_ptr(r15, offsetof(CpuContext, fpuStatus)));

                // Clear C3, C2, and C0 in the current status word (0xBAFF)
                a.and_(r8d, 0xBAFF);

                // Merge the new comparison status flags and write back
                a.or_(r8d, eax);
                a.mov(word_ptr(r15, offsetof(CpuContext, fpuStatus)), r8w);
            }
            break;

        case ZYDIS_MNEMONIC_FNCLEX:
            // Clear x87 exception flags (bits 0-7), stack fault (bit 6), ES (bit 7),
            // and busy (bit 15). Preserve condition codes (bits 8-14).
            a.and_(word_ptr(r15, offsetof(CpuContext, fpuStatus)), 0x7F00);
            break;

        case ZYDIS_MNEMONIC_FNSTSW:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[0].reg.value == ZYDIS_REGISTER_AX)
            {
                a.mov(ax, word_ptr(r15, offsetof(CpuContext, fpuStatus)));
                a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    a.mov(ax, word_ptr(r15, offsetof(CpuContext, fpuStatus)));
                    a.mov(word_ptr(r14, r8, 0), ax);
                }
                else
                    return nullptr;
            }
            break;

        case ZYDIS_MNEMONIC_SAHF:
        {
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eflags)));
            a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, eax)));
            a.and_(r8d, 0xFFFFFF00); // Clear AH-related flags (or bits 0-7)
            a.shr(r9d, 8);           // Get AH
            a.and_(r9d, 0xD5);       // Only CF, PF, AF, ZF, SF are set by SAHF
            a.or_(r8d, r9d);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);

            // Also restore them to host CPU so conditional jumps work!
            a.push(r8);
            a.popfq();
        }
        break;

        case ZYDIS_MNEMONIC_FLDPI:
            emitFpuPush();
            a.mov(rax, (uint64_t)0x400921FB54442D18ULL); // PI as double
            a.movq(xmm0, rax);
            a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
            break;

        case ZYDIS_MNEMONIC_FLDL2E:
            emitFpuPush();
            a.mov(rax, 0x3FF71547652B82FEULL); // log2(e) ≈ 1.442695
            a.mov(qword_ptr(r15, offsetof(CpuContext, mm[0])), rax);
            break;

        case ZYDIS_MNEMONIC_FLDL2T:
            emitFpuPush();
            a.mov(rax, 0x400A934F0979A371ULL); // log2(10) ≈ 3.321928
            a.mov(qword_ptr(r15, offsetof(CpuContext, mm[0])), rax);
            break;

        case ZYDIS_MNEMONIC_FLDLG2:
            emitFpuPush();
            a.mov(rax, 0x3FD34413509F79FFULL); // log10(2) ≈ 0.301030
            a.mov(qword_ptr(r15, offsetof(CpuContext, mm[0])), rax);
            break;

        case ZYDIS_MNEMONIC_FLDLN2:
            emitFpuPush();
            a.mov(rax, 0x3FE62E42FEFA39EFULL); // ln(2) ≈ 0.693147
            a.mov(qword_ptr(r15, offsetof(CpuContext, mm[0])), rax);
            break;

        case ZYDIS_MNEMONIC_FPATAN:
            // ST(1) = Y, ST(0) = X. Computes atan2(Y, X), stores in ST(1), pops ST(0)
            a.movsd(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[1]))); // Y
            a.movsd(xmm1, qword_ptr(r15, offsetof(CpuContext, mm[0]))); // X
            a.sub(rsp, 40);                                             // Align 16 + 32 shadow space
            a.mov(rax, (uint64_t)&HostAtan2);
            a.call(rax);
            a.add(rsp, 40);
            a.movsd(qword_ptr(r15, offsetof(CpuContext, mm[1])), xmm0);
            emitFpuPop();
            break;

        case ZYDIS_MNEMONIC_FPREM:
            // ST0 = ST0 mod ST1, set C2=0 in FPU status (assume complete)
            a.movsd(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0]))); // ST0
            a.movsd(xmm1, qword_ptr(r15, offsetof(CpuContext, mm[1]))); // ST1

            a.sub(rsp, 40);
            a.mov(rax, (uint64_t)&HostFprem);
            a.call(rax);
            a.add(rsp, 40);

            a.movsd(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);

            // Clear C2 bit (bit 10) directly in memory indicating reduction is complete
            a.and_(word_ptr(r15, offsetof(CpuContext, fpuStatus)), 0xFBFF);
            break;

        case ZYDIS_MNEMONIC_F2XM1:
            // ST0 = 2^ST0 - 1
            a.movsd(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));

            a.sub(rsp, 40);
            a.mov(rax, (uint64_t)&HostF2xm1);
            a.call(rax);
            a.add(rsp, 40);

            a.movsd(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
            break;

        case ZYDIS_MNEMONIC_FSCALE:
            // ST0 = ST0 * 2^trunc(ST1)
            a.movsd(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0]))); // ST0
            a.movsd(xmm1, qword_ptr(r15, offsetof(CpuContext, mm[1]))); // ST1

            a.sub(rsp, 40);
            a.mov(rax, (uint64_t)&HostFscale);
            a.call(rax);
            a.add(rsp, 40);

            a.movsd(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
            break;

        case ZYDIS_MNEMONIC_FYL2X:
            // ST(1) = ST(1) * log2(ST(0)), then pop ST(0)
            a.movsd(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[1]))); // ST1
            a.movsd(xmm1, qword_ptr(r15, offsetof(CpuContext, mm[0]))); // ST0

            a.sub(rsp, 40); // Align 16 + 32 shadow space
            a.mov(rax, (uint64_t)&HostFyl2x);
            a.call(rax);
            a.add(rsp, 40);

            a.movsd(qword_ptr(r15, offsetof(CpuContext, mm[1])), xmm0);
            emitFpuPop();
            break;

        case ZYDIS_MNEMONIC_FPTAN:
            // ST(0) = tan(ST(0)), then push 1.0 onto FPU stack
            a.movsd(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            a.lea(rdx, ptr(r15, offsetof(CpuContext, fpuStatus)));
            a.sub(rsp, 40); // Align 16 + 32 shadow space + 8-byte padding
            a.mov(rax, (uint64_t)&HostFptan);
            a.call(rax);
            a.add(rsp, 40);
            a.movsd(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);

            // push 1.0
            emitFpuPush();
            a.mov(rax, 0x3FF0000000000000ULL); // 1.0 as double
            a.mov(qword_ptr(r15, offsetof(CpuContext, mm[0])), rax);
            break;

        case ZYDIS_MNEMONIC_FXAM:
            // Examines ST(0) (which is mm[0]) and sets FPU status word condition flags C0, C1, C2, C3.
            a.movsd(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            a.sub(rsp, 40); // Align 16 + 32 shadow space
            a.mov(rax, (uint64_t)&HostFxam);
            a.call(rax);
            a.add(rsp, 40);
            a.mov(cx, word_ptr(r15, offsetof(CpuContext, fpuStatus)));
            a.and_(cx, 0xB8FF);
            a.or_(cx, ax);
            a.mov(word_ptr(r15, offsetof(CpuContext, fpuStatus)), cx);
            break;

        case ZYDIS_MNEMONIC_FCOS:
            // ST(0) = cos(ST(0))
            a.movsd(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            a.lea(rdx, ptr(r15, offsetof(CpuContext, fpuStatus)));
            a.sub(rsp, 40); // Align 16 + 32 shadow space + 8-byte padding
            a.mov(rax, (uint64_t)&HostFcos);
            a.call(rax);
            a.add(rsp, 40);
            a.movsd(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
            break;

        case ZYDIS_MNEMONIC_FSIN:
            // ST(0) = sin(ST(0))
            a.movsd(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));
            // HostFcos(double, uint16_t*): the pointer is the second
            // positional slot (RDX) on Win64, but the first *integer*
            // argument (RDI) on SysV. The double stays in XMM0 for both.
            #ifdef _WIN32
            a.lea(rdx, ptr(r15, offsetof(CpuContext, fpuStatus)));
            #else
            a.lea(rdi, ptr(r15, offsetof(CpuContext, fpuStatus)));
            #endif
            a.sub(rsp, 40); // Align 16 + 32 shadow space + 8-byte padding
            a.mov(rax, (uint64_t)&HostFsin);
            a.call(rax);
            a.add(rsp, 40);
            a.movsd(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
            break;

        case ZYDIS_MNEMONIC_FSINCOS:
            // Computes both sin and cos of ST(0)
            // ST(0) = sin(ST(0)), ST(1) = cos(ST(0)) after push.
            a.movsd(xmm3, qword_ptr(r15, offsetof(CpuContext, mm[0])));

            // 1. Compute sin(ST(0))
            a.movaps(xmm0, xmm3);
            // HostFsin(double, uint16_t*): the pointer is the second
            // positional slot (RDX) on Win64, but the first *integer*
            // argument (RDI) on SysV. The double stays in XMM0 for both.
            #ifdef _WIN32
            a.lea(rdx, ptr(r15, offsetof(CpuContext, fpuStatus)));
            #else
            a.lea(rdi, ptr(r15, offsetof(CpuContext, fpuStatus)));
            #endif
            a.sub(rsp, 40); // Align 16 + 32 shadow space + 8-byte padding
            a.movups(qword_ptr(rsp, 24), xmm3);
            a.mov(rax, (uint64_t)&HostFsin);
            a.call(rax);
            a.movups(xmm3, qword_ptr(rsp, 24));
            a.add(rsp, 40);
            a.movaps(xmm4, xmm0); // XMM4 = sin

            // 2. Compute cos(ST(0))
            a.movaps(xmm0, xmm3);
            a.lea(rdx, ptr(r15, offsetof(CpuContext, fpuStatus)));
            a.sub(rsp, 40);
            a.movups(qword_ptr(rsp, 24), xmm4);
            a.mov(rax, (uint64_t)&HostFcos);
            a.call(rax);
            a.movups(xmm4, qword_ptr(rsp, 24));
            a.add(rsp, 40);
            // XMM0 = cos

            // 3. ST(0) = sin (XMM4)
            a.movsd(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm4);

            // 4. Push cos (XMM0) to stack (making it new ST(0))
            a.movaps(xmm3, xmm0);
            emitFpuPush();
            a.movsd(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm3);
            break;

        case ZYDIS_MNEMONIC_FRNDINT:
            // FRNDINT: Round ST0 to integer using the current rounding mode
            {
                // ST0 is stored in the first FPU/MMX register slot
                a.movq(xmm0, qword_ptr(r15, offsetof(CpuContext, mm[0])));

                // Safely load the 16-bit FPU Control Word
                a.movzx(r10d, word_ptr(r15, offsetof(CpuContext, fpuControl)));

                // Extract the 2-bit Rounding Control (RC) field (bits 10-11)
                a.shr(r10d, 10);
                a.and_(r10d, 3);

                Label roundDown = a.newLabel();
                Label roundUp = a.newLabel();
                Label roundChop = a.newLabel();
                Label rounded = a.newLabel();

                // Branch based on FPU Control Word RC bits (0=Nearest, 1=Down, 2=Up, 3=Chop)
                a.cmp(r10d, 1);
                a.je(roundDown);
                a.cmp(r10d, 2);
                a.je(roundUp);
                a.cmp(r10d, 3);
                a.je(roundChop);

                // Case 0: Round to nearest (even)
                a.roundsd(xmm0, xmm0, 0);
                a.jmp(rounded);

                a.bind(roundDown);
                // Case 1: Round down (toward -infinity)
                a.roundsd(xmm0, xmm0, 1);
                a.jmp(rounded);

                a.bind(roundUp);
                // Case 2: Round up (toward +infinity)
                a.roundsd(xmm0, xmm0, 2);
                a.jmp(rounded);

                a.bind(roundChop);
                // Case 3: Round toward zero (truncate/chop)
                a.roundsd(xmm0, xmm0, 3);

                a.bind(rounded);
                // Write the rounded result back to ST0
                a.movq(qword_ptr(r15, offsetof(CpuContext, mm[0])), xmm0);
            }
            break;

        case ZYDIS_MNEMONIC_FNSTCW:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    a.mov(r9w, word_ptr(r15, offsetof(CpuContext, fpuControl)));
                    a.mov(word_ptr(r14, r8, 0), r9w);
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_FLDCW:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    a.mov(r9w, word_ptr(r14, r8, 0));
                    a.mov(word_ptr(r15, offsetof(CpuContext, fpuControl)), r9w);
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_FWAIT:
            // Pending x87 exceptions are not modeled yet.
            break;

        // SSE Instructions
        case ZYDIS_MNEMONIC_MOVSS:
            // MOVSS: Move scalar single-precision float
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                // Load from memory to XMM register
                if (resolveMemoryIntoR8(operands[1].mem))
                {
                    int xmmIndex = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
                    if (xmmIndex >= 0 && xmmIndex < 8)
                    {
                        a.movss(xmm0, dword_ptr(r14, r8, 0));
                        a.movss(dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmIndex * 16), xmm0);
                    }
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                // Store from XMM register to memory
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    int xmmIndex = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
                    if (xmmIndex >= 0 && xmmIndex < 8)
                    {
                        a.movss(xmm0, dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmIndex * 16));
                        a.movss(dword_ptr(r14, r8, 0), xmm0);
                    }
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                // XMM to XMM
                int xmmSrc = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
                int xmmDst = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
                if (xmmSrc >= 0 && xmmSrc < 8 && xmmDst >= 0 && xmmDst < 8)
                {
                    a.movss(xmm0, dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmSrc * 16));
                    a.movss(dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmDst * 16), xmm0);
                }
            }
            break;

        case ZYDIS_MNEMONIC_CVTTSS2SI:
            // Convert float (truncate) to signed 32-bit int: reg32 = (int)xmm
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int dstOff = getRegOffset(operands[0].reg.value);
                int xmmSrc = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
                if (dstOff != -1 && xmmSrc >= 0 && xmmSrc < 8)
                {
                    a.movss(xmm0, dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmSrc * 16));
                    a.cvttss2si(eax, xmm0);
                    a.mov(dword_ptr(r15, dstOff), eax);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                int dstOff = getRegOffset(operands[0].reg.value);
                if (dstOff != -1 && resolveMemoryIntoR8(operands[1].mem))
                {
                    a.movss(xmm0, dword_ptr(r14, r8, 0));
                    a.cvttss2si(eax, xmm0);
                    a.mov(dword_ptr(r15, dstOff), eax);
                }
                else
                    return nullptr;
            }
            break;

        case ZYDIS_MNEMONIC_CVTSI2SS:
            // Convert signed 32-bit int to float: xmm = (float)reg32
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int xmmDst = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
                int srcOff = getRegOffset(operands[1].reg.value);
                if (xmmDst >= 0 && xmmDst < 8 && srcOff != -1)
                {
                    a.mov(eax, dword_ptr(r15, srcOff));
                    a.cvtsi2ss(xmm0, eax);
                    a.movss(dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmDst * 16), xmm0);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                int xmmDst = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
                if (xmmDst >= 0 && xmmDst < 8 && resolveMemoryIntoR8(operands[1].mem))
                {
                    a.mov(eax, dword_ptr(r14, r8, 0));
                    a.cvtsi2ss(xmm0, eax);
                    a.movss(dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmDst * 16), xmm0);
                }
                else
                    return nullptr;
            }
            break;

        case ZYDIS_MNEMONIC_ADDSS:
            // Add scalar single: xmm = xmm + xmm/mem
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int xmmDst = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
                int xmmSrc = operands[1].reg.value - ZYDIS_REGISTER_XMM0;
                if (xmmDst >= 0 && xmmDst < 8 && xmmSrc >= 0 && xmmSrc < 8)
                {
                    a.movss(xmm0, dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmDst * 16));
                    a.movss(xmm1, dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmSrc * 16));
                    a.addss(xmm0, xmm1);
                    a.movss(dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmDst * 16), xmm0);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                int xmmDst = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
                if (xmmDst >= 0 && xmmDst < 8 && resolveMemoryIntoR8(operands[1].mem))
                {
                    a.movss(xmm0, dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmDst * 16));
                    a.addss(xmm0, dword_ptr(r14, r8, 0));
                    a.movss(dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmDst * 16), xmm0);
                }
                else
                    return nullptr;
            }
            break;

        case ZYDIS_MNEMONIC_SUBSS:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                int xmmDst = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
                if (xmmDst >= 0 && xmmDst < 8 && resolveMemoryIntoR8(operands[1].mem))
                {
                    a.movss(xmm0, dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmDst * 16));
                    a.subss(xmm0, dword_ptr(r14, r8, 0));
                    a.movss(dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmDst * 16), xmm0);
                }
                else
                    return nullptr;
            }
            break;

        case ZYDIS_MNEMONIC_MULSS:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                int xmmDst = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
                if (xmmDst >= 0 && xmmDst < 8 && resolveMemoryIntoR8(operands[1].mem))
                {
                    a.movss(xmm0, dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmDst * 16));
                    a.mulss(xmm0, dword_ptr(r14, r8, 0));
                    a.movss(dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmDst * 16), xmm0);
                }
                else
                    return nullptr;
            }
            break;

        case ZYDIS_MNEMONIC_DIVSS:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                int xmmDst = operands[0].reg.value - ZYDIS_REGISTER_XMM0;
                if (xmmDst >= 0 && xmmDst < 8 && resolveMemoryIntoR8(operands[1].mem))
                {
                    a.movss(xmm0, dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmDst * 16));
                    a.divss(xmm0, dword_ptr(r14, r8, 0));
                    a.movss(dword_ptr(r15, offsetof(CpuContext, xmm[0]) + xmmDst * 16), xmm0);
                }
                else
                    return nullptr;
            }
            break;

        case ZYDIS_MNEMONIC_PUSH:
        {
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off == -1)
                    goto unimplemented;

                a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));
                uint32_t pushSize = (uint32_t)operands[0].size / 8;
                // In 32-bit mode, pushing a segment register always uses 4 bytes
                if (!isNE && !isMZ && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (operands[0].reg.value >= ZYDIS_REGISTER_ES && operands[0].reg.value <= ZYDIS_REGISTER_GS))
                {
                    pushSize = 4;
                }
                a.lea(r8d, dword_ptr(r8d, -(int)pushSize)); // LEA preserves flags for test→jnz chains
                if (isNE || isMZ)
                    a.movzx(r8d, r8w);
                a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);

                if (isNE || isMZ)
                {
                    a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                    a.lea(r10, dword_ptr(r14, r8));
                    a.add(r10, r11);
                }
                else
                {
                    a.lea(r10, dword_ptr(r14, r8));
                }

                if (operands[0].size == 8)
                {
                    a.mov(r9b, byte_ptr(r15, off));
                    a.mov(byte_ptr(r10, 0), r9b);
                }
                else if (operands[0].size == 16)
                {
                    a.mov(r9w, word_ptr(r15, off));
                    if (pushSize == 4)
                    {
                        a.movzx(r9d, r9w);
                        a.mov(dword_ptr(r10, 0), r9d);
                    }
                    else
                    {
                        a.mov(word_ptr(r10, 0), r9w);
                    }
                }
                else
                {
                    a.mov(r9d, dword_ptr(r15, off));
                    a.mov(dword_ptr(r10, 0), r9d);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t pushSize = instr.operand_width / 8;
                if (pushSize == 0)
                    pushSize = (!isNE && !isMZ) ? 4 : 2; // Fallback

                a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));
                a.lea(r8d, dword_ptr(r8d, -(int)pushSize));
                if (isNE || isMZ)
                    a.movzx(r8d, r8w);
                a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);

                if (isNE || isMZ)
                {
                    a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                    a.lea(r10, dword_ptr(r14, r8));
                    a.add(r10, r11);
                }
                else
                {
                    a.lea(r10, dword_ptr(r14, r8));
                }

                if (pushSize == 2)
                {
                    a.mov(word_ptr(r10, 0), (uint16_t)operands[0].imm.value.s);
                }
                else
                {
                    a.mov(dword_ptr(r10, 0), (uint32_t)operands[0].imm.value.s);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    const uint32_t pushSize = (uint32_t)operands[0].size / 8;
                    // x86 PUSH reads the source operand before updating ESP.
                    // Cache the value first so stack-based sources see the
                    // original address/value, then commit the stack change.
                    if (operands[0].size == 16)
                    {
                        a.mov(r9w, word_ptr(r14, r8, 0));
                        a.mov(r10d, dword_ptr(r15, offsetof(CpuContext, esp)));
                        a.lea(r10d, dword_ptr(r10d, -(int)pushSize));
                        if (isNE || isMZ)
                            a.movzx(r10d, r10w);

                        if (isNE || isMZ)
                        {
                            a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                            a.lea(r12, dword_ptr(r14, r10));
                            a.add(r12, r11);
                            a.mov(word_ptr(r12, 0), r9w);
                        }
                        else
                        {
                            a.mov(word_ptr(r14, r10, 0), r9w);
                        }
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r14, r8, 0));
                        a.mov(r10d, dword_ptr(r15, offsetof(CpuContext, esp)));
                        a.lea(r10d, dword_ptr(r10d, -(int)pushSize));
                        if (isNE || isMZ)
                            a.movzx(r10d, r10w);

                        if (isNE || isMZ)
                        {
                            a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                            a.lea(r12, dword_ptr(r14, r10));
                            a.add(r12, r11);
                            a.mov(dword_ptr(r12, 0), r9d);
                        }
                        else
                        {
                            a.mov(dword_ptr(r14, r10, 0), r9d);
                        }
                    }
                    a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r10d);
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
        }
        break;

        case ZYDIS_MNEMONIC_POP:
        {
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, esp)));
                    uint32_t popSize = (uint32_t)operands[0].size / 8;
                    // In 32-bit mode, popping a segment register always uses 4 bytes
                    if (!isNE && !isMZ && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        (operands[0].reg.value >= ZYDIS_REGISTER_ES && operands[0].reg.value <= ZYDIS_REGISTER_GS))
                    {
                        popSize = 4;
                    }

                    if (isNE || isMZ)
                    {
                        a.movzx(r9d, r9w);
                        a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                        a.lea(r10, dword_ptr(r14, r9));
                        a.add(r10, r11);
                    }
                    else
                    {
                        a.lea(r10, dword_ptr(r14, r9));
                    }

                    if (operands[0].size == 16)
                    {
                        a.movzx(r8d, word_ptr(r10, 0));
                        a.lea(r9d, dword_ptr(r9d, popSize));
                        if (isNE || isMZ)
                            a.movzx(r9d, r9w);
                        a.mov(word_ptr(r15, off), r8w);
                    }
                    else
                    {
                        a.mov(r8d, dword_ptr(r10, 0));
                        a.lea(r9d, dword_ptr(r9d, popSize));
                        if (isNE || isMZ)
                            a.movzx(r9d, r9w);
                        a.mov(dword_ptr(r15, off), r8d);
                    }
                    a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r9d);

                    if (operands[0].reg.value >= ZYDIS_REGISTER_ES && operands[0].reg.value <= ZYDIS_REGISTER_GS)
                    {
                        a.sub(rsp, 40);
                        a.mov(rcx, r15);
                        a.mov(rdx, r14);
                        a.mov(r8, r13);
                        a.mov(r9d, (uint32_t)operands[0].reg.value);
                        a.mov(rax, (uint64_t)UpdateSegRegFromContextStub);
                        EmitHostAbiArgs(a);
                        a.call(rax);
                        a.add(rsp, 40);
                    }
                }
                else
                    goto unimplemented;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, esp)));

                    if (isNE || isMZ)
                    {
                        a.movzx(r9d, r9w);
                        a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                        a.lea(r10, dword_ptr(r14, r9));
                        a.add(r10, r11);
                    }
                    else
                    {
                        a.lea(r10, dword_ptr(r14, r9));
                    }

                    if (operands[0].size == 8)
                    {
                        a.mov(r10b, byte_ptr(r10, 0));
                        a.lea(r9d, dword_ptr(r9d, 1));
                        if (isNE || isMZ)
                            a.movzx(r9d, r9w);
                        a.mov(byte_ptr(r14, r8, 0), r10b);
                    }
                    else if (operands[0].size == 16)
                    {
                        a.mov(r10w, word_ptr(r10, 0));
                        a.lea(r9d, dword_ptr(r9d, 2));
                        if (isNE || isMZ)
                            a.movzx(r9d, r9w);
                        a.mov(word_ptr(r14, r8, 0), r10w);
                    }
                    else
                    {
                        a.mov(r10d, dword_ptr(r10, 0));
                        a.lea(r9d, dword_ptr(r9d, 4));
                        if (isNE || isMZ)
                            a.movzx(r9d, r9w);
                        a.mov(dword_ptr(r14, r8, 0), r10d);
                    }
                    a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r9d);
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
        }
        break;

        case ZYDIS_MNEMONIC_ENTER:
        {
            // ENTER locals_size, nesting_level
            // For nesting_level == 0: push ebp; mov ebp, esp; sub esp, locals_size
            // For nesting_level > 0: also push old frame pointers
            uint32_t localsSize = (uint32_t)operands[0].imm.value.u;
            uint32_t nesting = (uint32_t)operands[1].imm.value.u % 32; // CPU masks nesting by mod 32

            // Load initial ESP and decrement to push EBP
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));
            a.lea(r8d, dword_ptr(r8d, -4));

            // FrameTemp (the new EBP value) is the ESP state immediately after pushing EBP
            a.mov(r10d, r8d);

            // Push the old EBP to the stack
            a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, ebp)));
            a.mov(dword_ptr(r14, r8, 0), r9d);

            if (nesting > 0)
            {
                for (uint32_t i = 1; i < nesting; i++)
                {
                    // Load EBP and safely read old frame pointers using explicit 0-shift
                    a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, ebp)));
                    a.mov(r11d, dword_ptr(r14, r9, 0, -(int)(i * 4))); // [old_ebp - i*4]

                    a.lea(r8d, dword_ptr(r8d, -4));
                    a.mov(dword_ptr(r14, r8, 0), r11d);
                }

                // Push the new frame pointer (FrameTemp) to the stack
                a.lea(r8d, dword_ptr(r8d, -4));
                a.mov(dword_ptr(r14, r8, 0), r10d);
            }

            // EBP always receives FrameTemp (stored safely in r10d)
            a.mov(dword_ptr(r15, offsetof(CpuContext, ebp)), r10d);

            // Allocate local space on the stack if requested
            if (localsSize > 0)
            {
                a.lea(r8d, dword_ptr(r8d, -(int)localsSize));
            }
            a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
        }
        break;

        case ZYDIS_MNEMONIC_LEAVE:
        {
            // LEAVE: Set ESP to EBP, then POP EBP

            // r8d = EBP (acts as the new ESP prior to popping)
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, ebp)));

            // Read the saved old EBP from the stack: [EBP] -> r9d
            a.mov(r9d, dword_ptr(r14, r8, 0));

            // Restore the old EBP into the CPU context
            a.mov(dword_ptr(r15, offsetof(CpuContext, ebp)), r9d);

            // Update the ESP context value: ESP = EBP + 4 (LEA preserves flags)
            a.lea(r8d, dword_ptr(r8d, 4));
            a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
        }
        break;

        case ZYDIS_MNEMONIC_LDS:
        case ZYDIS_MNEMONIC_LES:
        case ZYDIS_MNEMONIC_LSS:
        case ZYDIS_MNEMONIC_LFS:
        case ZYDIS_MNEMONIC_LGS:
        {
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                int offDst = getRegOffset(operands[0].reg.value);
                ZydisRegister segReg;
                switch (instr.mnemonic)
                {
                case ZYDIS_MNEMONIC_LDS: segReg = ZYDIS_REGISTER_DS; break;
                case ZYDIS_MNEMONIC_LES: segReg = ZYDIS_REGISTER_ES; break;
                case ZYDIS_MNEMONIC_LSS: segReg = ZYDIS_REGISTER_SS; break;
                case ZYDIS_MNEMONIC_LFS: segReg = ZYDIS_REGISTER_FS; break;
                case ZYDIS_MNEMONIC_LGS: segReg = ZYDIS_REGISTER_GS; break;
                default: segReg = ZYDIS_REGISTER_DS; break;
                }
                int offSeg = getRegOffset(segReg);
                if (offDst != -1 && offSeg != -1 && resolveMemoryIntoR8(operands[1].mem))
                {
                    if (operands[0].size == 16)
                    {
                        // 16-bit far pointer: offset at [r8], selector at [r8+2]
                        a.mov(r9w, word_ptr(r14, r8, 0));
                        a.mov(r10w, word_ptr(r14, r8, 0, 2));
                        a.mov(word_ptr(r15, offDst), r9w);
                        a.mov(word_ptr(r15, offSeg), r10w);
                    }
                    else
                    {
                        // 32-bit far pointer: offset at [r8], selector at [r8+4]
                        a.mov(r9d, dword_ptr(r14, r8, 0));
                        a.mov(r10w, word_ptr(r14, r8, 0, 4));
                        a.mov(dword_ptr(r15, offDst), r9d);
                        a.mov(word_ptr(r15, offSeg), r10w);
                    }

                    // Update the segment base for the newly loaded selector.
                    a.sub(rsp, 40);
                    a.mov(rcx, r15);
                    a.mov(rdx, r14);
                    a.mov(r8, r13);
                    a.mov(r9d, (uint32_t)segReg);
                    a.mov(rax, (uint64_t)UpdateSegRegFromContextStub);
                    EmitHostAbiArgs(a);
                    a.call(rax);
                    a.add(rsp, 40);
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
        }
        break;

        case ZYDIS_MNEMONIC_MOV:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    uint32_t val = (uint32_t)operands[1].imm.value.s;
                    if (operands[0].size == 8)
                        a.mov(byte_ptr(r15, off), (uint8_t)val);
                    else if (operands[0].size == 16)
                        a.mov(word_ptr(r15, off), (uint16_t)val);
                    else
                        a.mov(dword_ptr(r15, off), val);

                    if (operands[0].reg.value >= ZYDIS_REGISTER_ES && operands[0].reg.value <= ZYDIS_REGISTER_GS)
                    {
                        a.sub(rsp, 40);
                        a.mov(rcx, r15);
                        a.mov(rdx, r14);
                        a.mov(r8, r13);
                        a.mov(r9d, (uint32_t)operands[0].reg.value);
                        a.mov(rax, (uint64_t)UpdateSegRegFromContextStub);
                        EmitHostAbiArgs(a);
                        a.call(rax);
                        a.add(rsp, 40);
                    }
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int offDst = getRegOffset(operands[0].reg.value);
                int offSrc = getRegOffset(operands[1].reg.value);
                if (offDst != -1 && offSrc != -1)
                {
                    if (operands[1].size == 8)
                    {
                        a.mov(r8b, byte_ptr(r15, offSrc));
                    }
                    else if (operands[1].size == 16)
                    {
                        a.mov(r8w, word_ptr(r15, offSrc));
                    }
                    else
                    {
                        a.mov(r8d, dword_ptr(r15, offSrc));
                    }

                    if (operands[0].size == 8)
                    {
                        a.mov(byte_ptr(r15, offDst), r8b);
                    }
                    else if (operands[0].size == 16)
                    {
                        a.mov(word_ptr(r15, offDst), r8w);
                    }
                    else
                    {
                        if (operands[1].size == 16)
                        {
                            a.movzx(r8d, r8w);
                        }
                        else if (operands[1].size == 8)
                        {
                            a.movzx(r8d, r8b);
                        }
                        a.mov(dword_ptr(r15, offDst), r8d);
                    }

                    if (operands[0].reg.value >= ZYDIS_REGISTER_ES && operands[0].reg.value <= ZYDIS_REGISTER_GS)
                    {
                        a.sub(rsp, 40);
                        a.mov(rcx, r15);
                        a.mov(rdx, r14);
                        a.mov(r8, r13);
                        a.mov(r9d, (uint32_t)operands[0].reg.value);
                        a.mov(rax, (uint64_t)UpdateSegRegFromContextStub);
                        EmitHostAbiArgs(a);
                        a.call(rax);
                        a.add(rsp, 40);
                    }
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[0].size == 8)
                        a.mov(byte_ptr(r14, r8, 0), (uint8_t)operands[1].imm.value.s);
                    else if (operands[0].size == 16)
                        a.mov(word_ptr(r14, r8, 0), (uint16_t)operands[1].imm.value.s);
                    else
                        a.mov(dword_ptr(r14, r8, 0), (uint32_t)operands[1].imm.value.s);

                    emitDosVramMirror(r8d, (int)(operands[0].size / 8));
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1 && resolveMemoryIntoR8(operands[1].mem))
                {
                    emitDosVramLatch(r8d, (int)(operands[0].size / 8));

                    if (operands[0].size == 8)
                    {
                        a.mov(r9b, byte_ptr(r14, r8, 0));
                        a.mov(byte_ptr(r15, off), r9b);
                    }
                    else if (operands[0].size == 16)
                    {
                        a.mov(r9w, word_ptr(r14, r8, 0));
                        a.mov(word_ptr(r15, off), r9w);
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r14, r8, 0));
                        a.mov(dword_ptr(r15, off), r9d);
                    }

                    if (operands[0].reg.value >= ZYDIS_REGISTER_ES && operands[0].reg.value <= ZYDIS_REGISTER_GS)
                    {
                        a.sub(rsp, 40);
                        a.mov(rcx, r15);
                        a.mov(rdx, r14);
                        a.mov(r8, r13);
                        a.mov(r9d, (uint32_t)operands[0].reg.value);
                        a.mov(rax, (uint64_t)UpdateSegRegFromContextStub);
                        EmitHostAbiArgs(a);
                        a.call(rax);
                        a.add(rsp, 40);
                    }
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[1].reg.value);
                if (off != -1 && resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[1].size == 8)
                    {
                        a.mov(r9b, byte_ptr(r15, off));
                        a.mov(byte_ptr(r14, r8, 0), r9b);
                    }
                    else if (operands[1].size == 16)
                    {
                        a.mov(r9w, word_ptr(r15, off));
                        a.mov(word_ptr(r14, r8, 0), r9w);
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r15, off));
                        a.mov(dword_ptr(r14, r8, 0), r9d);
                    }

                    emitDosVramMirror(r8d, (int)(operands[1].size / 8));
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_MOVZX:
        case ZYDIS_MNEMONIC_MOVSX:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int offDst = getRegOffset(operands[0].reg.value);
                if (offDst == -1)
                {
                    std::cerr << "[JIT] MOVZX/MOVSX: offDst == -1 for reg " << ZydisRegisterGetString(operands[0].reg.value) << std::endl;
                    return nullptr;
                }

                if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    int offSrc = getRegOffset(operands[1].reg.value);
                    if (offSrc == -1)
                    {
                        std::cerr << "[JIT] MOVZX/MOVSX: offSrc == -1 for reg " << ZydisRegisterGetString(operands[1].reg.value) << std::endl;
                        return nullptr;
                    }

                    if (operands[1].size == 8)
                    {
                        a.mov(r8b, byte_ptr(r15, offSrc));
                        if (instr.mnemonic == ZYDIS_MNEMONIC_MOVZX)
                            a.movzx(r9d, r8b);
                        else
                            a.movsx(r9d, r8b);
                    }
                    else if (operands[1].size == 16)
                    {
                        a.mov(r8w, word_ptr(r15, offSrc));
                        if (instr.mnemonic == ZYDIS_MNEMONIC_MOVZX)
                            a.movzx(r9d, r8w);
                        else
                            a.movsx(r9d, r8w);
                    }
                    else
                    {
                        std::cerr << "[JIT] MOVZX/MOVSX: Unexpected src reg size " << operands[1].size << std::endl;
                        return nullptr;
                    }
                    a.mov(dword_ptr(r15, offDst), r9d);
                }
                else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    if (resolveMemoryIntoR8(operands[1].mem))
                    {
                        emitDosVramLatch(r8d, (int)(operands[1].size / 8));

                        if (operands[1].size == 8)
                        {
                            a.mov(r9b, byte_ptr(r14, r8, 0));
                            if (operands[0].size == 16)
                            {
                                if (instr.mnemonic == ZYDIS_MNEMONIC_MOVZX)
                                    a.movzx(r10w, r9b);
                                else
                                    a.movsx(r10w, r9b);
                                a.mov(word_ptr(r15, offDst), r10w);
                            }
                            else
                            {
                                if (instr.mnemonic == ZYDIS_MNEMONIC_MOVZX)
                                    a.movzx(r10d, r9b);
                                else
                                    a.movsx(r10d, r9b);
                                a.mov(dword_ptr(r15, offDst), r10d);
                            }
                        }
                        else if (operands[1].size == 16)
                        {
                            a.mov(r9w, word_ptr(r14, r8, 0));
                            if (instr.mnemonic == ZYDIS_MNEMONIC_MOVZX)
                                a.movzx(r10d, r9w);
                            else
                                a.movsx(r10d, r9w);
                            a.mov(dword_ptr(r15, offDst), r10d);
                        }
                        else
                        {
                            std::cerr << "[JIT] MOVZX/MOVSX: Unexpected mem size " << operands[1].size << std::endl;
                            return nullptr;
                        }
                    }
                    else
                    {
                        std::cerr << "[JIT] MOVZX/MOVSX: resolveMemoryIntoR8 failed" << std::endl;
                        return nullptr;
                    }
                }
                else
                {
                    std::cerr << "[JIT] MOVZX/MOVSX: Unexpected op[1] type " << (int)operands[1].type << std::endl;
                    return nullptr;
                }
            }
            else
            {
                std::cerr << "[JIT] MOVZX/MOVSX: op[0] is not a register, type=" << (int)operands[0].type << std::endl;
                return nullptr;
            }
            break;

        case ZYDIS_MNEMONIC_BT:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    a.mov(r8d, dword_ptr(r15, off));
                    a.bt(r8d, (uint32_t)operands[1].imm.value.u); // Bit index is always unsigned
                    a.pushfq();
                    a.pop(r8);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[0].size == 16)
                        a.bt(word_ptr(r14, r8, 0), (uint32_t)operands[1].imm.value.u);
                    else
                        a.bt(dword_ptr(r14, r8, 0), (uint32_t)operands[1].imm.value.u);
                    a.pushfq();
                    a.pop(r8);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off0 = getRegOffset(operands[0].reg.value);
                int off1 = getRegOffset(operands[1].reg.value);
                if (off0 != -1 && off1 != -1)
                {
                    if (operands[0].size == 16)
                    {
                        a.mov(r8w, word_ptr(r15, off0));
                        a.mov(r9w, word_ptr(r15, off1));
                        a.bt(r8w, r9w);
                    }
                    else
                    {
                        a.mov(r8d, dword_ptr(r15, off0));
                        a.mov(r9d, dword_ptr(r15, off1));
                        a.bt(r8d, r9d);
                    }
                    a.pushfq();
                    a.pop(r8);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[1].reg.value);
                if (off != -1 && resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[0].size == 16)
                    {
                        a.mov(r9w, word_ptr(r15, off));
                        a.bt(word_ptr(r14, r8, 0), r9w);
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r15, off));
                        a.bt(dword_ptr(r14, r8, 0), r9d);
                    }
                    a.pushfq();
                    a.pop(r8);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_BTS:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    if (operands[0].size == 16)
                    {
                        a.mov(r8w, word_ptr(r15, off));
                        a.bts(r8w, (uint32_t)operands[1].imm.value.u);
                        a.mov(word_ptr(r15, off), r8w);
                    }
                    else
                    {
                        a.mov(r8d, dword_ptr(r15, off));
                        a.bts(r8d, (uint32_t)operands[1].imm.value.u);
                        a.mov(dword_ptr(r15, off), r8d);
                    }
                    a.pushfq();
                    a.pop(r8);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off0 = getRegOffset(operands[0].reg.value);
                int off1 = getRegOffset(operands[1].reg.value);
                if (off0 != -1 && off1 != -1)
                {
                    if (operands[0].size == 16)
                    {
                        a.mov(r8w, word_ptr(r15, off0));
                        a.mov(r9w, word_ptr(r15, off1));
                        a.bts(r8w, r9w);
                        a.mov(word_ptr(r15, off0), r8w);
                    }
                    else
                    {
                        a.mov(r8d, dword_ptr(r15, off0));
                        a.mov(r9d, dword_ptr(r15, off1));
                        a.bts(r8d, r9d);
                        a.mov(dword_ptr(r15, off0), r8d);
                    }
                    a.pushfq();
                    a.pop(r8);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[0].size == 16)
                        a.bts(word_ptr(r14, r8, 0), (uint32_t)operands[1].imm.value.u);
                    else
                        a.bts(dword_ptr(r14, r8, 0), (uint32_t)operands[1].imm.value.u);
                    a.pushfq();
                    a.pop(r8);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[1].reg.value);
                if (off != -1 && resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[0].size == 16)
                    {
                        a.mov(r9w, word_ptr(r15, off));
                        a.bts(word_ptr(r14, r8, 0), r9w);
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r15, off));
                        a.bts(dword_ptr(r14, r8, 0), r9d);
                    }
                    a.pushfq();
                    a.pop(r8);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_LEA:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1 && resolveEffectiveAddressIntoR8(operands[1].mem))
                {
                    a.mov(dword_ptr(r15, off), r8d);
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_SBB:
            // SBB dst, src: dst = dst - src - CF
            {
                // High-performance injection: Shift guest CF (bit 0) directly into host CF
                auto setHostCfFromGuest = [&]()
                {
                    a.mov(r11b, byte_ptr(r15, offsetof(CpuContext, eflags)));
                    a.shr(r11b, 1);
                };

                auto storeReg = [&](int off, int size)
                {
                    if (size == 8)
                        a.mov(byte_ptr(r15, off), r8b);
                    else if (size == 16)
                        a.mov(word_ptr(r15, off), r8w);
                    else
                        a.mov(dword_ptr(r15, off), r8d);
                };

                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    int off0 = getRegOffset(operands[0].reg.value);
                    int off1 = getRegOffset(operands[1].reg.value);
                    if (off0 != -1 && off1 != -1)
                    {
                        a.mov(r8d, dword_ptr(r15, off0));
                        a.mov(r9d, dword_ptr(r15, off1));

                        setHostCfFromGuest();

                        if (operands[0].size == 8)
                            a.sbb(r8b, r9b);
                        else if (operands[0].size == 16)
                            a.sbb(r8w, r9w);
                        else
                            a.sbb(r8d, r9d);

                        a.pushfq();
                        a.pop(r10);
                        storeReg(off0, operands[0].size);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
                    }
                    else
                        return nullptr;
                }
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    int off = getRegOffset(operands[0].reg.value);
                    if (off != -1)
                    {
                        a.mov(r8d, dword_ptr(r15, off));
                        uint32_t val = (uint32_t)operands[1].imm.value.s;

                        setHostCfFromGuest();

                        if (operands[0].size == 8)
                            a.sbb(r8b, (uint8_t)val);
                        else if (operands[0].size == 16)
                            a.sbb(r8w, (uint16_t)val);
                        else
                            a.sbb(r8d, val);

                        a.pushfq();
                        a.pop(r10);
                        storeReg(off, operands[0].size);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
                    }
                    else
                        return nullptr;
                }
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    int off = getRegOffset(operands[0].reg.value);
                    if (off != -1 && resolveMemoryIntoR8(operands[1].mem))
                    {
                        a.mov(r10d, dword_ptr(r15, off));

                        // Safe memory read matching the exact operand size
                        if (operands[0].size == 8)
                            a.movzx(r9d, byte_ptr(r14, r8));
                        else if (operands[0].size == 16)
                            a.movzx(r9d, word_ptr(r14, r8));
                        else
                            a.mov(r9d, dword_ptr(r14, r8));

                        setHostCfFromGuest();

                        if (operands[0].size == 8)
                            a.sbb(r10b, r9b);
                        else if (operands[0].size == 16)
                            a.sbb(r10w, r9w);
                        else
                            a.sbb(r10d, r9d);

                        // Save host flags in r9 (safely recycling r9)
                        a.pushfq();
                        a.pop(r9);

                        if (operands[0].size == 8)
                            a.mov(byte_ptr(r15, off), r10b);
                        else if (operands[0].size == 16)
                            a.mov(word_ptr(r15, off), r10w);
                        else
                            a.mov(dword_ptr(r15, off), r10d);

                        a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r9d);
                    }
                    else
                        return nullptr;
                }
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    int off = getRegOffset(operands[1].reg.value);
                    if (off != -1 && resolveMemoryIntoR8(operands[0].mem))
                    {
                        a.mov(r9d, dword_ptr(r15, off));

                        // Safe memory read matching the exact operand size
                        if (operands[0].size == 8)
                            a.movzx(r10d, byte_ptr(r14, r8));
                        else if (operands[0].size == 16)
                            a.movzx(r10d, word_ptr(r14, r8));
                        else
                            a.mov(r10d, dword_ptr(r14, r8));

                        setHostCfFromGuest();

                        if (operands[0].size == 8)
                            a.sbb(r10b, r9b);
                        else if (operands[0].size == 16)
                            a.sbb(r10w, r9w);
                        else
                            a.sbb(r10d, r9d);

                        // Save host flags in r9 (safely recycling r9)
                        a.pushfq();
                        a.pop(r9);

                        if (operands[0].size == 8)
                            a.mov(byte_ptr(r14, r8), r10b);
                        else if (operands[0].size == 16)
                            a.mov(word_ptr(r14, r8), r10w);
                        else
                            a.mov(dword_ptr(r14, r8), r10d);

                        a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r9d);
                    }
                    else
                        return nullptr;
                }
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    if (resolveMemoryIntoR8(operands[0].mem))
                    {
                        uint32_t val = (uint32_t)operands[1].imm.value.s;

                        // Safe memory read matching the exact operand size
                        if (operands[0].size == 8)
                            a.movzx(r10d, byte_ptr(r14, r8));
                        else if (operands[0].size == 16)
                            a.movzx(r10d, word_ptr(r14, r8));
                        else
                            a.mov(r10d, dword_ptr(r14, r8));

                        setHostCfFromGuest();

                        if (operands[0].size == 8)
                            a.sbb(r10b, (uint8_t)val);
                        else if (operands[0].size == 16)
                            a.sbb(r10w, (uint16_t)val);
                        else
                            a.sbb(r10d, val);

                        a.pushfq();
                        a.pop(r9);

                        if (operands[0].size == 8)
                            a.mov(byte_ptr(r14, r8), r10b);
                        else if (operands[0].size == 16)
                            a.mov(word_ptr(r14, r8), r10w);
                        else
                            a.mov(dword_ptr(r14, r8), r10d);

                        a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r9d);
                    }
                    else
                        return nullptr;
                }
                else
                    goto unimplemented;
            }
            break;

        case ZYDIS_MNEMONIC_ADC:
            // ADC dst, src: dst = dst + src + CF
            {
                // High-performance flag injection: Shift guest CF (bit 0) directly into host CF
                auto setHostCfFromGuest = [&]()
                {
                    a.mov(r11b, byte_ptr(r15, offsetof(CpuContext, eflags)));
                    a.shr(r11b, 1);
                };

                auto storeReg = [&](int off, int size)
                {
                    if (size == 8)
                        a.mov(byte_ptr(r15, off), r8b);
                    else if (size == 16)
                        a.mov(word_ptr(r15, off), r8w);
                    else
                        a.mov(dword_ptr(r15, off), r8d);
                };

                if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    if (!resolveMemoryIntoR8(operands[0].mem)) return nullptr;
                    const uint32_t val = (uint32_t)operands[1].imm.value.s;
                    if (operands[0].size == 8) a.movzx(r10d, byte_ptr(r14, r8));
                    else if (operands[0].size == 16) a.movzx(r10d, word_ptr(r14, r8));
                    else a.mov(r10d, dword_ptr(r14, r8));

                    setHostCfFromGuest();
                    if (operands[0].size == 8) a.adc(r10b, (uint8_t)val);
                    else if (operands[0].size == 16) a.adc(r10w, (uint16_t)val);
                    else a.adc(r10d, val);
                    a.pushfq();
                    a.pop(r9);

                    if (operands[0].size == 8) a.mov(byte_ptr(r14, r8), r10b);
                    else if (operands[0].size == 16) a.mov(word_ptr(r14, r8), r10w);
                    else a.mov(dword_ptr(r14, r8), r10d);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r9d);
                }
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    int off0 = getRegOffset(operands[0].reg.value);
                    int off1 = getRegOffset(operands[1].reg.value);
                    if (off0 != -1 && off1 != -1)
                    {
                        a.mov(r8d, dword_ptr(r15, off0));
                        a.mov(r9d, dword_ptr(r15, off1));

                        setHostCfFromGuest();

                        if (operands[0].size == 8)
                            a.adc(r8b, r9b);
                        else if (operands[0].size == 16)
                            a.adc(r8w, r9w);
                        else
                            a.adc(r8d, r9d);

                        a.pushfq();
                        a.pop(r10);
                        storeReg(off0, operands[0].size);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
                    }
                    else
                        return nullptr;
                }
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    int off = getRegOffset(operands[0].reg.value);
                    if (off != -1)
                    {
                        a.mov(r8d, dword_ptr(r15, off));
                        uint32_t val = (uint32_t)operands[1].imm.value.s;

                        setHostCfFromGuest();

                        if (operands[0].size == 8)
                            a.adc(r8b, (uint8_t)val);
                        else if (operands[0].size == 16)
                            a.adc(r8w, (uint16_t)val);
                        else
                            a.adc(r8d, val);

                        a.pushfq();
                        a.pop(r10);
                        storeReg(off, operands[0].size);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
                    }
                    else
                        return nullptr;
                }
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    int off = getRegOffset(operands[0].reg.value);
                    if (off != -1 && resolveMemoryIntoR8(operands[1].mem))
                    {
                        a.mov(r10d, dword_ptr(r15, off));

                        // Safe memory read matching the exact operand size
                        if (operands[0].size == 8)
                            a.movzx(r9d, byte_ptr(r14, r8));
                        else if (operands[0].size == 16)
                            a.movzx(r9d, word_ptr(r14, r8));
                        else
                            a.mov(r9d, dword_ptr(r14, r8));

                        setHostCfFromGuest();

                        if (operands[0].size == 8)
                            a.adc(r10b, r9b);
                        else if (operands[0].size == 16)
                            a.adc(r10w, r9w);
                        else
                            a.adc(r10d, r9d);

                        // Save host flags in r9 (safely recycling r9)
                        a.pushfq();
                        a.pop(r9);

                        if (operands[0].size == 8)
                            a.mov(byte_ptr(r15, off), r10b);
                        else if (operands[0].size == 16)
                            a.mov(word_ptr(r15, off), r10w);
                        else
                            a.mov(dword_ptr(r15, off), r10d);

                        a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r9d);
                    }
                    else
                        return nullptr;
                }
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    int off = getRegOffset(operands[1].reg.value);
                    if (off != -1 && resolveMemoryIntoR8(operands[0].mem))
                    {
                        a.mov(r9d, dword_ptr(r15, off));

                        // Safe memory read matching the exact operand size
                        if (operands[0].size == 8)
                            a.movzx(r10d, byte_ptr(r14, r8));
                        else if (operands[0].size == 16)
                            a.movzx(r10d, word_ptr(r14, r8));
                        else
                            a.mov(r10d, dword_ptr(r14, r8));

                        setHostCfFromGuest();

                        if (operands[0].size == 8)
                            a.adc(r10b, r9b);
                        else if (operands[0].size == 16)
                            a.adc(r10w, r9w);
                        else
                            a.adc(r10d, r9d);

                        // Save host flags in r9 (safely recycling r9)
                        a.pushfq();
                        a.pop(r9);

                        if (operands[0].size == 8)
                            a.mov(byte_ptr(r14, r8), r10b);
                        else if (operands[0].size == 16)
                            a.mov(word_ptr(r14, r8), r10w);
                        else
                            a.mov(dword_ptr(r14, r8), r10d);

                        a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r9d);
                    }
                    else
                        return nullptr;
                }
                else
                    goto unimplemented;
            }
            break;
        case ZYDIS_MNEMONIC_AND:
        case ZYDIS_MNEMONIC_OR:
        case ZYDIS_MNEMONIC_ADD:
        case ZYDIS_MNEMONIC_SUB:
        case ZYDIS_MNEMONIC_XOR:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                // REGISTER and IMMEDIATE
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    uint32_t val = (uint32_t)operands[1].imm.value.s;
                    a.mov(r8d, dword_ptr(r15, off));
                    if (operands[0].size == 8)
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(r8b, (uint8_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(r8b, (uint8_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(r8b, (uint8_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(r8b, (uint8_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(r8b, (uint8_t)val);
                        a.mov(byte_ptr(r15, off), r8b);
                    }
                    else if (operands[0].size == 16)
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(r8w, (uint16_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(r8w, (uint16_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(r8w, (uint16_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(r8w, (uint16_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(r8w, (uint16_t)val);
                        a.mov(word_ptr(r15, off), r8w);
                    }
                    else
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(r8d, val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(r8d, val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(r8d, val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(r8d, val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(r8d, val);
                        a.mov(dword_ptr(r15, off), r8d);
                    }
                    // Synchronize host CPU flags back to guest Context
                    a.pushfq();
                    a.pop(r10);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
                }
                else
                {
                    return nullptr;
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                // REGISTER and REGISTER
                int off0 = getRegOffset(operands[0].reg.value);
                int off1 = getRegOffset(operands[1].reg.value);
                if (off0 != -1 && off1 != -1)
                {
                    a.mov(r8d, dword_ptr(r15, off0));
                    a.mov(r9d, dword_ptr(r15, off1));
                    if (operands[0].size == 8)
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(r8b, r9b);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(r8b, r9b);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(r8b, r9b);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(r8b, r9b);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(r8b, r9b);
                        a.mov(byte_ptr(r15, off0), r8b);
                    }
                    else if (operands[0].size == 16)
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(r8w, r9w);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(r8w, r9w);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(r8w, r9w);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(r8w, r9w);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(r8w, r9w);
                        a.mov(word_ptr(r15, off0), r8w);
                    }
                    else
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(r8d, r9d);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(r8d, r9d);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(r8d, r9d);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(r8d, r9d);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(r8d, r9d);
                        a.mov(dword_ptr(r15, off0), r8d);
                    }
                    // Synchronize host CPU flags back to guest Context
                    a.pushfq();
                    a.pop(r10);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
                }
                else
                {
                    return nullptr;
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                // REGISTER and MEMORY
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1 && resolveMemoryIntoR8(operands[1].mem))
                {
                    emitDosVramLatch(r8d, (int)(operands[0].size / 8));

                    a.mov(r10d, dword_ptr(r15, off));
                    if (operands[0].size == 8)
                    {
                        a.mov(r9b, byte_ptr(r14, r8));
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(r10b, r9b);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(r10b, r9b);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(r10b, r9b);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(r10b, r9b);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(r10b, r9b);
                        a.mov(byte_ptr(r15, off), r10b);
                    }
                    else if (operands[0].size == 16)
                    {
                        a.mov(r9w, word_ptr(r14, r8));
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(r10w, r9w);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(r10w, r9w);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(r10w, r9w);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(r10w, r9w);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(r10w, r9w);
                        a.mov(word_ptr(r15, off), r10w);
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r14, r8));
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(r10d, r9d);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(r10d, r9d);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(r10d, r9d);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(r10d, r9d);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(r10d, r9d);
                        a.mov(dword_ptr(r15, off), r10d);
                    }
                    // Synchronize host CPU flags back to guest Context
                    a.pushfq();
                    a.pop(r9);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r9d);
                }
                else
                {
                    return nullptr;
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                // MEMORY and REGISTER
                int off = getRegOffset(operands[1].reg.value);
                if (off != -1 && resolveMemoryIntoR8(operands[0].mem))
                {
                    // Read-modify-write: the read half latches too.
                    emitDosVramLatch(r8d, (int)(operands[1].size / 8));

                    if (operands[1].size == 8)
                    {
                        a.mov(r9b, byte_ptr(r15, off));
                        a.mov(r10b, byte_ptr(r14, r8));
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(r10b, r9b);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(r10b, r9b);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(r10b, r9b);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(r10b, r9b);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(r10b, r9b);
                        a.mov(byte_ptr(r14, r8), r10b);
                    }
                    else if (operands[1].size == 16)
                    {
                        a.mov(r9w, word_ptr(r15, off));
                        a.mov(r10w, word_ptr(r14, r8));
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(r10w, r9w);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(r10w, r9w);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(r10w, r9w);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(r10w, r9w);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(r10w, r9w);
                        a.mov(word_ptr(r14, r8), r10w);
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r15, off));
                        a.mov(r10d, dword_ptr(r14, r8));
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(r10d, r9d);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(r10d, r9d);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(r10d, r9d);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(r10d, r9d);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(r10d, r9d);
                        a.mov(dword_ptr(r14, r8), r10d);
                    }
                    // Synchronize host CPU flags back to guest Context
                    a.pushfq();
                    a.pop(r9);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r9d);

                    emitDosVramMirror(r8d, (int)(operands[1].size / 8));
                }
                else
                {
                    return nullptr;
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                // MEMORY and IMMEDIATE
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    // Read-modify-write: the read half latches too.
                    emitDosVramLatch(r8d, (int)(operands[0].size / 8));

                    uint32_t val = (uint32_t)operands[1].imm.value.s;
                    if (operands[0].size == 8)
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(byte_ptr(r14, r8), (uint8_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(byte_ptr(r14, r8), (uint8_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(byte_ptr(r14, r8), (uint8_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(byte_ptr(r14, r8), (uint8_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(byte_ptr(r14, r8), (uint8_t)val);
                    }
                    else if (operands[0].size == 16)
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(word_ptr(r14, r8), (uint16_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(word_ptr(r14, r8), (uint16_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(word_ptr(r14, r8), (uint16_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(word_ptr(r14, r8), (uint16_t)val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(word_ptr(r14, r8), (uint16_t)val);
                    }
                    else
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_AND)
                            a.and_(dword_ptr(r14, r8), val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_OR)
                            a.or_(dword_ptr(r14, r8), val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_ADD)
                            a.add(dword_ptr(r14, r8), val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_SUB)
                            a.sub(dword_ptr(r14, r8), val);
                        else if (instr.mnemonic == ZYDIS_MNEMONIC_XOR)
                            a.xor_(dword_ptr(r14, r8), val);
                    }
                    // Synchronize host CPU flags back to guest Context
                    a.pushfq();
                    a.pop(r10);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);

                    emitDosVramMirror(r8d, (int)(operands[0].size / 8));
                }
                else
                {
                    return nullptr;
                }
            }
            else
            {
                goto unimplemented;
            }
            break;

            // Save flags!
            a.pushfq();
            a.pop(r8);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
            break;
        case ZYDIS_MNEMONIC_TEST:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    a.mov(r8d, dword_ptr(r15, off));
                    uint32_t val = (uint32_t)operands[1].imm.value.s;
                    if (operands[0].size == 8)
                        a.test(r8b, (uint8_t)val);
                    else if (operands[0].size == 16)
                        a.test(r8w, (uint16_t)val);
                    else
                        a.test(r8d, val);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off0 = getRegOffset(operands[0].reg.value);
                int off1 = getRegOffset(operands[1].reg.value);
                if (off0 != -1 && off1 != -1)
                {
                    a.mov(r8d, dword_ptr(r15, off0));
                    a.mov(r9d, dword_ptr(r15, off1));
                    if (operands[0].size == 8)
                        a.test(r8b, r9b);
                    else if (operands[0].size == 16)
                        a.test(r8w, r9w);
                    else
                        a.test(r8d, r9d);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[1].reg.value);
                if (off != -1 && resolveMemoryIntoR8(operands[0].mem))
                {
                    a.mov(r10d, dword_ptr(r15, off));
                    if (operands[1].size == 8)
                        a.test(byte_ptr(r14, r8, 0), r10b);
                    else if (operands[1].size == 16)
                        a.test(word_ptr(r14, r8, 0), r10w);
                    else
                        a.test(dword_ptr(r14, r8, 0), r10d);
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    uint32_t val = (uint32_t)operands[1].imm.value.s;
                    if (operands[0].size == 8)
                        a.test(byte_ptr(r14, r8, 0), (uint8_t)val);
                    else if (operands[0].size == 16)
                        a.test(word_ptr(r14, r8, 0), (uint16_t)val);
                    else
                        a.test(dword_ptr(r14, r8, 0), val);
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;

            // Save flags!
            a.pushfq();
            a.pop(r8);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
            break;

        case ZYDIS_MNEMONIC_CMP:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    a.mov(r8d, dword_ptr(r15, off)); // load reg
                    uint32_t val = (uint32_t)operands[1].imm.value.s;
                    if (operands[0].size == 8)
                        a.cmp(r8b, (uint8_t)val);
                    else if (operands[0].size == 16)
                        a.cmp(r8w, (uint16_t)val);
                    else
                        a.cmp(r8d, val);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off0 = getRegOffset(operands[0].reg.value);
                int off1 = getRegOffset(operands[1].reg.value);
                if (off0 != -1 && off1 != -1)
                {
                    a.mov(r8d, dword_ptr(r15, off0));
                    a.mov(r9d, dword_ptr(r15, off1));
                    if (operands[0].size == 8)
                        a.cmp(r8b, r9b);
                    else if (operands[0].size == 16)
                        a.cmp(r8w, r9w);
                    else
                        a.cmp(r8d, r9d);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1 && resolveMemoryIntoR8(operands[1].mem))
                {
                    // r8 has MEM address
                    a.mov(r10d, dword_ptr(r15, off)); // r10 = REG
                    if (operands[0].size == 8)
                        a.cmp(r10b, byte_ptr(r14, r8, 0));
                    else if (operands[0].size == 16)
                        a.cmp(r10w, word_ptr(r14, r8, 0));
                    else
                        a.cmp(r10d, dword_ptr(r14, r8, 0));
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[1].reg.value);
                if (off != -1 && resolveMemoryIntoR8(operands[0].mem))
                {
                    // r8 has MEM address
                    a.mov(r10d, dword_ptr(r15, off)); // r10 = REG (src)

                    a.mov(r10d, dword_ptr(r15, off)); // r10 = REG (src)
                    if (operands[1].size == 8)
                        a.cmp(byte_ptr(r14, r8, 0), r10b);
                    else if (operands[1].size == 16)
                        a.cmp(word_ptr(r14, r8, 0), r10w);
                    else
                        a.cmp(dword_ptr(r14, r8, 0), r10d);
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    uint32_t val = (uint32_t)operands[1].imm.value.s;
                    if (operands[0].size == 8)
                        a.cmp(byte_ptr(r14, r8, 0), (uint8_t)val);
                    else if (operands[0].size == 16)
                        a.cmp(word_ptr(r14, r8, 0), (uint16_t)val);
                    else
                        a.cmp(dword_ptr(r14, r8, 0), val);
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;

            // Save flags!
            a.pushfq();
            a.pop(r8);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
            break;
        case ZYDIS_MNEMONIC_INC:
        case ZYDIS_MNEMONIC_DEC:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    a.mov(r8d, dword_ptr(r15, off));
                    if (operands[0].size == 8)
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_INC)
                            a.inc(r8b);
                        else
                            a.dec(r8b);
                        // Safe 8-bit write-back (prevents struct corruption)
                        a.mov(byte_ptr(r15, off), r8b);
                    }
                    else if (operands[0].size == 16)
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_INC)
                            a.inc(r8w);
                        else
                            a.dec(r8w);
                        // Safe 16-bit write-back (prevents struct corruption)
                        a.mov(word_ptr(r15, off), r8w);
                    }
                    else
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_INC)
                            a.inc(r8d);
                        else
                            a.dec(r8d);
                        a.mov(dword_ptr(r15, off), r8d);
                    }
                }
                else
                {
                    return nullptr;
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[0].size == 8)
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_INC)
                            a.inc(byte_ptr(r14, r8));
                        else
                            a.dec(byte_ptr(r14, r8));
                    }
                    else if (operands[0].size == 16)
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_INC)
                            a.inc(word_ptr(r14, r8));
                        else
                            a.dec(word_ptr(r14, r8));
                    }
                    else
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_INC)
                            a.inc(dword_ptr(r14, r8));
                        else
                            a.dec(dword_ptr(r14, r8));
                    }
                }
                else
                {
                    return nullptr;
                }
            }
            else
            {
                goto unimplemented;
            }

            // ============================================================
            // High-Performance Flag Synchronization
            // ============================================================
            // 1. Push pristine host flags (containing ZF/SF/OF/PF/AF) to stack
            a.pushfq();

            // 2. Direct read of the pushed flags from the stack top (saves a pop/push pair)
            a.mov(r8d, dword_ptr(rsp));

            // 3. Load guest's old eflags to retrieve the original Carry Flag (CF)
            a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, eflags)));

            // 4. Trident Bitwise Merge: Merge old guest CF (r9d bit 0) into r8d (bit 0)
            // This keeps host-modified flags (ZF, SF, OF, AF, PF) and restores guest CF
            a.xor_(r9d, r8d);
            a.and_(r9d, 1);
            a.xor_(r8d, r9d);

            // 5. Write the synchronized EFLAGS register back to guest context
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);

            // 6. Restore the pristine flags to the host CPU for subsequent Jcc instructions
            a.popfq();
            break;

        case ZYDIS_MNEMONIC_CLC:
            // CF = 0: clear bit 0 of EFLAGS
            a.and_(byte_ptr(r15, offsetof(CpuContext, eflags)), 0xFE);
            break;

        case ZYDIS_MNEMONIC_STC:
            // CF = 1: set bit 0 of EFLAGS
            a.or_(byte_ptr(r15, offsetof(CpuContext, eflags)), 1);
            break;

        case ZYDIS_MNEMONIC_CMC:
            // CF = !CF: toggle bit 0 of EFLAGS
            a.xor_(byte_ptr(r15, offsetof(CpuContext, eflags)), 1);
            break;

        case ZYDIS_MNEMONIC_NOT:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    a.mov(r8d, dword_ptr(r15, off));
                    if (operands[0].size == 8)
                        a.not_(r8b);
                    else if (operands[0].size == 16)
                        a.not_(r8w);
                    else
                        a.not_(r8d);
                    a.mov(dword_ptr(r15, off), r8d);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[0].size == 8)
                        a.not_(byte_ptr(r14, r8, 0));
                    else if (operands[0].size == 16)
                        a.not_(word_ptr(r14, r8, 0));
                    else
                        a.not_(dword_ptr(r14, r8, 0));
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_NEG:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    a.mov(r8d, dword_ptr(r15, off));
                    if (operands[0].size == 8)
                        a.neg(r8b);
                    else if (operands[0].size == 16)
                        a.neg(r8w);
                    else
                        a.neg(r8d);
                    a.mov(dword_ptr(r15, off), r8d);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[0].size == 8)
                        a.neg(byte_ptr(r14, r8, 0));
                    else if (operands[0].size == 16)
                        a.neg(word_ptr(r14, r8, 0));
                    else
                        a.neg(dword_ptr(r14, r8, 0));
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;

            // Save flags!
            a.pushfq();
            a.pop(r8);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
            break;

        case ZYDIS_MNEMONIC_SHL:
        case ZYDIS_MNEMONIC_SHR:
        case ZYDIS_MNEMONIC_SAR:
        case ZYDIS_MNEMONIC_ROL:
        case ZYDIS_MNEMONIC_ROR:
        case ZYDIS_MNEMONIC_RCL:
        case ZYDIS_MNEMONIC_RCR:
            if (instr.mnemonic == ZYDIS_MNEMONIC_RCL || instr.mnemonic == ZYDIS_MNEMONIC_RCR)
            {
                a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, eflags)));
                a.push(r9);
                a.popfq();
            }
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    a.mov(r8d, dword_ptr(r15, off));
                    if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                    {
                        uint8_t count = (uint8_t)operands[1].imm.value.u;
                        if (operands[0].size == 8)
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHL)
                                a.shl(r8b, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SHR)
                                a.shr(r8b, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SAR)
                                a.sar(r8b, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROL)
                                a.rol(r8b, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROR)
                                a.ror(r8b, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCL)
                                a.rcl(r8b, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCR)
                                a.rcr(r8b, count);
                        }
                        else if (operands[0].size == 16)
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHL)
                                a.shl(r8w, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SHR)
                                a.shr(r8w, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SAR)
                                a.sar(r8w, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROL)
                                a.rol(r8w, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROR)
                                a.ror(r8w, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCL)
                                a.rcl(r8w, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCR)
                                a.rcr(r8w, count);
                        }
                        else
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHL)
                                a.shl(r8d, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SHR)
                                a.shr(r8d, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SAR)
                                a.sar(r8d, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROL)
                                a.rol(r8d, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROR)
                                a.ror(r8d, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCL)
                                a.rcl(r8d, count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCR)
                                a.rcr(r8d, count);
                        }
                    }
                    else if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].reg.value == ZYDIS_REGISTER_CL)
                    {
                        a.mov(cl, byte_ptr(r15, offsetof(CpuContext, ecx)));
                        if (operands[0].size == 8)
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHL)
                                a.shl(r8b, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SHR)
                                a.shr(r8b, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SAR)
                                a.sar(r8b, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROL)
                                a.rol(r8b, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROR)
                                a.ror(r8b, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCL)
                                a.rcl(r8b, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCR)
                                a.rcr(r8b, cl);
                        }
                        else if (operands[0].size == 16)
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHL)
                                a.shl(r8w, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SHR)
                                a.shr(r8w, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SAR)
                                a.sar(r8w, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROL)
                                a.rol(r8w, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROR)
                                a.ror(r8w, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCL)
                                a.rcl(r8w, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCR)
                                a.rcr(r8w, cl);
                        }
                        else
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHL)
                                a.shl(r8d, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SHR)
                                a.shr(r8d, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SAR)
                                a.sar(r8d, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROL)
                                a.rol(r8d, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROR)
                                a.ror(r8d, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCL)
                                a.rcl(r8d, cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCR)
                                a.rcr(r8d, cl);
                        }
                    }
                    else
                        return nullptr;
                    a.mov(dword_ptr(r15, off), r8d);
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                    {
                        uint8_t count = (uint8_t)operands[1].imm.value.u;
                        if (operands[0].size == 8)
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHL)
                                a.shl(byte_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SHR)
                                a.shr(byte_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SAR)
                                a.sar(byte_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROL)
                                a.rol(byte_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROR)
                                a.ror(byte_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCL)
                                a.rcl(byte_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCR)
                                a.rcr(byte_ptr(r14, r8, 0), count);
                        }
                        else if (operands[0].size == 16)
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHL)
                                a.shl(word_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SHR)
                                a.shr(word_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SAR)
                                a.sar(word_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROL)
                                a.rol(word_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROR)
                                a.ror(word_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCL)
                                a.rcl(word_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCR)
                                a.rcr(word_ptr(r14, r8, 0), count);
                        }
                        else
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHL)
                                a.shl(dword_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SHR)
                                a.shr(dword_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SAR)
                                a.sar(dword_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROL)
                                a.rol(dword_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROR)
                                a.ror(dword_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCL)
                                a.rcl(dword_ptr(r14, r8, 0), count);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCR)
                                a.rcr(dword_ptr(r14, r8, 0), count);
                        }
                    }
                    else if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].reg.value == ZYDIS_REGISTER_CL)
                    {
                        a.mov(cl, byte_ptr(r15, offsetof(CpuContext, ecx)));
                        if (operands[0].size == 8)
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHL)
                                a.shl(byte_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SHR)
                                a.shr(byte_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SAR)
                                a.sar(byte_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROL)
                                a.rol(byte_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROR)
                                a.ror(byte_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCL)
                                a.rcl(byte_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCR)
                                a.rcr(byte_ptr(r14, r8, 0), cl);
                        }
                        else if (operands[0].size == 16)
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHL)
                                a.shl(word_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SHR)
                                a.shr(word_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SAR)
                                a.sar(word_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROL)
                                a.rol(word_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROR)
                                a.ror(word_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCL)
                                a.rcl(word_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCR)
                                a.rcr(word_ptr(r14, r8, 0), cl);
                        }
                        else
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHL)
                                a.shl(dword_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SHR)
                                a.shr(dword_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_SAR)
                                a.sar(dword_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROL)
                                a.rol(dword_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_ROR)
                                a.ror(dword_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCL)
                                a.rcl(dword_ptr(r14, r8, 0), cl);
                            else if (instr.mnemonic == ZYDIS_MNEMONIC_RCR)
                                a.rcr(dword_ptr(r14, r8, 0), cl);
                        }
                    }
                    else
                        return nullptr;
                }
                else
                    return nullptr;
            }
            else
                return nullptr;

            // Save flags!
            a.pushfq();
            a.pop(r8);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
            break;

        case ZYDIS_MNEMONIC_SHLD:
        case ZYDIS_MNEMONIC_SHRD:
        {
            int off1 = getRegOffset(operands[1].reg.value);
            if (off1 == -1)
                return nullptr;

            a.mov(r9d, dword_ptr(r15, off1));

            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off0 = getRegOffset(operands[0].reg.value);
                if (off0 == -1)
                    return nullptr;

                a.mov(r8d, dword_ptr(r15, off0));

                if (operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    uint8_t count = (uint8_t)operands[2].imm.value.u;
                    if (operands[0].size == 16)
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_SHLD)
                            a.shld(r8w, r9w, count);
                        else
                            a.shrd(r8w, r9w, count);
                    }
                    else
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_SHLD)
                            a.shld(r8d, r9d, count);
                        else
                            a.shrd(r8d, r9d, count);
                    }
                }
                else if (operands[2].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[2].reg.value == ZYDIS_REGISTER_CL)
                {
                    a.mov(cl, byte_ptr(r15, offsetof(CpuContext, ecx)));
                    if (operands[0].size == 16)
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_SHLD)
                            a.shld(r8w, r9w, cl);
                        else
                            a.shrd(r8w, r9w, cl);
                    }
                    else
                    {
                        if (instr.mnemonic == ZYDIS_MNEMONIC_SHLD)
                            a.shld(r8d, r9d, cl);
                        else
                            a.shrd(r8d, r9d, cl);
                    }
                }
                else
                    return nullptr;

                a.mov(dword_ptr(r15, off0), r8d);
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[0].size == 16)
                    {
                        a.mov(r10w, word_ptr(r14, r8, 0));
                    }
                    else
                    {
                        a.mov(r10d, dword_ptr(r14, r8, 0));
                    }

                    if (operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                    {
                        uint8_t count = (uint8_t)operands[2].imm.value.u;
                        if (operands[0].size == 16)
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHLD)
                                a.shld(r10w, r9w, count);
                            else
                                a.shrd(r10w, r9w, count);
                            a.mov(word_ptr(r14, r8, 0), r10w);
                        }
                        else
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHLD)
                                a.shld(r10d, r9d, count);
                            else
                                a.shrd(r10d, r9d, count);
                            a.mov(dword_ptr(r14, r8, 0), r10d);
                        }
                    }
                    else if (operands[2].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[2].reg.value == ZYDIS_REGISTER_CL)
                    {
                        a.mov(cl, byte_ptr(r15, offsetof(CpuContext, ecx)));
                        if (operands[0].size == 16)
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHLD)
                                a.shld(r10w, r9w, cl);
                            else
                                a.shrd(r10w, r9w, cl);
                            a.mov(word_ptr(r14, r8, 0), r10w);
                        }
                        else
                        {
                            if (instr.mnemonic == ZYDIS_MNEMONIC_SHLD)
                                a.shld(r10d, r9d, cl);
                            else
                                a.shrd(r10d, r9d, cl);
                            a.mov(dword_ptr(r14, r8, 0), r10d);
                        }
                    }
                    else
                        return nullptr;
                }
                else
                    return nullptr;
            }
            else
                return nullptr;

            a.pushfq();
            a.pop(r11);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r11d);
        }
        break;

        case ZYDIS_MNEMONIC_XCHG:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off0 = getRegOffset(operands[0].reg.value);
                int off1 = getRegOffset(operands[1].reg.value);
                if (off0 != -1 && off1 != -1)
                {
                    if (operands[0].size == 8)
                    {
                        a.mov(r8b, byte_ptr(r15, off0));
                        a.mov(r9b, byte_ptr(r15, off1));
                        a.mov(byte_ptr(r15, off0), r9b);
                        a.mov(byte_ptr(r15, off1), r8b);
                    }
                    else if (operands[0].size == 16)
                    {
                        a.mov(r8w, word_ptr(r15, off0));
                        a.mov(r9w, word_ptr(r15, off1));
                        a.mov(word_ptr(r15, off0), r9w);
                        a.mov(word_ptr(r15, off1), r8w);
                    }
                    else
                    {
                        a.mov(r8d, dword_ptr(r15, off0));
                        a.mov(r9d, dword_ptr(r15, off1));
                        a.mov(dword_ptr(r15, off0), r9d);
                        a.mov(dword_ptr(r15, off1), r8d);
                    }
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1 && resolveMemoryIntoR8(operands[1].mem))
                {
                    if (operands[0].size == 8)
                    {
                        a.mov(r9b, byte_ptr(r15, off));
                        a.xchg(byte_ptr(r14, r8, 0), r9b);
                        a.mov(byte_ptr(r15, off), r9b);
                    }
                    else if (operands[0].size == 16)
                    {
                        a.mov(r9w, word_ptr(r15, off));
                        a.xchg(word_ptr(r14, r8, 0), r9w);
                        a.mov(word_ptr(r15, off), r9w);
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r15, off));
                        a.xchg(dword_ptr(r14, r8, 0), r9d);
                        a.mov(dword_ptr(r15, off), r9d);
                    }
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[1].reg.value);
                if (off != -1 && resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[1].size == 8)
                    {
                        a.mov(r9b, byte_ptr(r15, off));
                        a.xchg(byte_ptr(r14, r8, 0), r9b);
                        a.mov(byte_ptr(r15, off), r9b);
                    }
                    else if (operands[1].size == 16)
                    {
                        a.mov(r9w, word_ptr(r15, off));
                        a.xchg(word_ptr(r14, r8, 0), r9w);
                        a.mov(word_ptr(r15, off), r9w);
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r15, off));
                        a.xchg(dword_ptr(r14, r8, 0), r9d);
                        a.mov(dword_ptr(r15, off), r9d);
                    }
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_XLAT:
            // XLAT/XLATB: AL = [DS:EBX + AL]
            if (resolveMemoryIntoR8(operands[0].mem))
            {
                a.movzx(eax, byte_ptr(r15, offsetof(CpuContext, eax)));  // eax = zero-extended AL (index)
                a.add(r8d, eax);                                          // r8 = dsBase + ebx + AL
                a.mov(al, byte_ptr(r14, r8, 0));                          // read byte
                a.mov(byte_ptr(r15, offsetof(CpuContext, eax)), al);      // store to guest AL
            }
            else
                return nullptr;
            break;

        case ZYDIS_MNEMONIC_CMPXCHG:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    int offSrc = getRegOffset(operands[1].reg.value);
                    if (offSrc != -1)
                    {
                        a.mov(eax, dword_ptr(r15, offsetof(CpuContext, eax)));
                        a.mov(r9d, dword_ptr(r15, offSrc));
                        if (instr.attributes & ZYDIS_ATTRIB_HAS_LOCK)
                            a.lock();
                        a.cmpxchg(dword_ptr(r14, r8, 0), r9d);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);
                    }
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_CBW:
            a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
            a.cbw();
            a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
            break;

        case ZYDIS_MNEMONIC_CWD:
            a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
            a.cwd();
            a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
            a.mov(word_ptr(r15, offsetof(CpuContext, edx)), dx);
            break;

        case ZYDIS_MNEMONIC_CDQ:
            // Sign-extend EAX into EDX:EAX
            a.mov(eax, dword_ptr(r15, offsetof(CpuContext, eax)));
            a.cdq();
            a.mov(dword_ptr(r15, offsetof(CpuContext, edx)), edx);
            break;

        case ZYDIS_MNEMONIC_CWDE:
            // Sign-extend AX into EAX
            a.movsx(eax, word_ptr(r15, offsetof(CpuContext, eax)));
            a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);
            break;

        case ZYDIS_MNEMONIC_IDIV:
            // Signed divide: 8-bit: AX / op → AL=quot, AH=rem
            //                16-bit: DX:AX / op → AX=quot, DX=rem
            //                32-bit: EDX:EAX / op → EAX=quot, EDX=rem
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[0].size == 8)
                    {
                        a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
                        a.idiv(byte_ptr(r14, r8, 0));
                        a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                    }
                    else if (operands[0].size == 16)
                    {
                        a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
                        a.mov(dx, word_ptr(r15, offsetof(CpuContext, edx)));
                        a.idiv(word_ptr(r14, r8, 0));
                        a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                        a.mov(word_ptr(r15, offsetof(CpuContext, edx)), dx);
                    }
                    else
                    {
                        a.mov(eax, dword_ptr(r15, offsetof(CpuContext, eax)));
                        a.mov(edx, dword_ptr(r15, offsetof(CpuContext, edx)));
                        a.idiv(dword_ptr(r14, r8, 0));
                        a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, edx)), edx);
                    }
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    if (operands[0].size == 8)
                    {
                        a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
                        a.idiv(byte_ptr(r15, off));
                        a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                    }
                    else if (operands[0].size == 16)
                    {
                        a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
                        a.mov(dx, word_ptr(r15, offsetof(CpuContext, edx)));
                        a.idiv(word_ptr(r15, off));
                        a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                        a.mov(word_ptr(r15, offsetof(CpuContext, edx)), dx);
                    }
                    else
                    {
                        a.mov(eax, dword_ptr(r15, offsetof(CpuContext, eax)));
                        a.mov(edx, dword_ptr(r15, offsetof(CpuContext, edx)));
                        a.idiv(dword_ptr(r15, off));
                        a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, edx)), edx);
                    }
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_MUL:
            // Unsigned multiply AX/DX:AX/EDX:EAX by operand
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[0].size == 8)
                    {
                        a.mov(al, byte_ptr(r15, offsetof(CpuContext, eax)));
                        a.mul(byte_ptr(r14, r8, 0));
                        a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                    }
                    else if (operands[0].size == 16)
                    {
                        a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
                        a.mov(dx, word_ptr(r15, offsetof(CpuContext, edx)));
                        a.mul(word_ptr(r14, r8, 0));
                        a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                        a.mov(word_ptr(r15, offsetof(CpuContext, edx)), dx);
                    }
                    else
                    {
                        a.mov(eax, dword_ptr(r15, offsetof(CpuContext, eax)));
                        a.mov(edx, dword_ptr(r15, offsetof(CpuContext, edx)));
                        a.mul(dword_ptr(r14, r8, 0));
                        a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, edx)), edx);
                    }
                    // Save flags
                    a.pushfq();
                    a.pop(r10);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    if (operands[0].size == 8)
                    {
                        a.mov(al, byte_ptr(r15, offsetof(CpuContext, eax)));
                        a.mul(byte_ptr(r15, off));
                        a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                    }
                    else if (operands[0].size == 16)
                    {
                        a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
                        a.mov(dx, word_ptr(r15, offsetof(CpuContext, edx)));
                        a.mul(word_ptr(r15, off));
                        a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                        a.mov(word_ptr(r15, offsetof(CpuContext, edx)), dx);
                    }
                    else
                    {
                        a.mov(eax, dword_ptr(r15, offsetof(CpuContext, eax)));
                        a.mov(edx, dword_ptr(r15, offsetof(CpuContext, edx)));
                        a.mul(dword_ptr(r15, off));
                        a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, edx)), edx);
                    }
                    // Save flags
                    a.pushfq();
                    a.pop(r10);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_DIV:
            // Unsigned divide AX/DX:AX/EDX:EAX by operand
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (operands[0].size == 8)
                    {
                        a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
                        a.div(byte_ptr(r14, r8, 0));
                        a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                    }
                    else if (operands[0].size == 16)
                    {
                        a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
                        a.mov(dx, word_ptr(r15, offsetof(CpuContext, edx)));
                        a.div(word_ptr(r14, r8, 0));
                        a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                        a.mov(word_ptr(r15, offsetof(CpuContext, edx)), dx);
                    }
                    else
                    {
                        a.mov(eax, dword_ptr(r15, offsetof(CpuContext, eax)));
                        a.mov(edx, dword_ptr(r15, offsetof(CpuContext, edx)));
                        a.div(dword_ptr(r14, r8, 0));
                        a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, edx)), edx);
                    }
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    if (operands[0].size == 8)
                    {
                        a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
                        a.div(byte_ptr(r15, off));
                        a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                    }
                    else if (operands[0].size == 16)
                    {
                        a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
                        a.mov(dx, word_ptr(r15, offsetof(CpuContext, edx)));
                        a.div(word_ptr(r15, off));
                        a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                        a.mov(word_ptr(r15, offsetof(CpuContext, edx)), dx);
                    }
                    else
                    {
                        a.mov(eax, dword_ptr(r15, offsetof(CpuContext, eax)));
                        a.mov(edx, dword_ptr(r15, offsetof(CpuContext, edx)));
                        a.div(dword_ptr(r15, off));
                        a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, edx)), edx);
                    }
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_IMUL:
            if (instr.operand_count_visible == 1)
            {
                // One-operand IMUL has implicit AX/DX:AX/EDX:EAX operands in
                // Zydis. Find the sole explicit source instead of treating
                // those implicit registers as the two-operand form.
                const ZydisDecodedOperand *source = nullptr;
                for (uint8_t i = 0; i < instr.operand_count; ++i)
                {
                    if (operands[i].visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT)
                    {
                        source = &operands[i];
                        break;
                    }
                }
                if (!source)
                    return nullptr;

                if (source->type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    int off = getRegOffset(source->reg.value);
                    if (off == -1)
                        return nullptr;
                    if (source->size == 8)
                        a.mov(r9b, byte_ptr(r15, off));
                    else if (source->size == 16)
                        a.mov(r9w, word_ptr(r15, off));
                    else
                        a.mov(r9d, dword_ptr(r15, off));
                }
                else if (source->type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    if (!resolveMemoryIntoR8(source->mem))
                        return nullptr;
                    if (source->size == 8)
                        a.mov(r9b, byte_ptr(r14, r8));
                    else if (source->size == 16)
                        a.mov(r9w, word_ptr(r14, r8));
                    else
                        a.mov(r9d, dword_ptr(r14, r8));
                }
                else
                {
                    return nullptr;
                }

                if (source->size == 8)
                {
                    a.mov(al, byte_ptr(r15, offsetof(CpuContext, eax)));
                    a.imul(r9b);
                    a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                }
                else if (source->size == 16)
                {
                    a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
                    a.imul(r9w);
                    a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                    a.mov(word_ptr(r15, offsetof(CpuContext, edx)), dx);
                }
                else
                {
                    a.mov(eax, dword_ptr(r15, offsetof(CpuContext, eax)));
                    a.imul(r9d);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, edx)), edx);
                }

                a.pushfq();
                a.pop(r10);
                a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                     operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                     instr.operand_count_visible >= 3 &&
                     operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                // 3-operand: IMUL reg, reg, imm
                int off0 = getRegOffset(operands[0].reg.value);
                int off1 = getRegOffset(operands[1].reg.value);
                if (off0 != -1 && off1 != -1)
                {
                    if (operands[0].size == 16)
                    {
                        a.mov(r8w, word_ptr(r15, off1));
                        a.imul(r8w, (int16_t)operands[2].imm.value.s);
                        a.mov(word_ptr(r15, off0), r8w);
                    }
                    else
                    {
                        a.mov(r8d, dword_ptr(r15, off1));
                        a.imul(r8d, (int32_t)operands[2].imm.value.s);
                        a.mov(dword_ptr(r15, off0), r8d);
                    }
                    a.pushfq();
                    a.pop(r10);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
                }
                else
                {
                    return nullptr;
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                     operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                     instr.operand_count_visible >= 3 &&
                     operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                // 3-operand: IMUL reg, mem, imm
                int off0 = getRegOffset(operands[0].reg.value);
                if (off0 != -1 && resolveMemoryIntoR8(operands[1].mem))
                {
                    if (operands[0].size == 16)
                    {
                        a.mov(r9w, word_ptr(r14, r8));
                        a.imul(r9w, (int16_t)operands[2].imm.value.s);
                        a.mov(word_ptr(r15, off0), r9w);
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r14, r8));
                        a.imul(r9d, (int32_t)operands[2].imm.value.s);
                        a.mov(dword_ptr(r15, off0), r9d);
                    }
                    a.pushfq();
                    a.pop(r10);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
                }
                else
                {
                    return nullptr;
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                // 2-operand: IMUL reg, reg
                int off0 = getRegOffset(operands[0].reg.value);
                int off1 = getRegOffset(operands[1].reg.value);
                if (off0 != -1 && off1 != -1)
                {
                    if (operands[0].size == 16)
                    {
                        a.mov(r8w, word_ptr(r15, off0));
                        a.mov(r9w, word_ptr(r15, off1));
                        a.imul(r8w, r9w);
                        a.mov(word_ptr(r15, off0), r8w);
                    }
                    else
                    {
                        a.mov(r8d, dword_ptr(r15, off0));
                        a.mov(r9d, dword_ptr(r15, off1));
                        a.imul(r8d, r9d);
                        a.mov(dword_ptr(r15, off0), r8d);
                    }
                    a.pushfq();
                    a.pop(r10);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
                }
                else
                {
                    return nullptr;
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                // 2-operand: IMUL reg, mem
                int off0 = getRegOffset(operands[0].reg.value);
                if (off0 != -1 && resolveMemoryIntoR8(operands[1].mem))
                {
                    if (operands[0].size == 16)
                    {
                        a.mov(r9w, word_ptr(r15, off0));
                        a.imul(r9w, word_ptr(r14, r8));
                        a.mov(word_ptr(r15, off0), r9w);
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r15, off0));
                        a.imul(r9d, dword_ptr(r14, r8));
                        a.mov(dword_ptr(r15, off0), r9d);
                    }
                    a.pushfq();
                    a.pop(r10);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
                }
                else
                {
                    return nullptr;
                }
            }
            else
            {
                goto unimplemented;
            }
            break;

        case ZYDIS_MNEMONIC_MOVSB:
        case ZYDIS_MNEMONIC_MOVSW:
        case ZYDIS_MNEMONIC_MOVSD:
        {
            const bool segmentedMode = isNE || isMZ;
            const bool use16BitIndex = instr.address_width == 16;
            bool repeat = (instr.attributes & ZYDIS_ATTRIB_HAS_REP) ||
                          (instr.attributes & ZYDIS_ATTRIB_HAS_REPE) ||
                          (instr.attributes & ZYDIS_ATTRIB_HAS_REPNE);
            int stride = (instr.mnemonic == ZYDIS_MNEMONIC_MOVSB) ? 1 : (instr.mnemonic == ZYDIS_MNEMONIC_MOVSW) ? 2
                                                                                                                 : 4;

            Label loopEnd = a.newLabel();
            Label loopEndNoOp = a.newLabel();

            if (repeat)
            {
                // Load counter ECX and verify it is not 0
                a.mov(ecx, dword_ptr(r15, offsetof(CpuContext, ecx)));
                if (use16BitIndex)
                {
                    a.movzx(ecx, cx);
                }
                a.test(ecx, ecx);
                a.jz(loopEndNoOp);

                a.pushfq(); // Save original flags

                // Load active indices (ESI and EDI)
                a.mov(esi, dword_ptr(r15, offsetof(CpuContext, esi)));
                a.mov(edi, dword_ptr(r15, offsetof(CpuContext, edi)));

                // Load guest EFLAGS (DF is bit 10 / 0x400)
                a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, eflags)));

                Label dfSet = a.newLabel();
                a.test(r9d, 0x400);
                a.jnz(dfSet);

                // ============================================================
                // DF == 0: INCREMENT LOOP
                // ============================================================
                Label loopStartInc = a.newLabel();
                if (segmentedMode)
                {
                    a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, dsBase)));
                    a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, esBase)));
                }

                a.bind(loopStartInc);
                {
                    if (use16BitIndex)
                    {
                        // Zero-extend SI/DI every iteration to handle 16-bit wrapping.
                        a.movzx(r10d, si);
                        a.movzx(r11d, di);
                        if (segmentedMode)
                        {
                            a.add(r10d, r8d); // r8d = dsBase
                            a.add(r11d, r9d); // r9d = esBase
                        }
                    }
                    else
                    {
                        a.mov(r10d, esi);
                        a.mov(r11d, edi);
                    }

                    // Copy data (r14 = Host Memory Base)
                    emitDosVramLatch(r10d, stride);
                    if (stride == 1)
                    {
                        a.mov(r12b, byte_ptr(r14, r10));
                        a.mov(byte_ptr(r14, r11), r12b);
                    }
                    else if (stride == 2)
                    {
                        a.mov(r12w, word_ptr(r14, r10));
                        a.mov(word_ptr(r14, r11), r12w);
                    }
                    else
                    {
                        a.mov(r12d, dword_ptr(r14, r10));
                        a.mov(dword_ptr(r14, r11), r12d);
                    }

                    emitDosVramMirror(r11d, stride);

                    if (use16BitIndex)
                    {
                        a.add(si, stride);
                        a.add(di, stride);
                    }
                    else
                    {
                        a.add(esi, stride);
                        a.add(edi, stride);
                    }

                    a.dec(ecx);
                    a.jnz(loopStartInc);
                }
                a.jmp(loopEnd);

                // ============================================================
                // DF == 1: DECREMENT LOOP
                // ============================================================
                a.bind(dfSet);
                Label loopStartDec = a.newLabel();
                if (segmentedMode)
                {
                    a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, dsBase)));
                    a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, esBase)));
                }

                a.bind(loopStartDec);
                {
                    if (use16BitIndex)
                    {
                        a.movzx(r10d, si);
                        a.movzx(r11d, di);
                        if (segmentedMode)
                        {
                            a.add(r10d, r8d);
                            a.add(r11d, r9d);
                        }
                    }
                    else
                    {
                        a.mov(r10d, esi);
                        a.mov(r11d, edi);
                    }

                    emitDosVramLatch(r10d, stride);
                    if (stride == 1)
                    {
                        a.mov(r12b, byte_ptr(r14, r10));
                        a.mov(byte_ptr(r14, r11), r12b);
                    }
                    else if (stride == 2)
                    {
                        a.mov(r12w, word_ptr(r14, r10));
                        a.mov(word_ptr(r14, r11), r12w);
                    }
                    else
                    {
                        a.mov(r12d, dword_ptr(r14, r10));
                        a.mov(dword_ptr(r14, r11), r12d);
                    }

                    emitDosVramMirror(r11d, stride);

                    if (use16BitIndex)
                    {
                        a.sub(si, stride);
                        a.sub(di, stride);
                    }
                    else
                    {
                        a.sub(esi, stride);
                        a.sub(edi, stride);
                    }

                    a.dec(ecx);
                    a.jnz(loopStartDec);
                }

                a.bind(loopEnd);

                if (use16BitIndex)
                {
                    a.mov(word_ptr(r15, offsetof(CpuContext, ecx)), cx);
                    a.mov(word_ptr(r15, offsetof(CpuContext, esi)), si);
                    a.mov(word_ptr(r15, offsetof(CpuContext, edi)), di);
                }
                else
                {
                    a.mov(dword_ptr(r15, offsetof(CpuContext, ecx)), ecx);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, esi)), esi);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, edi)), edi);
                }
                a.popfq(); // Restore original flags

                a.bind(loopEndNoOp);
            }
            else
            {
                // ============================================================
                // NON-REPEATING CASE
                // ============================================================
                a.pushfq(); // Save original flags

                a.mov(esi, dword_ptr(r15, offsetof(CpuContext, esi)));
                a.mov(edi, dword_ptr(r15, offsetof(CpuContext, edi)));
                a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, eflags)));

                if (use16BitIndex)
                {
                    a.movzx(r10d, si);
                    a.movzx(r11d, di);
                    if (segmentedMode)
                    {
                        a.add(r10d, dword_ptr(r15, offsetof(CpuContext, dsBase)));
                        a.add(r11d, dword_ptr(r15, offsetof(CpuContext, esBase)));
                    }
                }
                else
                {
                    a.mov(r10d, esi);
                    a.mov(r11d, edi);
                }

                if (stride == 1)
                {
                    a.mov(r8b, byte_ptr(r14, r10));
                    a.mov(byte_ptr(r14, r11), r8b);
                }
                else if (stride == 2)
                {
                    a.mov(r8w, word_ptr(r14, r10));
                    a.mov(word_ptr(r14, r11), r8w);
                }
                else
                {
                    a.mov(r8d, dword_ptr(r14, r10));
                    a.mov(dword_ptr(r14, r11), r8d);
                }

                emitDosVramMirror(r11d, stride);

                Label dfSetNonRep = a.newLabel();
                Label doneNonRep = a.newLabel();
                a.test(r9d, 0x400);
                a.jnz(dfSetNonRep);

                if (use16BitIndex)
                {
                    a.add(si, stride);
                    a.add(di, stride);
                }
                else
                {
                    a.add(esi, stride);
                    a.add(edi, stride);
                }
                a.jmp(doneNonRep);

                a.bind(dfSetNonRep);
                if (use16BitIndex)
                {
                    a.sub(si, stride);
                    a.sub(di, stride);
                }
                else
                {
                    a.sub(esi, stride);
                    a.sub(edi, stride);
                }

                a.bind(doneNonRep);

                if (use16BitIndex)
                {
                    a.mov(word_ptr(r15, offsetof(CpuContext, esi)), si);
                    a.mov(word_ptr(r15, offsetof(CpuContext, edi)), di);
                }
                else
                {
                    a.mov(dword_ptr(r15, offsetof(CpuContext, esi)), esi);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, edi)), edi);
                }
                a.popfq(); // Restore original flags
            }
        }
        break;

        case ZYDIS_MNEMONIC_CMPSB:
        case ZYDIS_MNEMONIC_CMPSW:
        case ZYDIS_MNEMONIC_CMPSD:
        {
            const bool segmentedMode = isNE || isMZ;
            const bool use16BitIndex = instr.address_width == 16;
            bool repe = (instr.attributes & ZYDIS_ATTRIB_HAS_REPE) || (instr.attributes & ZYDIS_ATTRIB_HAS_REP);
            bool repne = (instr.attributes & ZYDIS_ATTRIB_HAS_REPNE);
            bool repeat = repe || repne;
            int stride = (instr.mnemonic == ZYDIS_MNEMONIC_CMPSB) ? 1 : (instr.mnemonic == ZYDIS_MNEMONIC_CMPSW) ? 2
                                                                                                                 : 4;

            Label loopEnd = a.newLabel();
            Label loopEndNoOp = a.newLabel();

            // Load ESI, EDI from context
            a.mov(esi, dword_ptr(r15, offsetof(CpuContext, esi)));
            a.mov(edi, dword_ptr(r15, offsetof(CpuContext, edi)));
            if (use16BitIndex)
            {
                a.movzx(esi, si);
                a.movzx(edi, di);
            }

            // Load ECX if repeat
            if (repeat)
            {
                a.mov(ecx, dword_ptr(r15, offsetof(CpuContext, ecx)));
                if (use16BitIndex)
                {
                    a.movzx(ecx, cx);
                }
                a.test(ecx, ecx);
                a.jz(loopEndNoOp);
            }

            // Load DF from EFLAGS
            a.mov(edx, dword_ptr(r15, offsetof(CpuContext, eflags)));
            a.test(edx, 0x400); // DF bit

            Label dfSet = a.newLabel();
            a.jnz(dfSet);

            // ============================================================
            // DF == 0 (Increment)
            // ============================================================
            Label loopStartInc = a.newLabel();
            a.bind(loopStartInc);
            {
                // Load value from DS:ESI
                a.mov(r8d, esi);
                if (segmentedMode)
                {
                    a.add(r8d, dword_ptr(r15, offsetof(CpuContext, dsBase)));
                }
                // Load value from ES:EDI
                a.mov(r9d, edi);
                if (segmentedMode)
                {
                    a.add(r9d, dword_ptr(r15, offsetof(CpuContext, esBase)));
                }

                // Do comparison
                if (stride == 1)
                {
                    a.mov(r10b, byte_ptr(r14, r8d));
                    a.cmp(r10b, byte_ptr(r14, r9d));
                }
                else if (stride == 2)
                {
                    a.mov(r10w, word_ptr(r14, r8d));
                    a.cmp(r10w, word_ptr(r14, r9d));
                }
                else
                {
                    a.mov(r10d, dword_ptr(r14, r8d));
                    a.cmp(r10d, dword_ptr(r14, r9d));
                }

                // Save comparison flags in r10
                a.pushfq();
                a.pop(r10);

                // Increment index
                a.add(esi, stride);
                a.add(edi, stride);

                if (repeat)
                {
                    a.dec(ecx);
                    a.jz(loopEnd); // Terminate if ECX == 0

                    // Test ZF from the saved comparison flags in r10
                    a.test(r10, 0x40);
                    if (repe)
                    {
                        a.jnz(loopStartInc); // REPE: repeat if ZF == 1 (equal)
                    }
                    else
                    {
                        a.jz(loopStartInc); // REPNE: repeat if ZF == 0 (not equal)
                    }
                }
            }
            a.jmp(loopEnd);

            // ============================================================
            // DF == 1 (Decrement)
            // ============================================================
            a.bind(dfSet);
            Label loopStartDec = a.newLabel();
            a.bind(loopStartDec);
            {
                // Load value from DS:ESI
                a.mov(r8d, esi);
                if (segmentedMode)
                {
                    a.add(r8d, dword_ptr(r15, offsetof(CpuContext, dsBase)));
                }
                // Load value from ES:EDI
                a.mov(r9d, edi);
                if (segmentedMode)
                {
                    a.add(r9d, dword_ptr(r15, offsetof(CpuContext, esBase)));
                }

                // Do comparison
                if (stride == 1)
                {
                    a.mov(r10b, byte_ptr(r14, r8d));
                    a.cmp(r10b, byte_ptr(r14, r9d));
                }
                else if (stride == 2)
                {
                    a.mov(r10w, word_ptr(r14, r8d));
                    a.cmp(r10w, word_ptr(r14, r9d));
                }
                else
                {
                    a.mov(r10d, dword_ptr(r14, r8d));
                    a.cmp(r10d, dword_ptr(r14, r9d));
                }

                // Save comparison flags in r10
                a.pushfq();
                a.pop(r10);

                // Decrement index
                a.sub(esi, stride);
                a.sub(edi, stride);

                if (repeat)
                {
                    a.dec(ecx);
                    a.jz(loopEnd); // Terminate if ECX == 0

                    // Test ZF from the saved comparison flags in r10
                    a.test(r10, 0x40);
                    if (repe)
                    {
                        a.jnz(loopStartDec); // REPE: repeat if ZF == 1 (equal)
                    }
                    else
                    {
                        a.jz(loopStartDec); // REPNE: repeat if ZF == 0 (not equal)
                    }
                }
            }

            a.bind(loopEnd);

            // Save comparison flags to Context and restore to host
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
            a.push(r10);
            a.popfq();

            // Write back updated registers
            if (use16BitIndex)
            {
                a.mov(word_ptr(r15, offsetof(CpuContext, esi)), si);
                a.mov(word_ptr(r15, offsetof(CpuContext, edi)), di);
                if (repeat)
                {
                    a.mov(word_ptr(r15, offsetof(CpuContext, ecx)), cx);
                }
            }
            else
            {
                a.mov(dword_ptr(r15, offsetof(CpuContext, esi)), esi);
                a.mov(dword_ptr(r15, offsetof(CpuContext, edi)), edi);
                if (repeat)
                {
                    a.mov(dword_ptr(r15, offsetof(CpuContext, ecx)), ecx);
                }
            }

            a.bind(loopEndNoOp);
        }
        break;

        case ZYDIS_MNEMONIC_STOSB:
        case ZYDIS_MNEMONIC_STOSW:
        case ZYDIS_MNEMONIC_STOSD:
        {
            const bool use16BitIndex = instr.address_width == 16;
            const bool segmentedMode = isNE || isMZ;
            bool repeat = (instr.attributes & ZYDIS_ATTRIB_HAS_REP) ||
                          (instr.attributes & ZYDIS_ATTRIB_HAS_REPE) ||
                          (instr.attributes & ZYDIS_ATTRIB_HAS_REPNE);

            int stride = (instr.mnemonic == ZYDIS_MNEMONIC_STOSB) ? 1 : (instr.mnemonic == ZYDIS_MNEMONIC_STOSW) ? 2
                                                                                                                 : 4;

            Label loopEnd = a.newLabel();
            Label loopEndNoOp = a.newLabel();
            Label loopStart = a.newLabel();

            // 1. Load Counter
            if (repeat)
            {
                a.mov(ecx, dword_ptr(r15, offsetof(CpuContext, ecx)));
                if (use16BitIndex)
                    a.movzx(ecx, cx);
                a.test(ecx, ecx);
                a.jz(loopEndNoOp);
            }

            a.pushfq(); // Save original flags

            // 2. Load Base, Index, and Value (Load once outside loop!)
            a.mov(edi, dword_ptr(r15, offsetof(CpuContext, edi)));
            a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, esBase)));

            // Load the correct source value from EAX
            if (stride == 1)
                a.mov(r8b, byte_ptr(r15, offsetof(CpuContext, eax)));
            else if (stride == 2)
                a.mov(r8w, word_ptr(r15, offsetof(CpuContext, eax)));
            else
                a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eax)));

            // Load DF
            a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, eflags)));
            a.test(r9d, 0x400);
            Label dfSet = a.newLabel();
            a.jnz(dfSet);

            // ================= DF == 0 (Increment) =================
            a.bind(loopStart);
            {
                if (use16BitIndex)
                {
                    a.movzx(r10d, di);
                    if (segmentedMode)
                        a.add(r10d, r11d); // Base + wrapped DI
                }
                else
                {
                    a.mov(r10d, edi);
                    if (segmentedMode)
                        a.add(r10d, r11d); // Base + EDI
                }

                // Store
                if (stride == 1)
                    a.mov(byte_ptr(r14, r10), r8b);
                else if (stride == 2)
                    a.mov(word_ptr(r14, r10), r8w);
                else
                    a.mov(dword_ptr(r14, r10), r8d);

                emitDosVramMirror(r10d, stride);

                if (use16BitIndex)
                    a.add(di, stride);
                else
                    a.add(edi, stride);

                if (repeat)
                {
                    a.dec(ecx);
                    a.jnz(loopStart);
                }
            }
            a.jmp(loopEnd);

            // ================= DF == 1 (Decrement) =================
            a.bind(dfSet);
            Label loopStartDec = a.newLabel();
            a.bind(loopStartDec);
            {
                if (use16BitIndex)
                {
                    a.movzx(r10d, di);
                    if (segmentedMode)
                        a.add(r10d, r11d);
                }
                else
                {
                    a.mov(r10d, edi);
                    if (segmentedMode)
                        a.add(r10d, r11d);
                }

                // Store
                if (stride == 1)
                    a.mov(byte_ptr(r14, r10), r8b);
                else if (stride == 2)
                    a.mov(word_ptr(r14, r10), r8w);
                else
                    a.mov(dword_ptr(r14, r10), r8d);

                emitDosVramMirror(r10d, stride);

                if (use16BitIndex)
                    a.sub(di, stride);
                else
                    a.sub(edi, stride);

                if (repeat)
                {
                    a.dec(ecx);
                    a.jnz(loopStartDec);
                }
            }

            a.bind(loopEnd);

            // 3. Final Writeback (Once!)
            if (use16BitIndex)
            {
                a.mov(word_ptr(r15, offsetof(CpuContext, edi)), di);
                if (repeat)
                    a.mov(word_ptr(r15, offsetof(CpuContext, ecx)), cx);
            }
            else
            {
                a.mov(dword_ptr(r15, offsetof(CpuContext, edi)), edi);
                if (repeat)
                    a.mov(dword_ptr(r15, offsetof(CpuContext, ecx)), ecx);
            }
            a.popfq(); // Restore original flags

            a.bind(loopEndNoOp);
        }
        break;

        case ZYDIS_MNEMONIC_LODSB:
        case ZYDIS_MNEMONIC_LODSW:
        case ZYDIS_MNEMONIC_LODSD:
        {
            const bool use16BitIndex = instr.address_width == 16;
            const bool segmentedMode = isNE || isMZ;
            bool repeat = (instr.attributes & ZYDIS_ATTRIB_HAS_REP) || (instr.attributes & ZYDIS_ATTRIB_HAS_REPE) || (instr.attributes & ZYDIS_ATTRIB_HAS_REPNE);
            Label loopStart = a.newLabel();
            Label loopEnd = a.newLabel();
            Label loopEndNoOp = a.newLabel();

            if (repeat)
            {
                a.mov(ecx, dword_ptr(r15, offsetof(CpuContext, ecx)));
                if (use16BitIndex)
                    a.movzx(ecx, cx);
                a.test(ecx, ecx);
                a.jz(loopEndNoOp);
            }

            a.pushfq(); // Save original flags

            if (repeat)
            {
                a.bind(loopStart);
            }

            a.mov(esi, dword_ptr(r15, offsetof(CpuContext, esi)));
            if (use16BitIndex)
            {
                a.movzx(esi, si);
                if (segmentedMode)
                    a.add(esi, dword_ptr(r15, offsetof(CpuContext, dsBase)));
            }

            emitDosVramLatch(esi, (instr.mnemonic == ZYDIS_MNEMONIC_LODSB) ? 1
                                 : (instr.mnemonic == ZYDIS_MNEMONIC_LODSW) ? 2 : 4);

            if (instr.mnemonic == ZYDIS_MNEMONIC_LODSB)
            {
                a.mov(al, byte_ptr(r14, esi));
                a.mov(byte_ptr(r15, offsetof(CpuContext, eax)), al);
                a.mov(r8w, 1);
            }
            else if (instr.mnemonic == ZYDIS_MNEMONIC_LODSW)
            {
                a.mov(ax, word_ptr(r14, esi));
                a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);
                a.mov(r8w, 2);
            }
            else
            {
                a.mov(eax, dword_ptr(r14, esi));
                a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);
                a.mov(r8d, 4);
            }

            // Update ESI based on DF
            {
                Label dfSet = a.newLabel();
                Label done = a.newLabel();
                a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, eflags)));
                a.test(r9d, 0x400); // Check DF
                a.jnz(dfSet);

                // DF=0: Increment
                if (use16BitIndex)
                    a.add(word_ptr(r15, offsetof(CpuContext, esi)), r8w);
                else
                    a.add(dword_ptr(r15, offsetof(CpuContext, esi)), r8d);
                a.jmp(done);

                a.bind(dfSet);
                // DF=1: Decrement
                if (use16BitIndex)
                    a.sub(word_ptr(r15, offsetof(CpuContext, esi)), r8w);
                else
                    a.sub(dword_ptr(r15, offsetof(CpuContext, esi)), r8d);
                a.bind(done);
            }

            if (repeat)
            {
                a.dec(ecx);
                a.jnz(loopStart);
            }

            a.bind(loopEnd);
            if (repeat)
            {
                if (use16BitIndex)
                    a.mov(word_ptr(r15, offsetof(CpuContext, ecx)), cx);
                else
                    a.mov(dword_ptr(r15, offsetof(CpuContext, ecx)), ecx);
            }
            a.popfq(); // Restore original flags

            a.bind(loopEndNoOp);
        }
        break;

        case ZYDIS_MNEMONIC_SCASB:
        case ZYDIS_MNEMONIC_SCASW:
        case ZYDIS_MNEMONIC_SCASD:
        {
            const bool segmentedMode = isNE || isMZ;
            const bool use16BitIndex = instr.address_width == 16;
            bool repeat = (instr.attributes & ZYDIS_ATTRIB_HAS_REP) ||
                          (instr.attributes & ZYDIS_ATTRIB_HAS_REPE) ||
                          (instr.attributes & ZYDIS_ATTRIB_HAS_REPNE);
            bool isRepne = (instr.attributes & ZYDIS_ATTRIB_HAS_REPNE) != 0;
            int stride = (instr.mnemonic == ZYDIS_MNEMONIC_SCASB) ? 1 : (instr.mnemonic == ZYDIS_MNEMONIC_SCASW) ? 2
                                                                                                                 : 4;

            Label loopEnd = a.newLabel();
            Label loopEndNoOp = a.newLabel();

            if (repeat)
            {
                // Load ECX and check for 0
                a.mov(ecx, dword_ptr(r15, offsetof(CpuContext, ecx)));
                if (use16BitIndex)
                {
                    a.movzx(ecx, cx);
                }
                a.test(ecx, ecx);
                a.jz(loopEndNoOp); // ECX is 0 -> No-op (no writes to ECX/EDI/eflags)

                // Cache accumulator value once (remains unchanged across loop)
                if (stride == 1)
                {
                    a.mov(al, byte_ptr(r15, offsetof(CpuContext, eax)));
                }
                else if (stride == 2)
                {
                    a.mov(ax, word_ptr(r15, offsetof(CpuContext, eax)));
                }
                else
                {
                    a.mov(eax, dword_ptr(r15, offsetof(CpuContext, eax)));
                }

                // Load initial guest EDI
                a.mov(edi, dword_ptr(r15, offsetof(CpuContext, edi)));
                if (use16BitIndex)
                {
                    a.movzx(edi, di);
                }

                // Load guest EFLAGS to check DF (Direction Flag)
                a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eflags)));

                Label loopStartInc = a.newLabel();
                Label loopStartDec = a.newLabel();
                Label dfSet = a.newLabel();

                // Branch based on Direction Flag (DF is bit 10 / 0x400 of EFLAGS)
                a.test(r8d, 0x400);
                a.jnz(dfSet);

                // If 16-bit, load esBase into r8d to optimize the address calculation
                if (segmentedMode)
                {
                    a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esBase)));
                }

                // ==========================================
                // DF == 0: INCREMENT LOOP
                // ==========================================
                a.bind(loopStartInc);
                {
                    // Compute host memory address in r11
                    if (segmentedMode)
                    {
                        a.lea(r11d, ptr(r8d, edi)); // r11d = esBase + di
                    }
                    else
                    {
                        a.mov(r11d, edi);
                    }

                    // Compare accumulator with memory [r14 + r11]
                    if (stride == 1)
                    {
                        a.cmp(al, byte_ptr(r14, r11));
                    }
                    else if (stride == 2)
                    {
                        a.cmp(ax, word_ptr(r14, r11));
                    }
                    else
                    {
                        a.cmp(eax, dword_ptr(r14, r11));
                    }

                    // Snapshot comparison flags (used for both exit eflags and repeat checks)
                    a.pushfq();
                    a.pop(r9);

                    // Update guest EDI register
                    if (use16BitIndex)
                    {
                        a.add(di, stride);
                    }
                    else
                    {
                        a.add(edi, stride);
                    }

                    // Decrement counter
                    a.dec(ecx);
                    a.jz(loopEnd); // ECX exhausted

                    // Test Zero Flag (ZF is bit 6 / 0x40) from the saved comparison flags in r9
                    a.test(r9, 0x40);
                    if (isRepne)
                    {
                        a.jz(loopStartInc); // REPNE: repeat while ZF == 0 (not equal)
                    }
                    else
                    {
                        a.jnz(loopStartInc); // REPE: repeat while ZF == 1 (equal)
                    }
                    a.jmp(loopEnd);
                }

                // ==========================================
                // DF == 1: DECREMENT LOOP
                // ==========================================
                a.bind(dfSet);
                if (segmentedMode)
                {
                    a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esBase)));
                }

                a.bind(loopStartDec);
                {
                    // Compute host memory address in r11
                    if (segmentedMode)
                    {
                        a.lea(r11d, ptr(r8d, edi)); // r11d = esBase + di
                    }
                    else
                    {
                        a.mov(r11d, edi);
                    }

                    // Compare accumulator with memory [r14 + r11]
                    if (stride == 1)
                    {
                        a.cmp(al, byte_ptr(r14, r11));
                    }
                    else if (stride == 2)
                    {
                        a.cmp(ax, word_ptr(r14, r11));
                    }
                    else
                    {
                        a.cmp(eax, dword_ptr(r14, r11));
                    }

                    // Snapshot comparison flags
                    a.pushfq();
                    a.pop(r9);

                    // Update guest EDI register
                    if (use16BitIndex)
                    {
                        a.sub(di, stride);
                    }
                    else
                    {
                        a.sub(edi, stride);
                    }

                    // Decrement counter
                    a.dec(ecx);
                    a.jz(loopEnd); // ECX exhausted

                    // Test Zero Flag (ZF is bit 6 / 0x40) from the saved comparison flags in r9
                    a.test(r9, 0x40);
                    if (isRepne)
                    {
                        a.jz(loopStartDec); // REPNE: repeat while ZF == 0 (not equal)
                    }
                    else
                    {
                        a.jnz(loopStartDec); // REPE: repeat while ZF == 1 (equal)
                    }
                }

                a.bind(loopEnd);
                // Save last comparison flags and updated registers back to the CPU Context
                a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r9d);
                a.push(r9);
                a.popfq();

                if (use16BitIndex)
                {
                    a.mov(word_ptr(r15, offsetof(CpuContext, ecx)), cx);
                    a.mov(word_ptr(r15, offsetof(CpuContext, edi)), di);
                }
                else
                {
                    a.mov(dword_ptr(r15, offsetof(CpuContext, ecx)), ecx);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, edi)), edi);
                }

                a.bind(loopEndNoOp);
            }
            else
            {
                // ==========================================
                // NON-REPEATING SCAS
                // ==========================================
                // Load guest EDI
                a.mov(edi, dword_ptr(r15, offsetof(CpuContext, edi)));
                if (use16BitIndex)
                {
                    a.movzx(edi, di);
                }

                // Load guest EFLAGS to check DF later
                a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, eflags)));

                // Compute host memory address in r11
                if (segmentedMode)
                {
                    a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esBase)));
                    a.lea(r11d, ptr(r8d, edi));
                }
                else
                {
                    a.mov(r11d, edi);
                }

                // Compare accumulator with memory [r14 + r11]
                if (stride == 1)
                {
                    a.mov(r8b, byte_ptr(r15, offsetof(CpuContext, eax)));
                    a.cmp(r8b, byte_ptr(r14, r11));
                }
                else if (stride == 2)
                {
                    a.mov(r8w, word_ptr(r15, offsetof(CpuContext, eax)));
                    a.cmp(r8w, word_ptr(r14, r11));
                }
                else
                {
                    a.mov(eax, dword_ptr(r15, offsetof(CpuContext, eax)));
                    a.cmp(eax, dword_ptr(r14, r11));
                }

                // Save comparison flags
                a.pushfq();
                a.pop(r8);
                a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);

                // Update guest EDI register based on EFLAGS' DF (bit 10 / 0x400 of r9d)
                Label dfSet = a.newLabel();
                Label dfDone = a.newLabel();
                a.test(r9d, 0x400);
                a.jnz(dfSet);

                // DF == 0 (Increment)
                if (use16BitIndex)
                {
                    a.add(di, stride);
                }
                else
                {
                    a.add(edi, stride);
                }
                a.jmp(dfDone);

                // DF == 1 (Decrement)
                a.bind(dfSet);
                if (use16BitIndex)
                {
                    a.sub(di, stride);
                }
                else
                {
                    a.sub(edi, stride);
                }

                a.bind(dfDone);

                // Write back the updated guest EDI register
                if (use16BitIndex)
                {
                    a.mov(word_ptr(r15, offsetof(CpuContext, edi)), di);
                }
                else
                {
                    a.mov(dword_ptr(r15, offsetof(CpuContext, edi)), edi);
                }
                a.push(r8);
                a.popfq();
            }
        }
        break;
        case ZYDIS_MNEMONIC_CALL:
            // Handle FAR call (inter-segment) for NE and MZ modes
            if (instr.meta.branch_type == ZYDIS_BRANCH_TYPE_FAR && (isNE || isMZ))
            {
                uint16_t targetSel = 0, targetOff = 0;
                if (operands[0].type == ZYDIS_OPERAND_TYPE_POINTER)
                {
                    targetSel = operands[0].ptr.segment;
                    targetOff = (uint16_t)operands[0].ptr.offset;
                }
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    // Memory-indirect far call: read 4-byte far pointer from
                    // guest memory, push return CS:IP, then jump to target.
                    if (!resolveMemoryIntoR8(operands[0].mem))
                        return nullptr;
                    uint32_t retLinear = currentEip + instr.length;
                    uint32_t retIPForPush = retLinear;
                    if (isMZ)
                        retIPForPush = retLinear - (uint32_t)context.cs * 16;
                    a.sub(rsp, 40);
                    a.mov(rcx, (uint64_t)this);
                    a.mov(edx, r8d);           // arg2: linear address of far pointer
                    a.mov(r8d, retIPForPush);  // arg3: return IP (segment-relative)
                    a.movzx(r9d, word_ptr(r15, offsetof(CpuContext, cs)));  // arg4: retCS
                    a.mov(rax, (uint64_t)JitFarCallMemIndirectLinear);
                    EmitHostAbiArgs(a);
                    a.call(rax);
                    a.add(rsp, 40);
                    blockEnded = true;
                    break;
                }
                else
                {
                    // Memory-indirect or other far call forms not yet supported
                    return nullptr;
                }

                uint32_t retAddr = currentEip + instr.length;
                uint32_t retIPForPush = retAddr;
                if (isMZ)
                    retIPForPush = retAddr - (uint32_t)context.cs * 16;
                // Push return CS (16-bit), then IP (16-bit) onto guest stack
                a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));
                a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                a.movzx(r9d, word_ptr(r15, offsetof(CpuContext, cs))); // load CS into r9w

                a.sub(r8d, 2);
                a.movzx(r8d, r8w);
                a.lea(r10, dword_ptr(r14, r8));
                a.mov(word_ptr(r10, r11, 0), r9w); // push CS (16-bit)

                a.sub(r8d, 2);
                a.movzx(r8d, r8w);
                a.lea(r10, dword_ptr(r14, r8));
                a.mov(word_ptr(r10, r11, 0), (uint16_t)retIPForPush); // push IP (16-bit)

                a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);

                // Update CS and resolve target EIP via runtime helper
                a.mov(word_ptr(r15, offsetof(CpuContext, cs)), targetSel);
                a.sub(rsp, 40); // 16-align + 32 shadow
                a.mov(rcx, (uint64_t)this);
                a.mov(edx, targetSel);
                a.mov(r8d, targetOff);
                a.mov(rax, (uint64_t)JitGetLinearAddress);
                EmitHostAbiArgs(a);
                a.call(rax);
                a.add(rsp, 40);
                a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), eax);
                blockEnded = true;
                break;
            }
            if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t target = currentEip + instr.length + (int32_t)operands[0].imm.value.s;
                uint32_t retAddr = currentEip + instr.length;
                if (isMZ) {
                    // Real-mode: retAddr is segment-relative; target is linear.
                    // currentEip is already linear, so convert to an IP offset,
                    // add rel16 with 16-bit wrap, then map back (same as JMP path).
                    uint32_t csBase = (uint32_t)context.cs << 4;
                    retAddr = (retAddr - csBase) & 0xFFFF;
                    target = csBase + (uint16_t)((currentEip - csBase) + instr.length + (int32_t)operands[0].imm.value.s);
                }
                a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));
                if (isNE || isMZ)
                {
                    // 16-bit near call: push 2-byte IP
                    a.lea(r8d, dword_ptr(r8d, -2));
                    a.movzx(r8d, r8w);
                }
                else
                {
                    a.lea(r8d, dword_ptr(r8d, -4));
                }

                a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
                if (isNE || isMZ)
                {
                    a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                    a.lea(r10, dword_ptr(r14, r8));
                    a.add(r10, r11);
                    if (isMZ)
                    {
                        // Cached real-mode blocks can execute through an
                        // overlapping CS segment.  Derive the return IP from
                        // the runtime CS instead of the selector present when
                        // this block was compiled.
                        a.mov(r9d, currentEip + instr.length);
                        a.movzx(r11d, word_ptr(r15, offsetof(CpuContext, cs)));
                        a.shl(r11d, 4);
                        a.sub(r9d, r11d);
                        a.mov(word_ptr(r10, 0), r9w);
                    }
                    else
                    {
                        a.mov(word_ptr(r10, 0), (uint16_t)retAddr);
                    }
                }
                else
                {
                    a.mov(dword_ptr(r14, r8, 0), retAddr);
                }
                a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), target);
                blockEnded = true;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    if (isNE || isMZ)
                        a.movzx(r9d, word_ptr(r15, off)); // Load 16-bit target address from register
                    else
                        a.mov(r9d, dword_ptr(r15, off)); // Load 32-bit target address from register
                    uint32_t retAddr = currentEip + instr.length;
                    if (isMZ) {
                        uint32_t csBase = (uint32_t)context.cs << 4;
                        retAddr = (retAddr - csBase) & 0xFFFF;
                    }

                    // Log the indirect call
                    a.push(r9);      // Save target (volatile)
                    a.sub(rsp, 32);  // push(8) + 32 realigns RSP to 16n for the call

                    a.mov(rcx, (uint64_t)this);
                    a.mov(edx, r9d);
                    a.mov(r8d, retAddr);
                    a.mov(rax, (uint64_t)&LogIndirectCall);
                    EmitHostAbiArgs(a);
                    a.call(rax);
                    a.add(rsp, 32);
                    a.pop(r9);

                    // Runtime Check: Is it a trap?
                    Label regular_call = a.newLabel();
                    a.cmp(r9d, (uint32_t)trapPageBase);
                    a.jb(regular_call);

                    // TRAP: Push retAddr, Set EIP, Return to Host
                    a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));
                    if (isNE || isMZ)
                    {
                        a.sub(r8d, 2);
                        a.movzx(r8d, r8w);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
                        a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                        a.lea(r10, dword_ptr(r14, r8));
                        a.add(r10, r11);
                        a.mov(word_ptr(r10, 0), (uint16_t)retAddr);
                    }
                    else
                    {
                        a.sub(r8d, 4);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
                        a.mov(dword_ptr(r14, r8, 0), retAddr);
                    }
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), r9d);

                    // CALL preserves guest flags. Do not leak the host CMP/SUB
                    // flags used by this bridge into CpuContext.
                    a.pop(r15);
                    a.pop(r14);
                    a.pop(r13);
                    a.pop(r12);
                    a.pop(rsi);
                    a.pop(rdi);
                    a.pop(rbp);
                    a.pop(rbx);
                    a.ret();

                    a.bind(regular_call);

                    if (isNE || isMZ)
                    {
                        a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, csBase)));
                        a.add(r9d, r11d);
                    }

                    // Regular Call: Jump to target
                    a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));
                    if (isNE || isMZ)
                    {
                        a.lea(r8d, dword_ptr(r8d, -2));
                        a.movzx(r8d, r8w);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
                        a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                        a.lea(r10, dword_ptr(r14, r8));
                        a.add(r10, r11);
                        a.mov(word_ptr(r10, 0), (uint16_t)retAddr);
                    }
                    else
                    {
                        a.lea(r8d, dword_ptr(r8d, -4));
                        a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
                        a.mov(dword_ptr(r14, r8, 0), retAddr);
                    }
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), r9d);
                    blockEnded = true;
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (isNE || isMZ)
                        a.movzx(r9d, word_ptr(r14, r8, 0)); // Load 16-bit target address from memory
                    else
                        a.mov(r9d, dword_ptr(r14, r8, 0)); // Load 32-bit target address from memory
                    uint32_t retAddr = currentEip + instr.length;
                    if (isMZ) {
                        uint32_t csBase = (uint32_t)context.cs << 4;
                        retAddr = (retAddr - csBase) & 0xFFFF;
                    }

                    // Log the indirect call
                    a.push(r9);      // Save target (volatile)
                    a.sub(rsp, 32);  // push(8) + 32 realigns RSP to 16n for the call

                    a.mov(rcx, (uint64_t)this);
                    a.mov(edx, r9d);
                    a.mov(r8d, retAddr);
                    a.mov(rax, (uint64_t)&LogIndirectCall);
                    EmitHostAbiArgs(a);
                    a.call(rax);
                    a.add(rsp, 32);
                    a.pop(r9);

                    // Runtime Check: Is it a trap?
                    Label regular_call = a.newLabel();
                    a.cmp(r9d, (uint32_t)trapPageBase);
                    a.jb(regular_call);

                    // TRAP: Push retAddr, Set EIP, Return to Host
                    a.mov(r10d, dword_ptr(r15, offsetof(CpuContext, esp)));
                    if (isNE || isMZ)
                    {
                        a.sub(r10d, 2);
                        a.movzx(r10d, r10w);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r10d);
                        a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                        a.add(r10d, r11d);
                        a.mov(word_ptr(r14, r10, 0), (uint16_t)retAddr);
                    }
                    else
                    {
                        a.sub(r10d, 4);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r10d);
                        a.mov(dword_ptr(r14, r10, 0), retAddr);
                    }
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), r9d);

                    // CALL preserves guest flags. Do not leak the host CMP/SUB
                    // flags used by this bridge into CpuContext.
                    a.pop(r15);
                    a.pop(r14);
                    a.pop(r13);
                    a.pop(r12);
                    a.pop(rsi);
                    a.pop(rdi);
                    a.pop(rbp);
                    a.pop(rbx);
                    a.ret();

                    a.bind(regular_call);

                    if (isNE || isMZ)
                    {
                        a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, csBase)));
                        a.add(r9d, r11d);
                    }

                    // Regular Call: Jump to target
                    a.mov(r10d, dword_ptr(r15, offsetof(CpuContext, esp)));
                    if (isNE || isMZ)
                    {
                        a.lea(r10d, dword_ptr(r10d, -2));
                        a.movzx(r10d, r10w);
                        a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r10d);
                        a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                        a.add(r10d, r11d);
                        a.mov(word_ptr(r14, r10, 0), (uint16_t)retAddr);
                    }
                    else
                    {
                        a.lea(r10d, dword_ptr(r10d, -4));
                        a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r10d);
                        a.mov(dword_ptr(r14, r10, 0), retAddr);
                    }
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), r9d);
                    blockEnded = true;
                }
            }
            break;

        case ZYDIS_MNEMONIC_RET:
            // Handle FAR return (inter-segment) for NE and MZ modes
            if (instr.meta.branch_type == ZYDIS_BRANCH_TYPE_FAR && (isNE || isMZ))
            {
                // Pop IP (16-bit), then CS (16-bit) from guest stack
                a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));
                a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));

                // IP
                a.movzx(r8d, r8w);
                a.lea(r10, dword_ptr(r14, r8));
                a.movzx(r9d, word_ptr(r10, r11, 0));

                // CS
                a.add(r8d, 2);
                a.movzx(r8d, r8w);
                a.lea(r10, dword_ptr(r14, r8));
                a.movzx(r10d, word_ptr(r10, r11, 0));

                a.add(r8d, 2);
                a.movzx(r8d, r8w);

                // Optional immediate: pop extra bytes
                if (instr.operand_count > 0 && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    a.add(r8d, (uint32_t)operands[0].imm.value.u);
                    a.movzx(r8d, r8w);
                }
                a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
                a.mov(word_ptr(r15, offsetof(CpuContext, cs)), r10w);
                // Resolve linear address via runtime helper
                a.sub(rsp, 40); // 16-align + 32 shadow
                a.mov(rcx, (uint64_t)this);
                a.mov(edx, r10d);
                a.mov(r8d, r9d);
                a.mov(rax, (uint64_t)JitGetLinearAddress);
                EmitHostAbiArgs(a);
                a.call(rax);
                a.add(rsp, 40);
                a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), eax);
                blockEnded = true;
                break;
            }
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));
            if (isNE || isMZ)
            {
                a.movzx(r8d, r8w);
                a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                a.lea(r10, dword_ptr(r14, r8));
                a.add(r10, r11);
                a.movzx(r9d, word_ptr(r10, 0));
                a.lea(r8d, dword_ptr(r8d, 2));
                a.movzx(r8d, r8w);

                a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, csBase)));
                a.add(r9d, r11d);
            }
            else
            {
                a.mov(r9d, dword_ptr(r14, r8, 0));
                a.lea(r8d, dword_ptr(r8d, 4));
            }
            if (instr.operand_count > 0 && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                a.lea(r8d, dword_ptr(r8d, (uint32_t)operands[0].imm.value.u));
            }
            a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), r9d);

            blockEnded = true;
            break;

        case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_IRETD:
            // IRET in MZ: pop IP, CS, FLAGS. IRETD: pop EIP, CS, EFLAGS.
            {
                a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));
                if (isMZ || instr.mnemonic == ZYDIS_MNEMONIC_IRET)
                {
                    // Stack is at ssBase:SP (16-bit). Compute the host pointer
                    // to the interrupt frame (RET already does this; IRET did
                    // not, reading from r14+SP without ssBase and returning to 0).
                    a.movzx(r8d, r8w);
                    a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                    a.lea(r12, dword_ptr(r14, r8));
                    a.add(r12, r11);

                    a.movzx(r9d, word_ptr(r12, 0));  // IP
                    a.movzx(r10d, word_ptr(r12, 2)); // CS
                    a.movzx(r11d, word_ptr(r12, 4)); // FLAGS
                    a.lea(r8d, dword_ptr(r8d, 6));   // SP += 6
                    a.movzx(r8d, r8w);
                    a.mov(word_ptr(r15, offsetof(CpuContext, cs)), r10w);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r11d);

                    // Call JitGetLinearAddress(engine, CS, IP)
                    a.push(r8);     // Save ESP
                    a.push(r11);    // Save FLAGS
                    a.sub(rsp, 40); // Align 16 + 32 shadow space
                    a.mov(rcx, (uint64_t)this);
                    a.mov(edx, r10d); // CS
                    a.mov(r8d, r9d);  // IP
                    a.mov(rax, (uint64_t)JitGetLinearAddress);
                    EmitHostAbiArgs(a);
                    a.call(rax);
                    a.add(rsp, 40);
                    a.pop(r11); // Restore FLAGS
                    a.pop(r8);  // Restore ESP
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), eax);
                }
                else
                {
                    a.mov(r9d, dword_ptr(r14, r8, 0)); // EIP
                    a.lea(r8d, dword_ptr(r8d, 4));
                    a.mov(r10d, dword_ptr(r14, r8, 0)); // CS
                    a.lea(r8d, dword_ptr(r8d, 4));
                    a.mov(r11d, dword_ptr(r14, r8, 0)); // EFLAGS
                    a.lea(r8d, dword_ptr(r8d, 4));
                    a.mov(word_ptr(r15, offsetof(CpuContext, cs)), r10w);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), r9d);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r11d);
                }
                a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
                // Restore flags to host CPU for conditional jumps
                a.push(r11);
                a.popfq();
                blockEnded = true;
            }
            break;

        // ---- Packed integer ALU (MMX 64-bit and the SSE2 128-bit forms) ----
        // These all share one shape: dst = dst OP src, where src is either a
        // vector register or memory.  They were missing wholesale, and since an
        // unimplemented mnemonic aborts the entire block, one of them (pand) was
        // enough to stop Smacker's MMX video decoder dead.
        //
        // Shift-by-immediate forms (e.g. "psrlw mm0, 3") are included: asmjit
        // takes the same overload with an Imm operand.
        case ZYDIS_MNEMONIC_PAND:
        case ZYDIS_MNEMONIC_PANDN:
        case ZYDIS_MNEMONIC_POR:
        case ZYDIS_MNEMONIC_PADDB:
        case ZYDIS_MNEMONIC_PADDW:
        case ZYDIS_MNEMONIC_PADDD:
        case ZYDIS_MNEMONIC_PADDQ:
        case ZYDIS_MNEMONIC_PADDSB:
        case ZYDIS_MNEMONIC_PADDSW:
        case ZYDIS_MNEMONIC_PADDUSB:
        case ZYDIS_MNEMONIC_PADDUSW:
        case ZYDIS_MNEMONIC_PSUBB:
        case ZYDIS_MNEMONIC_PSUBW:
        case ZYDIS_MNEMONIC_PSUBD:
        case ZYDIS_MNEMONIC_PSUBQ:
        case ZYDIS_MNEMONIC_PSUBSB:
        case ZYDIS_MNEMONIC_PSUBSW:
        case ZYDIS_MNEMONIC_PSUBUSB:
        case ZYDIS_MNEMONIC_PSUBUSW:
        case ZYDIS_MNEMONIC_PCMPEQB:
        case ZYDIS_MNEMONIC_PCMPEQW:
        case ZYDIS_MNEMONIC_PCMPEQD:
        case ZYDIS_MNEMONIC_PCMPGTB:
        case ZYDIS_MNEMONIC_PCMPGTW:
        case ZYDIS_MNEMONIC_PCMPGTD:
        case ZYDIS_MNEMONIC_PUNPCKLBW:
        case ZYDIS_MNEMONIC_PUNPCKLWD:
        case ZYDIS_MNEMONIC_PUNPCKHBW:
        case ZYDIS_MNEMONIC_PUNPCKHWD:
        case ZYDIS_MNEMONIC_PUNPCKHDQ:
        case ZYDIS_MNEMONIC_PACKUSWB:
        case ZYDIS_MNEMONIC_PACKSSWB:
        case ZYDIS_MNEMONIC_PACKSSDW:
        case ZYDIS_MNEMONIC_PMULLW:
        case ZYDIS_MNEMONIC_PMULHW:
        case ZYDIS_MNEMONIC_PMULHUW:
        case ZYDIS_MNEMONIC_PMADDWD:
        case ZYDIS_MNEMONIC_PAVGB:
        case ZYDIS_MNEMONIC_PAVGW:
        case ZYDIS_MNEMONIC_PMINUB:
        case ZYDIS_MNEMONIC_PMAXUB:
        case ZYDIS_MNEMONIC_PSADBW:
        case ZYDIS_MNEMONIC_PSLLW:
        case ZYDIS_MNEMONIC_PSLLD:
        case ZYDIS_MNEMONIC_PSRLW:
        case ZYDIS_MNEMONIC_PSRLD:
        case ZYDIS_MNEMONIC_PSRLQ:
        case ZYDIS_MNEMONIC_PSRAW:
        case ZYDIS_MNEMONIC_PSRAD:
        {
            // Register and memory sources: the whole set.
            auto emitPacked = [&](auto &&dst, auto &&src) -> bool {
                switch (instr.mnemonic)
                {
                case ZYDIS_MNEMONIC_PAND: a.pand(dst, src); return true;
                case ZYDIS_MNEMONIC_PANDN: a.pandn(dst, src); return true;
                case ZYDIS_MNEMONIC_POR: a.por(dst, src); return true;
                case ZYDIS_MNEMONIC_PADDB: a.paddb(dst, src); return true;
                case ZYDIS_MNEMONIC_PADDW: a.paddw(dst, src); return true;
                case ZYDIS_MNEMONIC_PADDD: a.paddd(dst, src); return true;
                case ZYDIS_MNEMONIC_PADDQ: a.paddq(dst, src); return true;
                case ZYDIS_MNEMONIC_PADDSB: a.paddsb(dst, src); return true;
                case ZYDIS_MNEMONIC_PADDSW: a.paddsw(dst, src); return true;
                case ZYDIS_MNEMONIC_PADDUSB: a.paddusb(dst, src); return true;
                case ZYDIS_MNEMONIC_PADDUSW: a.paddusw(dst, src); return true;
                case ZYDIS_MNEMONIC_PSUBB: a.psubb(dst, src); return true;
                case ZYDIS_MNEMONIC_PSUBW: a.psubw(dst, src); return true;
                case ZYDIS_MNEMONIC_PSUBD: a.psubd(dst, src); return true;
                case ZYDIS_MNEMONIC_PSUBQ: a.psubq(dst, src); return true;
                case ZYDIS_MNEMONIC_PSUBSB: a.psubsb(dst, src); return true;
                case ZYDIS_MNEMONIC_PSUBSW: a.psubsw(dst, src); return true;
                case ZYDIS_MNEMONIC_PSUBUSB: a.psubusb(dst, src); return true;
                case ZYDIS_MNEMONIC_PSUBUSW: a.psubusw(dst, src); return true;
                case ZYDIS_MNEMONIC_PCMPEQB: a.pcmpeqb(dst, src); return true;
                case ZYDIS_MNEMONIC_PCMPEQW: a.pcmpeqw(dst, src); return true;
                case ZYDIS_MNEMONIC_PCMPEQD: a.pcmpeqd(dst, src); return true;
                case ZYDIS_MNEMONIC_PCMPGTB: a.pcmpgtb(dst, src); return true;
                case ZYDIS_MNEMONIC_PCMPGTW: a.pcmpgtw(dst, src); return true;
                case ZYDIS_MNEMONIC_PCMPGTD: a.pcmpgtd(dst, src); return true;
                case ZYDIS_MNEMONIC_PUNPCKLBW: a.punpcklbw(dst, src); return true;
                case ZYDIS_MNEMONIC_PUNPCKLWD: a.punpcklwd(dst, src); return true;
                case ZYDIS_MNEMONIC_PUNPCKHBW: a.punpckhbw(dst, src); return true;
                case ZYDIS_MNEMONIC_PUNPCKHWD: a.punpckhwd(dst, src); return true;
                case ZYDIS_MNEMONIC_PUNPCKHDQ: a.punpckhdq(dst, src); return true;
                case ZYDIS_MNEMONIC_PACKUSWB: a.packuswb(dst, src); return true;
                case ZYDIS_MNEMONIC_PACKSSWB: a.packsswb(dst, src); return true;
                case ZYDIS_MNEMONIC_PACKSSDW: a.packssdw(dst, src); return true;
                case ZYDIS_MNEMONIC_PMULLW: a.pmullw(dst, src); return true;
                case ZYDIS_MNEMONIC_PMULHW: a.pmulhw(dst, src); return true;
                case ZYDIS_MNEMONIC_PMULHUW: a.pmulhuw(dst, src); return true;
                case ZYDIS_MNEMONIC_PMADDWD: a.pmaddwd(dst, src); return true;
                case ZYDIS_MNEMONIC_PAVGB: a.pavgb(dst, src); return true;
                case ZYDIS_MNEMONIC_PAVGW: a.pavgw(dst, src); return true;
                case ZYDIS_MNEMONIC_PMINUB: a.pminub(dst, src); return true;
                case ZYDIS_MNEMONIC_PMAXUB: a.pmaxub(dst, src); return true;
                case ZYDIS_MNEMONIC_PSADBW: a.psadbw(dst, src); return true;
                case ZYDIS_MNEMONIC_PSLLW: a.psllw(dst, src); return true;
                case ZYDIS_MNEMONIC_PSLLD: a.pslld(dst, src); return true;
                case ZYDIS_MNEMONIC_PSRLW: a.psrlw(dst, src); return true;
                case ZYDIS_MNEMONIC_PSRLD: a.psrld(dst, src); return true;
                case ZYDIS_MNEMONIC_PSRLQ: a.psrlq(dst, src); return true;
                case ZYDIS_MNEMONIC_PSRAW: a.psraw(dst, src); return true;
                case ZYDIS_MNEMONIC_PSRAD: a.psrad(dst, src); return true;
                default: return false;
                }
            };

            // Immediate sources: only the shift-by-count forms take one, so they
            // get their own dispatcher rather than instantiating the full switch
            // against an Imm operand.
            auto emitPackedImm = [&](auto &&dst, const Imm &count) -> bool {
                switch (instr.mnemonic)
                {
                case ZYDIS_MNEMONIC_PSLLW: a.psllw(dst, count); return true;
                case ZYDIS_MNEMONIC_PSLLD: a.pslld(dst, count); return true;
                case ZYDIS_MNEMONIC_PSRLW: a.psrlw(dst, count); return true;
                case ZYDIS_MNEMONIC_PSRLD: a.psrld(dst, count); return true;
                case ZYDIS_MNEMONIC_PSRLQ: a.psrlq(dst, count); return true;
                case ZYDIS_MNEMONIC_PSRAW: a.psraw(dst, count); return true;
                case ZYDIS_MNEMONIC_PSRAD: a.psrad(dst, count); return true;
                default: return false;
                }
            };

            const uint32_t reg0 = (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
                                      ? operands[0].reg.value : 0;
            const bool dstIsMm  = reg0 >= ZYDIS_REGISTER_MM0  && reg0 <= ZYDIS_REGISTER_MM7;
            const bool dstIsXmm = reg0 >= ZYDIS_REGISTER_XMM0 && reg0 <= ZYDIS_REGISTER_XMM7;
            if (!dstIsMm && !dstIsXmm) goto unimplemented;

            const int off0 = dstIsMm
                ? (int)(offsetof(CpuContext, mmx) + (reg0 - ZYDIS_REGISTER_MM0) * 8)
                : (int)(offsetof(CpuContext, xmm) + (reg0 - ZYDIS_REGISTER_XMM0) * 16);

            if (dstIsMm) a.movq(mm0, qword_ptr(r15, off0));
            else         a.movdqu(xmm0, xmmword_ptr(r15, off0));

            bool ok = false;
            if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                const Imm count((uint32_t)operands[1].imm.value.u);
                ok = dstIsMm ? emitPackedImm(mm0, count) : emitPackedImm(xmm0, count);
            }
            else if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                const uint32_t reg1 = operands[1].reg.value;
                if (reg1 >= ZYDIS_REGISTER_MM0 && reg1 <= ZYDIS_REGISTER_MM7 && dstIsMm)
                {
                    int off1 = (int)(offsetof(CpuContext, mmx) + (reg1 - ZYDIS_REGISTER_MM0) * 8);
                    a.movq(mm1, qword_ptr(r15, off1));
                    ok = emitPacked(mm0, mm1);
                }
                else if (reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7 && dstIsXmm)
                {
                    int off1 = (int)(offsetof(CpuContext, xmm) + (reg1 - ZYDIS_REGISTER_XMM0) * 16);
                    a.movdqu(xmm1, xmmword_ptr(r15, off1));
                    ok = emitPacked(xmm0, xmm1);
                }
            }
            else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && resolveMemoryIntoR8(operands[1].mem))
            {
                if (dstIsMm)
                {
                    a.movq(mm1, qword_ptr(r14, r8, 0));
                    ok = emitPacked(mm0, mm1);
                }
                else
                {
                    a.movdqu(xmm1, xmmword_ptr(r14, r8, 0));
                    ok = emitPacked(xmm0, xmm1);
                }
            }

            if (!ok) goto unimplemented;

            if (dstIsMm) a.movq(qword_ptr(r15, off0), mm0);
            else         a.movdqu(xmmword_ptr(r15, off0), xmm0);
        }
        break;

        case ZYDIS_MNEMONIC_PXOR:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                uint32_t reg0 = operands[0].reg.value;
                uint32_t reg1 = operands[1].reg.value;

                if (reg0 >= ZYDIS_REGISTER_MM0 && reg0 <= ZYDIS_REGISTER_MM7 &&
                    reg1 >= ZYDIS_REGISTER_MM0 && reg1 <= ZYDIS_REGISTER_MM7)
                {

                    int idx0 = reg0 - ZYDIS_REGISTER_MM0;
                    int idx1 = reg1 - ZYDIS_REGISTER_MM0;

                    // Load MM0 from Context
                    int off0 = offsetof(CpuContext, mmx) + idx0 * 8;
                    a.movq(mm0, qword_ptr(r15, off0));

                    // Load MM1 from Context
                    int off1 = offsetof(CpuContext, mmx) + idx1 * 8;
                    a.movq(mm1, qword_ptr(r15, off1));

                    a.pxor(mm0, mm1);

                    // Store Back
                    a.movq(qword_ptr(r15, off0), mm0);
                }
                else if (reg0 >= ZYDIS_REGISTER_XMM0 && reg0 <= ZYDIS_REGISTER_XMM7 &&
                         reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7)
                {
                    // SSE Logic
                    int idx0 = reg0 - ZYDIS_REGISTER_XMM0;
                    int idx1 = reg1 - ZYDIS_REGISTER_XMM0;
                    int off0 = offsetof(CpuContext, xmm) + idx0 * 16;
                    int off1 = offsetof(CpuContext, xmm) + idx1 * 16;
                    a.movdqu(xmm0, xmmword_ptr(r15, off0));
                    a.movdqu(xmm1, xmmword_ptr(r15, off1));
                    a.pxor(xmm0, xmm1);
                    a.movdqu(xmmword_ptr(r15, off0), xmm0);
                }
                else
                    goto unimplemented;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                uint32_t reg0 = operands[0].reg.value;
                if (reg0 >= ZYDIS_REGISTER_MM0 && reg0 <= ZYDIS_REGISTER_MM7 && resolveMemoryIntoR8(operands[1].mem))
                {
                    int idx0 = reg0 - ZYDIS_REGISTER_MM0;
                    int off0 = offsetof(CpuContext, mmx) + idx0 * 8;

                    a.movq(mm0, qword_ptr(r15, off0));
                    a.movq(mm1, qword_ptr(r14, r8, 0)); // Load from guest mem

                    a.pxor(mm0, mm1);

                    a.movq(qword_ptr(r15, off0), mm0);
                }
                else if (reg0 >= ZYDIS_REGISTER_XMM0 && reg0 <= ZYDIS_REGISTER_XMM7 && resolveMemoryIntoR8(operands[1].mem))
                {
                    // SSE Logic
                    int idx0 = reg0 - ZYDIS_REGISTER_XMM0;
                    int off0 = offsetof(CpuContext, xmm) + idx0 * 16;
                    a.movdqu(xmm0, xmmword_ptr(r15, off0));
                    a.movdqu(xmm1, xmmword_ptr(r14, r8, 0)); // Load from guest mem
                    a.pxor(xmm0, xmm1);
                    a.movdqu(xmmword_ptr(r15, off0), xmm0);
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_PUNPCKLDQ:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                uint32_t reg0 = operands[0].reg.value;
                uint32_t reg1 = operands[1].reg.value;

                if (reg0 >= ZYDIS_REGISTER_MM0 && reg0 <= ZYDIS_REGISTER_MM7 &&
                    reg1 >= ZYDIS_REGISTER_MM0 && reg1 <= ZYDIS_REGISTER_MM7)
                {
                    int idx0 = reg0 - ZYDIS_REGISTER_MM0;
                    int idx1 = reg1 - ZYDIS_REGISTER_MM0;
                    int off0 = offsetof(CpuContext, mmx) + idx0 * 8;
                    int off1 = offsetof(CpuContext, mmx) + idx1 * 8;
                    a.movq(mm0, qword_ptr(r15, off0));
                    a.movq(mm1, qword_ptr(r15, off1));
                    a.punpckldq(mm0, mm1);
                    a.movq(qword_ptr(r15, off0), mm0);
                }
                else if (reg0 >= ZYDIS_REGISTER_XMM0 && reg0 <= ZYDIS_REGISTER_XMM7 &&
                         reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7)
                {
                    int idx0 = reg0 - ZYDIS_REGISTER_XMM0;
                    int idx1 = reg1 - ZYDIS_REGISTER_XMM0;
                    int off0 = offsetof(CpuContext, xmm) + idx0 * 16;
                    int off1 = offsetof(CpuContext, xmm) + idx1 * 16;
                    a.movdqu(xmm0, xmmword_ptr(r15, off0));
                    a.movdqu(xmm1, xmmword_ptr(r15, off1));
                    a.punpckldq(xmm0, xmm1);
                    a.movdqu(xmmword_ptr(r15, off0), xmm0);
                }
                else
                    goto unimplemented;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                uint32_t reg0 = operands[0].reg.value;
                if (reg0 >= ZYDIS_REGISTER_MM0 && reg0 <= ZYDIS_REGISTER_MM7 && resolveMemoryIntoR8(operands[1].mem))
                {
                    int idx0 = reg0 - ZYDIS_REGISTER_MM0;
                    int off0 = offsetof(CpuContext, mmx) + idx0 * 8;
                    a.movq(mm0, qword_ptr(r15, off0));
                    a.movq(mm1, qword_ptr(r14, r8, 0));
                    a.punpckldq(mm0, mm1);
                    a.movq(qword_ptr(r15, off0), mm0);
                }
                else if (reg0 >= ZYDIS_REGISTER_XMM0 && reg0 <= ZYDIS_REGISTER_XMM7 && resolveMemoryIntoR8(operands[1].mem))
                {
                    int idx0 = reg0 - ZYDIS_REGISTER_XMM0;
                    int off0 = offsetof(CpuContext, xmm) + idx0 * 16;
                    a.movdqu(xmm0, xmmword_ptr(r15, off0));
                    a.movdqu(xmm1, xmmword_ptr(r14, r8, 0));
                    a.punpckldq(xmm0, xmm1);
                    a.movdqu(xmmword_ptr(r15, off0), xmm0);
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_PSLLQ:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                uint32_t reg0 = operands[0].reg.value;
                uint32_t reg1 = operands[1].reg.value;

                if (reg0 >= ZYDIS_REGISTER_MM0 && reg0 <= ZYDIS_REGISTER_MM7 &&
                    reg1 >= ZYDIS_REGISTER_MM0 && reg1 <= ZYDIS_REGISTER_MM7)
                {
                    int idx0 = reg0 - ZYDIS_REGISTER_MM0;
                    int idx1 = reg1 - ZYDIS_REGISTER_MM0;
                    int off0 = offsetof(CpuContext, mmx) + idx0 * 8;
                    int off1 = offsetof(CpuContext, mmx) + idx1 * 8;
                    a.movq(mm0, qword_ptr(r15, off0));
                    a.movq(mm1, qword_ptr(r15, off1));
                    a.psllq(mm0, mm1);
                    a.movq(qword_ptr(r15, off0), mm0);
                }
                else if (reg0 >= ZYDIS_REGISTER_XMM0 && reg0 <= ZYDIS_REGISTER_XMM7 &&
                         reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7)
                {
                    int idx0 = reg0 - ZYDIS_REGISTER_XMM0;
                    int idx1 = reg1 - ZYDIS_REGISTER_XMM0;
                    int off0 = offsetof(CpuContext, xmm) + idx0 * 16;
                    int off1 = offsetof(CpuContext, xmm) + idx1 * 16;
                    a.movdqu(xmm0, xmmword_ptr(r15, off0));
                    a.movdqu(xmm1, xmmword_ptr(r15, off1));
                    a.psllq(xmm0, xmm1);
                    a.movdqu(xmmword_ptr(r15, off0), xmm0);
                }
                else
                    goto unimplemented;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                uint32_t reg0 = operands[0].reg.value;
                if (reg0 >= ZYDIS_REGISTER_MM0 && reg0 <= ZYDIS_REGISTER_MM7 && resolveMemoryIntoR8(operands[1].mem))
                {
                    int idx0 = reg0 - ZYDIS_REGISTER_MM0;
                    int off0 = offsetof(CpuContext, mmx) + idx0 * 8;
                    a.movq(mm0, qword_ptr(r15, off0));
                    a.movq(mm1, qword_ptr(r14, r8, 0));
                    a.psllq(mm0, mm1);
                    a.movq(qword_ptr(r15, off0), mm0);
                }
                else if (reg0 >= ZYDIS_REGISTER_XMM0 && reg0 <= ZYDIS_REGISTER_XMM7 && resolveMemoryIntoR8(operands[1].mem))
                {
                    int idx0 = reg0 - ZYDIS_REGISTER_XMM0;
                    int off0 = offsetof(CpuContext, xmm) + idx0 * 16;
                    a.movdqu(xmm0, xmmword_ptr(r15, off0));
                    a.movdqu(xmm1, xmmword_ptr(r14, r8, 0));
                    a.psllq(xmm0, xmm1);
                    a.movdqu(xmmword_ptr(r15, off0), xmm0);
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t reg0 = operands[0].reg.value;
                uint32_t imm = (uint32_t)operands[1].imm.value.u;
                if (reg0 >= ZYDIS_REGISTER_MM0 && reg0 <= ZYDIS_REGISTER_MM7)
                {
                    int idx0 = reg0 - ZYDIS_REGISTER_MM0;
                    int off0 = offsetof(CpuContext, mmx) + idx0 * 8;
                    a.movq(mm0, qword_ptr(r15, off0));
                    a.psllq(mm0, imm);
                    a.movq(qword_ptr(r15, off0), mm0);
                }
                else if (reg0 >= ZYDIS_REGISTER_XMM0 && reg0 <= ZYDIS_REGISTER_XMM7)
                {
                    int idx0 = reg0 - ZYDIS_REGISTER_XMM0;
                    int off0 = offsetof(CpuContext, xmm) + idx0 * 16;
                    a.movdqu(xmm0, xmmword_ptr(r15, off0));
                    a.psllq(xmm0, imm);
                    a.movdqu(xmmword_ptr(r15, off0), xmm0);
                }
                else
                    goto unimplemented;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_MOVUPS:
        case ZYDIS_MNEMONIC_MOVAPS:
        case ZYDIS_MNEMONIC_MOVDQU:
        case ZYDIS_MNEMONIC_MOVDQA:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                // Reg -> Reg
                uint32_t reg0 = operands[0].reg.value;
                uint32_t reg1 = operands[1].reg.value;
                if (reg0 >= ZYDIS_REGISTER_XMM0 && reg0 <= ZYDIS_REGISTER_XMM7 &&
                    reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7)
                {
                    int idx0 = reg0 - ZYDIS_REGISTER_XMM0;
                    int idx1 = reg1 - ZYDIS_REGISTER_XMM0;
                    int off0 = offsetof(CpuContext, xmm) + idx0 * 16;
                    int off1 = offsetof(CpuContext, xmm) + idx1 * 16;
                    a.movdqu(xmm0, xmmword_ptr(r15, off1)); // Load src
                    a.movdqu(xmmword_ptr(r15, off0), xmm0); // Store dest
                }
                else
                    goto unimplemented;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                // Mem -> Reg
                uint32_t reg0 = operands[0].reg.value;
                if (reg0 >= ZYDIS_REGISTER_XMM0 && reg0 <= ZYDIS_REGISTER_XMM7 && resolveMemoryIntoR8(operands[1].mem))
                {
                    int idx0 = reg0 - ZYDIS_REGISTER_XMM0;
                    int off0 = offsetof(CpuContext, xmm) + idx0 * 16;
                    a.movdqu(xmm0, xmmword_ptr(r14, r8, 0)); // Load from guest mem
                    a.movdqu(xmmword_ptr(r15, off0), xmm0);  // Store to ctx
                }
                else
                    return nullptr;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                // Reg -> Mem
                uint32_t reg1 = operands[1].reg.value;
                if (reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7 && resolveMemoryIntoR8(operands[0].mem))
                {
                    int idx1 = reg1 - ZYDIS_REGISTER_XMM0;
                    int off1 = offsetof(CpuContext, xmm) + idx1 * 16;
                    a.movdqu(xmm0, xmmword_ptr(r15, off1));  // Load from ctx
                    a.movdqu(xmmword_ptr(r14, r8, 0), xmm0); // Store to guest mem
                }
                else
                    return nullptr;
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_MOVD:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                uint32_t reg0 = operands[0].reg.value;

                if (reg0 >= ZYDIS_REGISTER_XMM0 && reg0 <= ZYDIS_REGISTER_XMM7)
                {
                    int xmmIdx = reg0 - ZYDIS_REGISTER_XMM0;
                    int xmmOff = offsetof(CpuContext, xmm) + xmmIdx * 16;

                    if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                    {
                        uint32_t reg1 = operands[1].reg.value;
                        if (reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7)
                        {
                            return nullptr;
                        }

                        int srcOff = getRegOffset((ZydisRegister)reg1);
                        if (srcOff != -1)
                        {
                            a.mov(r8d, dword_ptr(r15, srcOff));
                            a.movd(xmm0, r8d);
                            a.pxor(xmm1, xmm1);
                            a.punpckldq(xmm0, xmm1);
                            a.punpcklqdq(xmm0, xmm1);
                            a.movdqu(xmmword_ptr(r15, xmmOff), xmm0);
                        }
                        else if (reg1 >= ZYDIS_REGISTER_MM0 && reg1 <= ZYDIS_REGISTER_MM7)
                        {
                            int mmIdx = reg1 - ZYDIS_REGISTER_MM0;
                            int mmOff = offsetof(CpuContext, mmx) + mmIdx * 8;
                            a.movd(mm0, dword_ptr(r15, mmOff));
                            a.movd(r8d, mm0);
                            a.movd(xmm0, r8d);
                            a.pxor(xmm1, xmm1);
                            a.punpckldq(xmm0, xmm1);
                            a.punpcklqdq(xmm0, xmm1);
                            a.movdqu(xmmword_ptr(r15, xmmOff), xmm0);
                        }
                        else
                        {
                            return nullptr;
                        }
                    }
                    else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && resolveMemoryIntoR8(operands[1].mem))
                    {
                        a.mov(r8d, dword_ptr(r14, r8, 0));
                        a.movd(xmm0, r8d);
                        a.pxor(xmm1, xmm1);
                        a.punpckldq(xmm0, xmm1);
                        a.punpcklqdq(xmm0, xmm1);
                        a.movdqu(xmmword_ptr(r15, xmmOff), xmm0);
                    }
                    else
                    {
                        goto unimplemented;
                    }
                }
                else if (reg0 >= ZYDIS_REGISTER_MM0 && reg0 <= ZYDIS_REGISTER_MM7)
                {
                    int mmIdx = reg0 - ZYDIS_REGISTER_MM0;
                    int mmOff = offsetof(CpuContext, mmx) + mmIdx * 8;

                    if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                    {
                        uint32_t reg1 = operands[1].reg.value;
                        int srcOff = getRegOffset((ZydisRegister)reg1);
                        if (srcOff != -1)
                        {
                            a.mov(r8d, dword_ptr(r15, srcOff));
                            a.movd(mm0, r8d);
                            a.movq(qword_ptr(r15, mmOff), mm0);
                        }
                        else if (reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7)
                        {
                            int xmmIdx = reg1 - ZYDIS_REGISTER_XMM0;
                            int xmmOff = offsetof(CpuContext, xmm) + xmmIdx * 16;
                            a.movdqu(xmm0, xmmword_ptr(r15, xmmOff));
                            a.movd(r8d, xmm0);
                            a.movd(mm0, r8d);
                            a.movq(qword_ptr(r15, mmOff), mm0);
                        }
                        else
                        {
                            return nullptr;
                        }
                    }
                    else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && resolveMemoryIntoR8(operands[1].mem))
                    {
                        a.movd(mm0, dword_ptr(r14, r8, 0));
                        a.movq(qword_ptr(r15, mmOff), mm0);
                    }
                    else
                    {
                        goto unimplemented;
                    }
                }
                else
                {
                    int dstOff = getRegOffset((ZydisRegister)reg0);
                    if (dstOff != -1)
                    {
                        if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                        {
                            uint32_t reg1 = operands[1].reg.value;
                            if (reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7)
                            {
                                int xmmIdx = reg1 - ZYDIS_REGISTER_XMM0;
                                int xmmOff = offsetof(CpuContext, xmm) + xmmIdx * 16;
                                a.movdqu(xmm0, xmmword_ptr(r15, xmmOff));
                                a.movd(r8d, xmm0);
                                a.mov(dword_ptr(r15, dstOff), r8d);
                            }
                            else if (reg1 >= ZYDIS_REGISTER_MM0 && reg1 <= ZYDIS_REGISTER_MM7)
                            {
                                int mmIdx = reg1 - ZYDIS_REGISTER_MM0;
                                int mmOff = offsetof(CpuContext, mmx) + mmIdx * 8;
                                a.movq(mm0, qword_ptr(r15, mmOff));
                                a.movd(r8d, mm0);
                                a.mov(dword_ptr(r15, dstOff), r8d);
                            }
                            else
                            {
                                goto unimplemented;
                            }
                        }
                        else
                        {
                            goto unimplemented;
                        }
                    }
                    else
                    {
                        goto unimplemented;
                    }
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && resolveMemoryIntoR8(operands[0].mem))
            {
                if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    uint32_t reg1 = operands[1].reg.value;
                    if (reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7)
                    {
                        int xmmIdx = reg1 - ZYDIS_REGISTER_XMM0;
                        int xmmOff = offsetof(CpuContext, xmm) + xmmIdx * 16;
                        a.movdqu(xmm0, xmmword_ptr(r15, xmmOff));
                        a.movd(r9d, xmm0);
                        a.mov(dword_ptr(r14, r8, 0), r9d);
                    }
                    else if (reg1 >= ZYDIS_REGISTER_MM0 && reg1 <= ZYDIS_REGISTER_MM7)
                    {
                        int mmIdx = reg1 - ZYDIS_REGISTER_MM0;
                        int mmOff = offsetof(CpuContext, mmx) + mmIdx * 8;
                        a.movq(mm0, qword_ptr(r15, mmOff));
                        a.movd(r9d, mm0);
                        a.mov(dword_ptr(r14, r8, 0), r9d);
                    }
                    else
                    {
                        goto unimplemented;
                    }
                }
                else
                {
                    goto unimplemented;
                }
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_MOVQ:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                uint32_t reg0 = operands[0].reg.value;

                if (reg0 >= ZYDIS_REGISTER_XMM0 && reg0 <= ZYDIS_REGISTER_XMM7)
                {
                    int dstIdx = reg0 - ZYDIS_REGISTER_XMM0;
                    int dstOff = offsetof(CpuContext, xmm) + dstIdx * 16;

                    if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                    {
                        uint32_t reg1 = operands[1].reg.value;
                        if (reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7)
                        {
                            int srcIdx = reg1 - ZYDIS_REGISTER_XMM0;
                            int srcOff = offsetof(CpuContext, xmm) + srcIdx * 16;
                            a.movq(xmm0, qword_ptr(r15, srcOff));
                            a.movq(qword_ptr(r15, dstOff), xmm0);
                            a.mov(qword_ptr(r15, dstOff + 8), 0);
                        }
                        else if (reg1 >= ZYDIS_REGISTER_MM0 && reg1 <= ZYDIS_REGISTER_MM7)
                        {
                            int mmIdx = reg1 - ZYDIS_REGISTER_MM0;
                            int mmOff = offsetof(CpuContext, mmx) + mmIdx * 8;
                            a.movq(xmm0, qword_ptr(r15, mmOff));
                            a.movq(qword_ptr(r15, dstOff), xmm0);
                            a.mov(qword_ptr(r15, dstOff + 8), 0);
                        }
                        else
                        {
                            goto unimplemented;
                        }
                    }
                    else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && resolveMemoryIntoR8(operands[1].mem))
                    {
                        a.movq(xmm0, qword_ptr(r14, r8, 0));
                        a.movq(qword_ptr(r15, dstOff), xmm0);
                        a.mov(qword_ptr(r15, dstOff + 8), 0);
                    }
                    else
                    {
                        goto unimplemented;
                    }
                }
                else if (reg0 >= ZYDIS_REGISTER_MM0 && reg0 <= ZYDIS_REGISTER_MM7)
                {
                    int dstIdx = reg0 - ZYDIS_REGISTER_MM0;
                    int dstOff = offsetof(CpuContext, mmx) + dstIdx * 8;

                    if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                    {
                        uint32_t reg1 = operands[1].reg.value;
                        if (reg1 >= ZYDIS_REGISTER_MM0 && reg1 <= ZYDIS_REGISTER_MM7)
                        {
                            int srcIdx = reg1 - ZYDIS_REGISTER_MM0;
                            int srcOff = offsetof(CpuContext, mmx) + srcIdx * 8;
                            a.movq(mm0, qword_ptr(r15, srcOff));
                            a.movq(qword_ptr(r15, dstOff), mm0);
                        }
                        else if (reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7)
                        {
                            int srcIdx = reg1 - ZYDIS_REGISTER_XMM0;
                            int srcOff = offsetof(CpuContext, xmm) + srcIdx * 16;
                            a.movq(xmm0, qword_ptr(r15, srcOff));
                            a.movq(qword_ptr(r15, dstOff), xmm0);
                        }
                        else
                        {
                            goto unimplemented;
                        }
                    }
                    else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && resolveMemoryIntoR8(operands[1].mem))
                    {
                        a.movq(mm0, qword_ptr(r14, r8, 0));
                        a.movq(qword_ptr(r15, dstOff), mm0);
                    }
                    else
                    {
                        goto unimplemented;
                    }
                }
                else
                {
                    goto unimplemented;
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && resolveMemoryIntoR8(operands[0].mem))
            {
                if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    uint32_t reg1 = operands[1].reg.value;
                    if (reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7)
                    {
                        int srcIdx = reg1 - ZYDIS_REGISTER_XMM0;
                        int srcOff = offsetof(CpuContext, xmm) + srcIdx * 16;
                        a.movq(xmm0, qword_ptr(r15, srcOff));
                        a.movq(qword_ptr(r14, r8, 0), xmm0);
                    }
                    else if (reg1 >= ZYDIS_REGISTER_MM0 && reg1 <= ZYDIS_REGISTER_MM7)
                    {
                        int srcIdx = reg1 - ZYDIS_REGISTER_MM0;
                        int srcOff = offsetof(CpuContext, mmx) + srcIdx * 8;
                        a.movq(mm0, qword_ptr(r15, srcOff));
                        a.movq(qword_ptr(r14, r8, 0), mm0);
                    }
                    else
                    {
                        goto unimplemented;
                    }
                }
                else
                {
                    goto unimplemented;
                }
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_PSHUFD:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t reg0 = operands[0].reg.value;
                uint8_t imm = (uint8_t)operands[2].imm.value.u;

                if (reg0 >= ZYDIS_REGISTER_XMM0 && reg0 <= ZYDIS_REGISTER_XMM7)
                {
                    int dstIdx = reg0 - ZYDIS_REGISTER_XMM0;
                    int dstOff = offsetof(CpuContext, xmm) + dstIdx * 16;

                    if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                    {
                        uint32_t reg1 = operands[1].reg.value;
                        if (reg1 >= ZYDIS_REGISTER_XMM0 && reg1 <= ZYDIS_REGISTER_XMM7)
                        {
                            int srcIdx = reg1 - ZYDIS_REGISTER_XMM0;
                            int srcOff = offsetof(CpuContext, xmm) + srcIdx * 16;
                            a.movdqu(xmm0, xmmword_ptr(r15, srcOff));
                            a.pshufd(xmm0, xmm0, imm);
                            a.movdqu(xmmword_ptr(r15, dstOff), xmm0);
                        }
                        else
                        {
                            goto unimplemented;
                        }
                    }
                    else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && resolveMemoryIntoR8(operands[1].mem))
                    {
                        a.movdqu(xmm0, xmmword_ptr(r14, r8, 0));
                        a.pshufd(xmm0, xmm0, imm);
                        a.movdqu(xmmword_ptr(r15, dstOff), xmm0);
                    }
                    else
                    {
                        goto unimplemented;
                    }
                }
                else
                {
                    goto unimplemented;
                }
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_BSF:
            // BSF dest, src: bit scan forward (find LSB index)
            // If src == 0: ZF=1, dest unchanged
            // If src != 0: ZF=0, dest = bit index of least significant set bit
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int dstOff = getRegOffset(operands[0].reg.value);
                if (dstOff == -1) goto unimplemented;

                if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    int srcOff = getRegOffset(operands[1].reg.value);
                    if (srcOff == -1) goto unimplemented;

                    a.mov(r8d, dword_ptr(r15, srcOff));
                }
                else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    if (!resolveMemoryIntoR8(operands[1].mem)) return nullptr;
                    a.mov(r8d, dword_ptr(r14, r8, 0));
                }
                else
                    goto unimplemented;

                Label bsfDone = a.newLabel();
                Label bsfNonzero = a.newLabel();

                a.test(r8d, r8d);
                a.jnz(bsfNonzero);

                // src == 0: ZF = 1, leave dest unchanged
                a.or_(byte_ptr(r15, offsetof(CpuContext, eflags)), 0x40);
                a.jmp(bsfDone);

                a.bind(bsfNonzero);
                // src != 0: ZF = 0, dest = bit index
                a.bsf(r8d, r8d);
                a.mov(dword_ptr(r15, dstOff), r8d);
                a.and_(byte_ptr(r15, offsetof(CpuContext, eflags)), 0xBF);

                a.bind(bsfDone);
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_BSR:
            // BSR dest, src: bit scan reverse (find MSB index)
            // If src == 0: ZF=1, dest unchanged
            // If src != 0: ZF=0, dest = bit index of most significant set bit
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int dstOff = getRegOffset(operands[0].reg.value);
                if (dstOff == -1) goto unimplemented;

                if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    int srcOff = getRegOffset(operands[1].reg.value);
                    if (srcOff == -1) goto unimplemented;

                    a.mov(r8d, dword_ptr(r15, srcOff));
                }
                else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    if (!resolveMemoryIntoR8(operands[1].mem)) return nullptr;
                    a.mov(r8d, dword_ptr(r14, r8, 0));
                }
                else
                    goto unimplemented;

                Label bsrDone = a.newLabel();
                Label bsrNonzero = a.newLabel();

                a.test(r8d, r8d);
                a.jnz(bsrNonzero);

                // src == 0: ZF = 1, leave dest unchanged
                a.or_(byte_ptr(r15, offsetof(CpuContext, eflags)), 0x40);
                a.jmp(bsrDone);

                a.bind(bsrNonzero);
                // src != 0: ZF = 0, dest = bit index
                a.bsr(r8d, r8d);
                a.mov(dword_ptr(r15, dstOff), r8d);
                a.and_(byte_ptr(r15, offsetof(CpuContext, eflags)), 0xBF);

                a.bind(bsrDone);
            }
            else
                goto unimplemented;
            break;

        case ZYDIS_MNEMONIC_BSWAP:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1 && operands[0].size == 32)
                {
                    a.mov(r8d, dword_ptr(r15, off));
                    a.bswap(r8d);
                    a.mov(dword_ptr(r15, off), r8d);
                }
                else
                {
                    return nullptr;
                }
            }
            else
            {
                goto unimplemented;
            }
            break;

        case ZYDIS_MNEMONIC_EMMS:
            a.emms();
            break;

        case ZYDIS_MNEMONIC_JMP:
            // Handle FAR jump (inter-segment) for NE and MZ modes
            if (instr.meta.branch_type == ZYDIS_BRANCH_TYPE_FAR && (isNE || isMZ))
            {
                uint16_t targetSel = 0, targetOff = 0;
                if (operands[0].type == ZYDIS_OPERAND_TYPE_POINTER)
                {
                    targetSel = operands[0].ptr.segment;
                    targetOff = (uint16_t)operands[0].ptr.offset;
                }
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    // Memory-indirect far jump: jmp far [segment:base+disp]
                    // Read 4-byte far pointer (IP, CS) from guest memory.
                    // Use resolveMemoryIntoR8 to compute the linear address
                    // (handles MZ real-mode seg*16 and NE GDT bases correctly).
                    if (!resolveMemoryIntoR8(operands[0].mem))
                        return nullptr;
                    a.sub(rsp, 40);
                    a.mov(rcx, (uint64_t)this);
                    a.mov(edx, r8d);  // linear address from resolveMemoryIntoR8
                    a.mov(rax, (uint64_t)JitFarJumpMemIndirectLinear);
                    EmitHostAbiArgs(a);
                    a.call(rax);
                    a.add(rsp, 40);
                    blockEnded = true;
                    break;
                }
                else
                {
                    return nullptr; // Unsupported far jump operand type
                }

                // Update CS and resolve target EIP via runtime helper
                a.mov(word_ptr(r15, offsetof(CpuContext, cs)), targetSel);
                a.sub(rsp, 40); // 16-align + 32 shadow
                a.mov(rcx, (uint64_t)this);
                a.mov(edx, targetSel);
                a.mov(r8d, targetOff);
                a.mov(rax, (uint64_t)JitGetLinearAddress);
                EmitHostAbiArgs(a);
                a.call(rax);
                a.add(rsp, 40);
                a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), eax);
                blockEnded = true;
                break;
            }
            if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t target = 0;
                if (operands[0].imm.is_relative)
                {
                    if (isMZ) {
                        uint32_t csBase = (uint32_t)context.cs << 4;
                        uint32_t targetOffset = (currentEip - csBase) + instr.length + (int32_t)operands[0].imm.value.s;
                        target = csBase + (uint16_t)targetOffset;
                    } else {
                        target = currentEip + instr.length + (int32_t)operands[0].imm.value.s;
                    }
                }
                else
                {
                    target = (uint32_t)operands[0].imm.value.u;
                    if (isMZ) {
                        target = ((uint32_t)context.cs << 4) + (uint16_t)target;
                    }
                }
                auto localTarget = localBlockLabels.find(target);
                if (localTarget != localBlockLabels.end() && target < currentEip) {
                    emitLocalBackEdge(target, localTarget->second);
                } else {
                    emitBlockEnd(target);
                }
                blockEnded = true;
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                int off = getRegOffset(operands[0].reg.value);
                if (off != -1)
                {
                    if (isNE || isMZ)
                    {
                        a.movzx(r9d, word_ptr(r15, off));
                        a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, csBase)));
                        a.add(r9d, r11d);
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r15, off));
                    }
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), r9d);
                    blockEnded = true;
                }
            }
            else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (resolveMemoryIntoR8(operands[0].mem))
                {
                    if (isNE || isMZ)
                    {
                        a.movzx(r9d, word_ptr(r14, r8, 0));
                        a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, csBase)));
                        a.add(r9d, r11d);
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r14, r8, 0));
                    }
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), r9d);
                    blockEnded = true;
                }
            }
            break;

        case ZYDIS_MNEMONIC_JZ:
        case ZYDIS_MNEMONIC_JNZ:
        case ZYDIS_MNEMONIC_JB:
        case ZYDIS_MNEMONIC_JBE:
        case ZYDIS_MNEMONIC_JNB:
        case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JL:
        case ZYDIS_MNEMONIC_JLE:
        case ZYDIS_MNEMONIC_JNL:
        case ZYDIS_MNEMONIC_JNLE:
        case ZYDIS_MNEMONIC_JO:
        case ZYDIS_MNEMONIC_JNO:
        case ZYDIS_MNEMONIC_JS:
        case ZYDIS_MNEMONIC_JNS:
        case ZYDIS_MNEMONIC_JP:
        case ZYDIS_MNEMONIC_JNP:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t target = 0;
                uint32_t fallthrough = 0;
                if (isMZ) {
                    uint32_t csBase = (uint32_t)context.cs << 4;
                    uint32_t targetOffset = (currentEip - csBase) + instr.length + (int32_t)operands[0].imm.value.s;
                    uint32_t fallthroughOffset = (currentEip - csBase) + instr.length;
                    target = csBase + (uint16_t)targetOffset;
                    fallthrough = csBase + (uint16_t)fallthroughOffset;
                } else {
                    target = currentEip + instr.length + (int32_t)operands[0].imm.value.s;
                    fallthrough = currentEip + instr.length;
                }
                const auto localTarget = localBlockLabels.find(target);
                const bool useLocalBackEdge =
                    localTarget != localBlockLabels.end() && target < currentEip;

                Label takenLabel = a.newLabel();
                // Emit conditional branch to taken path
                switch (instr.mnemonic)
                {
                case ZYDIS_MNEMONIC_JZ:
                    a.jz(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JNZ:
                    a.jnz(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JB:
                    a.jb(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JBE:
                    a.jbe(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JNB:
                    a.jnb(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JNBE:
                    a.jnbe(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JL:
                    a.jl(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JLE:
                    a.jle(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JNL:
                    a.jnl(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JNLE:
                    a.jnle(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JO:
                    a.jo(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JNO:
                    a.jno(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JS:
                    a.js(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JNS:
                    a.jns(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JP:
                    a.jp(takenLabel);
                    break;
                case ZYDIS_MNEMONIC_JNP:
                    a.jnp(takenLabel);
                    break;
                default:
                    break;
                }

                // Fallthrough path (condition not taken)
                emitBlockEnd(fallthrough);

                // Taken path (condition met)
                a.bind(takenLabel);
                if (useLocalBackEdge) {
                    emitLocalBackEdge(target, localTarget->second);
                } else {
                    emitBlockEnd(target);
                }

                blockEnded = true;
            }
            break;
        case ZYDIS_MNEMONIC_JCXZ:
        case ZYDIS_MNEMONIC_JECXZ:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t target = 0;
                uint32_t fallthrough = 0;
                if (isMZ) {
                    uint32_t csBase = (uint32_t)context.cs << 4;
                    uint32_t targetOffset = (currentEip - csBase) + instr.length + (int32_t)operands[0].imm.value.s;
                    uint32_t fallthroughOffset = (currentEip - csBase) + instr.length;
                    target = csBase + (uint16_t)targetOffset;
                    fallthrough = csBase + (uint16_t)fallthroughOffset;
                } else {
                    target = currentEip + instr.length + (int32_t)operands[0].imm.value.s;
                    fallthrough = currentEip + instr.length;
                }

                Label takenLabel = a.newLabel();
                if (instr.mnemonic == ZYDIS_MNEMONIC_JCXZ)
                {
                    // 16-bit CX
                    a.movzx(r10d, word_ptr(r15, offsetof(CpuContext, ecx)));
                }
                else
                {
                    // 32-bit ECX
                    a.mov(r10d, dword_ptr(r15, offsetof(CpuContext, ecx)));
                }
                a.test(r10d, r10d);
                a.jz(takenLabel);

                a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eflags)));
                a.push(r8);
                a.popfq();
                emitBlockEnd(fallthrough);

                a.bind(takenLabel);
                a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eflags)));
                a.push(r8);
                a.popfq();
                emitBlockEnd(target);

                blockEnded = true;
            }
            break;
        case ZYDIS_MNEMONIC_LOOPE:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t target = currentEip + instr.length + (int32_t)operands[0].imm.value.s;
                uint32_t fallthrough = currentEip + instr.length;

                // Save original ZF (bit 6) before dec clobbers it
                a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, eflags)));
                a.shr(r9d, 6);
                a.and_(r9d, 1);  // r9d = original ZF (0 or 1)

                a.mov(ecx, dword_ptr(r15, offsetof(CpuContext, ecx)));
                if (isNE || isMZ)
                {
                    a.dec(cx);
                    a.mov(word_ptr(r15, offsetof(CpuContext, ecx)), cx);
                }
                else
                {
                    a.dec(ecx);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, ecx)), ecx);
                }

                // LOOPE: jump if ECX != 0 AND original ZF == 1
                a.setnz(r8b);    // r8b = 1 if ECX != 0
                a.and_(r8b, r9b); // r8b = 1 if (ECX != 0) && (orig ZF == 1)
                a.test(r8b, r8b);

                a.mov(r10d, target);
                a.mov(r11d, fallthrough);
                a.cmovz(r10d, r11d); // if condition false, take fallthrough
                a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), r10d);

                blockEnded = true;
            }
            break;

        case ZYDIS_MNEMONIC_LOOPNE:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t target = currentEip + instr.length + (int32_t)operands[0].imm.value.s;
                uint32_t fallthrough = currentEip + instr.length;

                // Save original ZF (bit 6) before dec clobbers it
                a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, eflags)));
                a.shr(r9d, 6);
                a.and_(r9d, 1);  // r9d = original ZF (0 or 1)

                a.mov(ecx, dword_ptr(r15, offsetof(CpuContext, ecx)));
                if (isNE || isMZ)
                {
                    a.dec(cx);
                    a.mov(word_ptr(r15, offsetof(CpuContext, ecx)), cx);
                }
                else
                {
                    a.dec(ecx);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, ecx)), ecx);
                }

                // LOOPNE: jump if ECX != 0 AND original ZF == 0
                a.setnz(r8b);    // r8b = 1 if ECX != 0
                a.xor_(r9b, 1);  // r9b = 1 if orig ZF == 0
                a.and_(r8b, r9b); // r8b = 1 if (ECX != 0) && (orig ZF == 0)
                a.test(r8b, r8b);

                a.mov(r10d, target);
                a.mov(r11d, fallthrough);
                a.cmovz(r10d, r11d); // if condition false, take fallthrough
                a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), r10d);

                blockEnded = true;
            }
            break;

        case ZYDIS_MNEMONIC_LOOP:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                uint32_t target = currentEip + instr.length + (int32_t)operands[0].imm.value.s;
                uint32_t fallthrough = currentEip + instr.length;

                // Load the loop counter from the CpuContext
                a.mov(ecx, dword_ptr(r15, offsetof(CpuContext, ecx)));

                if (isNE || isMZ)
                {
                    a.dec(cx); // Decrement CX (automatically sets host ZF)
                    a.mov(word_ptr(r15, offsetof(CpuContext, ecx)), cx);
                }
                else
                {
                    a.dec(ecx); // Decrement ECX (automatically sets host ZF)
                    a.mov(dword_ptr(r15, offsetof(CpuContext, ecx)), ecx);
                }

                // Load both branch targets into scratch registers
                a.mov(r10d, target);
                a.mov(r11d, fallthrough);

                // Branchless selection: If ZF is set (count reached 0), select fallthrough
                a.cmovz(r10d, r11d);

                // Write the resolved EIP back to CpuContext
                a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), r10d);

                blockEnded = true;
            }
            break;

        case ZYDIS_MNEMONIC_PUSHA:
        {
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));
            if (isNE || isMZ) a.movzx(r8d, r8w);
            a.mov(r9d, r8d); // Original SP (16-bit)

            // PUSH AX, CX, DX, BX, original SP, BP, SI, DI — each 2 bytes
            static const int regs[] = {offsetof(CpuContext, eax), offsetof(CpuContext, ecx),
                                       offsetof(CpuContext, edx), offsetof(CpuContext, ebx)};
            for (int i = 0; i < 4; i++)
            {
                a.lea(r8d, dword_ptr(r8d, -2));
                if (isNE || isMZ) a.movzx(r8d, r8w);
                if (isNE || isMZ) {
                    a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                    a.lea(r10, dword_ptr(r14, r8));
                    a.add(r10, r11);
                } else {
                    a.lea(r10, dword_ptr(r14, r8));
                }
                a.mov(r11w, word_ptr(r15, regs[i]));
                a.mov(word_ptr(r10, 0), r11w);
            }
            // original SP
            a.lea(r8d, dword_ptr(r8d, -2));
            if (isNE || isMZ) a.movzx(r8d, r8w);
            if (isNE || isMZ) {
                a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                a.lea(r10, dword_ptr(r14, r8));
                a.add(r10, r11);
            } else {
                a.lea(r10, dword_ptr(r14, r8));
            }
            a.mov(word_ptr(r10, 0), r9w);

            static const int regs2[] = {offsetof(CpuContext, ebp), offsetof(CpuContext, esi),
                                        offsetof(CpuContext, edi)};
            for (int i = 0; i < 3; i++)
            {
                a.lea(r8d, dword_ptr(r8d, -2));
                if (isNE || isMZ) a.movzx(r8d, r8w);
                if (isNE || isMZ) {
                    a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                    a.lea(r10, dword_ptr(r14, r8));
                    a.add(r10, r11);
                } else {
                    a.lea(r10, dword_ptr(r14, r8));
                }
                a.mov(r11w, word_ptr(r15, regs2[i]));
                a.mov(word_ptr(r10, 0), r11w);
            }
            a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
        }
        break;

        case ZYDIS_MNEMONIC_PUSHAD:
        {
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));
            a.mov(r9d, r8d); // Original ESP

            // PUSH EAX, ECX, EDX, EBX, original ESP, EBP, ESI, EDI
            static const int regs[] = {offsetof(CpuContext, eax), offsetof(CpuContext, ecx), offsetof(CpuContext, edx), offsetof(CpuContext, ebx)};
            for (int i = 0; i < 4; i++)
            {
                a.lea(r8d, dword_ptr(r8d, -4));
                a.mov(r10d, dword_ptr(r15, regs[i]));
                a.mov(dword_ptr(r14, r8, 0), r10d);
            }
            // original ESP
            a.lea(r8d, dword_ptr(r8d, -4));
            a.mov(dword_ptr(r14, r8, 0), r9d);

            static const int regs2[] = {offsetof(CpuContext, ebp), offsetof(CpuContext, esi), offsetof(CpuContext, edi)};
            for (int i = 0; i < 3; i++)
            {
                a.lea(r8d, dword_ptr(r8d, -4));
                a.mov(r10d, dword_ptr(r15, regs2[i]));
                a.mov(dword_ptr(r14, r8, 0), r10d);
            }
            a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
        }
        break;

        case ZYDIS_MNEMONIC_POPAD:
        {
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, esp)));

            // POP EDI, ESI, EBP, (skip ESP), EBX, EDX, ECX, EAX
            static const int regs[] = {offsetof(CpuContext, edi), offsetof(CpuContext, esi), offsetof(CpuContext, ebp)};
            for (int i = 0; i < 3; i++)
            {
                a.mov(r9d, dword_ptr(r14, r8, 0));
                a.mov(dword_ptr(r15, regs[i]), r9d);
                a.lea(r8d, dword_ptr(r8d, 4));
            }
            // Skip ESP
            a.lea(r8d, dword_ptr(r8d, 4));

            static const int regs2[] = {offsetof(CpuContext, ebx), offsetof(CpuContext, edx), offsetof(CpuContext, ecx), offsetof(CpuContext, eax)};
            for (int i = 0; i < 4; i++)
            {
                a.mov(r9d, dword_ptr(r14, r8, 0));
                a.mov(dword_ptr(r15, regs2[i]), r9d);
                a.lea(r8d, dword_ptr(r8d, 4));
            }
            a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r8d);
        }
        break;

        case ZYDIS_MNEMONIC_SETZ:
        case ZYDIS_MNEMONIC_SETNZ:
        case ZYDIS_MNEMONIC_SETB:
        case ZYDIS_MNEMONIC_SETBE:
        case ZYDIS_MNEMONIC_SETNB:
        case ZYDIS_MNEMONIC_SETNBE:
        case ZYDIS_MNEMONIC_SETL:
        case ZYDIS_MNEMONIC_SETLE:
        case ZYDIS_MNEMONIC_SETNL:
        case ZYDIS_MNEMONIC_SETNLE:
        case ZYDIS_MNEMONIC_SETO:
        case ZYDIS_MNEMONIC_SETNO:
        case ZYDIS_MNEMONIC_SETS:
        case ZYDIS_MNEMONIC_SETNS:
        case ZYDIS_MNEMONIC_SETP:
        case ZYDIS_MNEMONIC_SETNP:
            if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER || operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eflags)));
                a.push(r8);
                a.popfq();
                switch (instr.mnemonic)
                {
                case ZYDIS_MNEMONIC_SETZ:
                    a.setz(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETNZ:
                    a.setnz(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETB:
                    a.setb(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETBE:
                    a.setbe(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETNB:
                    a.setae(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETNBE:
                    a.seta(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETL:
                    a.setl(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETLE:
                    a.setle(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETNL:
                    a.setge(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETNLE:
                    a.setg(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETO:
                    a.seto(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETNO:
                    a.setno(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETS:
                    a.sets(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETNS:
                    a.setns(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETP:
                    a.setp(r8b);
                    break;
                case ZYDIS_MNEMONIC_SETNP:
                    a.setnp(r8b);
                    break;
                default:
                    break;
                }
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    int off = getRegOffset(operands[0].reg.value);
                    if (off != -1)
                        a.mov(byte_ptr(r15, off), r8b);
                }
                else
                {
                    a.mov(r11b, r8b); // Save result to r11b
                    if (resolveMemoryIntoR8(operands[0].mem))
                    {
                        a.mov(byte_ptr(r14, r8, 0), r11b);
                    }
                }
            }
            break;

        case ZYDIS_MNEMONIC_CMOVZ:
        case ZYDIS_MNEMONIC_CMOVNZ:
        case ZYDIS_MNEMONIC_CMOVB:
        case ZYDIS_MNEMONIC_CMOVBE:
        case ZYDIS_MNEMONIC_CMOVNB:
        case ZYDIS_MNEMONIC_CMOVNBE:
        case ZYDIS_MNEMONIC_CMOVL:
        case ZYDIS_MNEMONIC_CMOVLE:
        case ZYDIS_MNEMONIC_CMOVNL:
        case ZYDIS_MNEMONIC_CMOVNLE:
        case ZYDIS_MNEMONIC_CMOVO:
        case ZYDIS_MNEMONIC_CMOVNO:
        case ZYDIS_MNEMONIC_CMOVS:
        case ZYDIS_MNEMONIC_CMOVNS:
        case ZYDIS_MNEMONIC_CMOVP:
        case ZYDIS_MNEMONIC_CMOVNP:
        {
            // Restore flags
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eflags)));
            a.push(r8);
            a.popfq();

            int dstOff = getRegOffset(operands[0].reg.value);
            if (dstOff != -1)
            {
                // Load Dest
                if (operands[0].size == 16)
                    a.mov(r10w, word_ptr(r15, dstOff));
                else
                    a.mov(r10d, dword_ptr(r15, dstOff));

                // Load Src into r11
                if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    int srcOff = getRegOffset(operands[1].reg.value);
                    if (srcOff != -1)
                    {
                        if (operands[0].size == 16)
                            a.mov(r11w, word_ptr(r15, srcOff));
                        else
                            a.mov(r11d, dword_ptr(r15, srcOff));
                    }
                    else
                        goto unimplemented;
                }
                else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    if (resolveMemoryIntoR8(operands[1].mem))
                    {
                        if (operands[0].size == 16)
                            a.mov(r11w, word_ptr(r14, r8, 0));
                        else
                            a.mov(r11d, dword_ptr(r14, r8, 0));
                    }
                    else
                        return nullptr;
                }
                else
                    goto unimplemented;

                // Perform CMOV
                // Note: r10 is DestReg, r11 is SrcVal
                if (operands[0].size == 16)
                {
                    switch (instr.mnemonic)
                    {
                    case ZYDIS_MNEMONIC_CMOVZ:
                        a.cmovz(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNZ:
                        a.cmovnz(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVB:
                        a.cmovb(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVBE:
                        a.cmovbe(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNB:
                        a.cmovae(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNBE:
                        a.cmova(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVL:
                        a.cmovl(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVLE:
                        a.cmovle(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNL:
                        a.cmovge(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNLE:
                        a.cmovg(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVO:
                        a.cmovo(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNO:
                        a.cmovno(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVS:
                        a.cmovs(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNS:
                        a.cmovns(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVP:
                        a.cmovp(r10w, r11w);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNP:
                        a.cmovnp(r10w, r11w);
                        break;
                    default:
                        break;
                    }
                    a.mov(word_ptr(r15, dstOff), r10w);
                }
                else
                {
                    // 32-bit
                    switch (instr.mnemonic)
                    {
                    case ZYDIS_MNEMONIC_CMOVZ:
                        a.cmovz(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNZ:
                        a.cmovnz(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVB:
                        a.cmovb(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVBE:
                        a.cmovbe(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNB:
                        a.cmovae(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNBE:
                        a.cmova(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVL:
                        a.cmovl(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVLE:
                        a.cmovle(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNL:
                        a.cmovge(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNLE:
                        a.cmovg(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVO:
                        a.cmovo(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNO:
                        a.cmovno(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVS:
                        a.cmovs(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNS:
                        a.cmovns(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVP:
                        a.cmovp(r10d, r11d);
                        break;
                    case ZYDIS_MNEMONIC_CMOVNP:
                        a.cmovnp(r10d, r11d);
                        break;
                    default:
                        break;
                    }
                    a.mov(dword_ptr(r15, dstOff), r10d);
                }
            }
            else
                goto unimplemented;
        }
        break;
        case ZYDIS_MNEMONIC_AAM:
        {
            uint8_t divisor = 10;
            if (instr.operand_count >= 1 && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                divisor = (uint8_t)operands[0].imm.value.u;
            }
            a.movzx(ax, byte_ptr(r15, offsetof(CpuContext, eax))); // AX = AL
            a.mov(cl, divisor);
            a.div(cl);      // AL = AX / CL (quotient), AH = AX % CL (remainder)
            a.xchg(al, ah); // AH = quotient, AL = remainder
            a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);

            // Set flags based on AL
            a.test(al, al);
            a.pushfq();
            a.pop(r8);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
        }
        break;

        case ZYDIS_MNEMONIC_AAD:
        {
            uint8_t divisor = 10;
            if (instr.operand_count >= 1 && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                divisor = (uint8_t)operands[0].imm.value.u;
            }
            a.movzx(ax, byte_ptr(r15, offsetof(CpuContext, eax) + 1)); // AX = AH
            a.mov(cl, divisor);
            a.imul(ax, cx);                                        // AX = AH * divisor
            a.movzx(cx, byte_ptr(r15, offsetof(CpuContext, eax))); // CX = AL
            a.add(ax, cx);                                         // AX = (AH * divisor) + AL
            a.mov(ah, 0);                                          // AH = 0
            a.mov(word_ptr(r15, offsetof(CpuContext, eax)), ax);

            // Set flags based on AL
            a.test(al, al);
            a.pushfq();
            a.pop(r8);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
        }
        break;

        case ZYDIS_MNEMONIC_AAA:
        {
            a.mov(ecx, dword_ptr(r15, offsetof(CpuContext, eax)));
            a.mov(edx, dword_ptr(r15, offsetof(CpuContext, eflags)));
            a.sub(rsp, 40);
            a.mov(rax, (uint64_t)JitAaa);
            EmitHostAbiArgs(a);
            a.call(rax);
            a.add(rsp, 40);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);
            a.mov(r8, rax);
            a.shr(r8, 32);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
        }
        break;

        case ZYDIS_MNEMONIC_DAS:
        {
            a.mov(ecx, dword_ptr(r15, offsetof(CpuContext, eax)));
            a.mov(edx, dword_ptr(r15, offsetof(CpuContext, eflags)));
            a.sub(rsp, 40);
            a.mov(rax, (uint64_t)JitDas);
            EmitHostAbiArgs(a);
            a.call(rax);
            a.add(rsp, 40);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eax)), eax);
            a.mov(r8, rax);
            a.shr(r8, 32);
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
        }
        break;

        case ZYDIS_MNEMONIC_PUSHF:
        case ZYDIS_MNEMONIC_PUSHFD:
        {
            // CpuContext's IF is the guest's own (CLI/STI/POPF/IRET maintain it and
            // flag publishes keep it), so push it as is: a pushfd/cli/popfd section
            // must come back with interrupts enabled.
            a.mov(r8d, dword_ptr(r15, offsetof(CpuContext, eflags)));
            a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, esp)));
            if (isNE || isMZ || instr.mnemonic == ZYDIS_MNEMONIC_PUSHF)
            {
                a.lea(r9d, dword_ptr(r9d, -2));
                a.movzx(r9d, r9w);
                a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                a.lea(r10, dword_ptr(r14, r9));
                a.add(r10, r11);
                a.mov(word_ptr(r10, 0), r8w);
            }
            else
            {
                a.lea(r9d, dword_ptr(r9d, -4));
                a.mov(dword_ptr(r14, r9, 0), r8d);
            }
            a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r9d);
        }
        break;

        case ZYDIS_MNEMONIC_POPF:
        case ZYDIS_MNEMONIC_POPFD:
        {
            a.mov(r9d, dword_ptr(r15, offsetof(CpuContext, esp)));
            if (isNE || isMZ || instr.mnemonic == ZYDIS_MNEMONIC_POPF)
            {
                a.movzx(r9d, r9w);
                a.mov(r11d, dword_ptr(r15, offsetof(CpuContext, ssBase)));
                a.lea(r10, dword_ptr(r14, r9));
                a.add(r10, r11);
                a.movzx(r8d, word_ptr(r10, 0));
                a.lea(r9d, dword_ptr(r9d, 2));
                a.movzx(r9d, r9w);
            }
            else
            {
                a.mov(r8d, dword_ptr(r14, r9, 0));
                a.lea(r9d, dword_ptr(r9d, 4));
            }
            a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r8d);
            a.mov(dword_ptr(r15, offsetof(CpuContext, esp)), r9d);
        }
        break;

        case ZYDIS_MNEMONIC_XADD:
            if (resolveMemoryIntoR8(operands[0].mem))
            {
                int off = getRegOffset(operands[1].reg.value);
                if (off != -1)
                {
                    if (operands[1].size == 8)
                    {
                        a.mov(r9b, byte_ptr(r15, off));
                        if (instr.attributes & ZYDIS_ATTRIB_HAS_LOCK)
                            a.lock();
                        a.xadd(byte_ptr(r14, r8, 0), r9b);
                        a.mov(byte_ptr(r15, off), r9b);
                    }
                    else if (operands[1].size == 16)
                    {
                        a.mov(r9w, word_ptr(r15, off));
                        if (instr.attributes & ZYDIS_ATTRIB_HAS_LOCK)
                            a.lock();
                        a.xadd(word_ptr(r14, r8, 0), r9w);
                        a.mov(word_ptr(r15, off), r9w);
                    }
                    else
                    {
                        a.mov(r9d, dword_ptr(r15, off));
                        if (instr.attributes & ZYDIS_ATTRIB_HAS_LOCK)
                            a.lock();
                        a.xadd(dword_ptr(r14, r8, 0), r9d);
                        a.mov(dword_ptr(r15, off), r9d);
                    }
                    a.pushfq();
                    a.pop(r10);
                    a.mov(dword_ptr(r15, offsetof(CpuContext, eflags)), r10d);
                }
            }
            break;

        unimplemented:
        default:
            log.isError = true;
            log.buffer << "[JIT] UNIMPLEMENTED: " << ZydisMnemonicGetString(instr.mnemonic) << " at 0x" << std::hex << currentEip << std::dec << "\n";
            for (int i = 0; i < instr.operand_count; ++i)
            {
                log.buffer << "  Op[" << i << "]: type=" << (int)operands[i].type
                           << " size=" << operands[i].size;
                if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER)
                    log.buffer << " reg=" << ZydisRegisterGetString(operands[i].reg.value);
                else if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
                    log.buffer << " mem.base=" << ZydisRegisterGetString(operands[i].mem.base)
                               << " mem.disp=" << operands[i].mem.disp.value;
                log.buffer << "\n";
            }
            // Return nullptr to fall back to interpreter
            return nullptr;
        }

        if (preserveHostFlags)
        {
            if (blockEnded)
            {
                // A flag-neutral, non-branch instruction ended the block after
                // all. Its handler has already emitted a return or a jump, so
                // the pushfq above is stranded and the stack is unbalanced —
                // fall back to the interpreter rather than emit broken code.
                log.isError = true;
                log.buffer << "[JIT] Flag-preserving instruction ended block at 0x"
                           << std::hex << currentEip << std::dec << "; bailing out\n";
                return nullptr;
            }
            a.add(rsp, 8);
            a.popfq();
        }

        currentEip += instr.length;
        instructionCount++;

        if (!blockEnded)
        {
            a.mov(dword_ptr(r15, offsetof(CpuContext, eip)), currentEip);

            // A store that hit a write-protected code page (OnWriteFault) may have patched
            // the instructions that follow in this very block (DD patches displacements a few
            // instructions ahead): leave here, with EIP on the next instruction, so the run
            // loop retranslates. The flag compare is harmless: the host flags are re-seeded
            // from CpuContext just below.
            bool writesMemory = false;
            for (int k = 0; k < instr.operand_count; ++k)
                if (operands[k].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    (operands[k].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                    writesMemory = true;
            if (writesMemory)
            {
                Label noSmc = a.newLabel();
                a.cmp(byte_ptr(r13, offsetof(JitEngine, smcPending)), 0);
                a.je(noSmc);
                emitReturnToRunLoop();
                a.bind(noSmc);
            }

            // Re-seed the host flags register from CpuContext at every guest
            // instruction boundary.
            //
            // Guest flags are meant to live in the host flags register across a
            // block, but CpuContext is the copy that is actually maintained:
            // flag-setting handlers publish to it explicitly, which is why a
            // block that ends on the size limit can return through
            // emitReturnToRunLoop without republishing anything. The host
            // register is not maintained to the same standard — handlers that
            // compute flags through a C helper, or do scratch work after
            // publishing, leave translator state in it.
            //
            // With one instruction per block the next prologue's popfq re-seeded
            // it and the discrepancy was invisible. With two or more, the next
            // instruction in the same block reads whatever the previous
            // handler happened to leave behind. Re-seeding here makes every
            // instruction boundary behave like the single-instruction case.
            //
            // The re-seed itself is emitted lazily, at the top of the next
            // instruction, and only if that instruction needs it (see
            // needsHostFlags): popfq is microcoded, and paying it at every
            // boundary made tight loops several times slower.
            pendingReseed = true;
        }
    }

    if (instructionCount == 0)
    {
        return nullptr;
    }

    // Flag-writing guest instructions update CpuContext explicitly. The
    // translator's own address/stack arithmetic must never become guest flags.
    emitReturnToRunLoop();

    if (asmError.error != kErrorOk)
    {
        log.isError = true;
        log.buffer << "[JIT] AsmJit emit error at guest EIP 0x" << std::hex << startEip
                   << ": " << asmError.message << " (" << std::dec << asmError.error << ")\n";
        return nullptr;
    }

    void *fnPtr = nullptr;
    Error err = jitRuntime.add(&fnPtr, &code);
    if (err)
    {
        log.isError = true;
        log.buffer << "[JIT] AsmJit Error: " << err << "\n";
        return nullptr;
    }

    // Compute hot entry address (post-prologue) for direct chaining
    uint64_t hotOffset = code.labelOffset(hotEntry.id());
    void *hotPtr = (uint8_t *)fnPtr + hotOffset;

    CachedBlock block = {fnPtr, hotPtr};

    // Resolve the chain slots: StoreBlock aims each at its target's hot entry when that is
    // translated, or at the slot's slow path (the run loop) until it is.
    std::vector<std::pair<uint32_t, Link>> exits;
    exits.reserve(exitPatches.size());
    for (const auto& patch : exitPatches)
    {
        void** slot = (void**)((uint8_t*)fnPtr + code.labelOffset(patch.pointerLabel.id()));
        void* slowPathAddr = (uint8_t*)fnPtr + code.labelOffset(patch.slowPathLabel.id());
        exits.push_back({patch.targetEip, Link{slot, slowPathAddr, startEip}});
    }

    StoreBlock(startEip, currentEip, block, std::move(exits));
    log.buffer << "[JIT] Block compiled successfully (" << instructionCount << " instructions)\n";
    return fnPtr;
}
