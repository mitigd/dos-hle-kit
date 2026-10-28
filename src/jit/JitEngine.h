// AsmJit x86-64 JIT for the kit's guests.
//
// JitEngine owns the translation cache and the 16/32-bit x86 compiler in CompileBlock.cpp
// (Zydis decode + AsmJit emission). Loaders, OS services and hardware seams live above it;
// the CPU backend in src/vcpu_jit.cpp supplies the run loop, state synchronisation and the
// trap/I/O exits.
//
// The guest is a 32-bit flat DOS/4GW client, so isNE and isMZ stay false: CompileBlock's
// flat-32 paths are the ones the kit needs. Software interrupts and port I/O still use the
// pendingInt/pendingIo handshake the compiler emits, and the backend dispatches them through
// the guest's IDT (whose gates are the kit's hlt stubs).
#pragma once

#include <asmjit/asmjit.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <list>
#include <string>
#include <unordered_map>
#include <vector>

class JitEngine {
public:
    // The register file the generated code works on. CompileBlock emits
    // `offsetof(CpuContext, ...)`, so the layout is part of the compiler contract.
    struct CpuContext {
        uint32_t eax, ebx, ecx, edx;
        uint32_t esi, edi, ebp, esp;
        uint32_t eip;
        uint32_t eflags;
        uint32_t chainBudget = 0;
        uint16_t fpuStatus;
        uint16_t fpuControl;
        uint16_t fpuTag;
        uint16_t cs, ds, es, ss, fs, gs;
        uint32_t csBase, dsBase, esBase, ssBase, fsBase, gsBase;
        uint64_t mm[8];      // x87 stack, values as host doubles
        uint64_t mmx[8];     // MMX registers, kept separate from the x87 stack
        uint8_t xmm[8][16];
        uint8_t pendingInt = 0xFF;
        uint8_t pendingIo = 0;
        uint16_t pendingIoPort = 0;
        uint8_t pendingIoWidth = 0;
        uint32_t pendingIoValue = 0;
    };

    JitEngine();
    ~JitEngine();

    // Map the kit's guest RAM (physical 0..size). The caller owns the buffer (Vm::mem).
    bool Initialize(uint8_t* memory, size_t size, std::string& err);

    uint8_t* GetPointer(uint64_t address) { return address < memorySize ? guestMemory + address : nullptr; }
    uint64_t GetMemorySize() const { return memorySize; }
    size_t size() const { return memorySize; }
    void* GetEngineContext() { return (void*)&context; }

    uint32_t Read32(uint64_t address);
    uint8_t Read8(uint64_t address);

    // Block cache.
    struct CachedBlock {
        void* coldEntry;   // full prologue entry (from the run loop)
        void* hotEntry;    // post-prologue entry (from a chained block)
    };
    void* CompileBlock(uint32_t eip);
    void ExecuteJit(void* hostCode);
    CachedBlock* FindCachedBlock(uint32_t eip);
    bool RestoreCachedBlock(uint32_t eip);
    void ClearCachedBlocks();

    // Self-modifying code. Every host page holding guest bytes that a translation was made from
    // is write-protected; the first write to it (generated code or the kit) faults, and
    // OnWriteFault unprotects the page and marks it dirty. Before the next block runs, the run
    // loop calls SyncDirtyCode, which drops exactly the translations whose source bytes changed
    // (unlinking the chains into them) and protects the page again. Chained code checks
    // smcPending, so a store that patches code ends the chain at the next block boundary;
    // only the rest of the storing block itself can still run stale.
    bool OnWriteFault(const void* hostAddr);   // signal handler: true if it was ours
    void SyncDirtyCode();
    volatile uint8_t smcPending = 0;
    uint64_t smcFaults = 0, smcInvalidated = 0, smcRestored = 0, smcEvicted = 0;

    // The kit wrote [addr, addr+len) from the host (Vm's writers, DOS reads): unprotect those
    // pages now (the kernel cannot write a protected page for fread) and recheck them before
    // the next block.
    void Invalidate(uint32_t addr, uint32_t len);

    // 16-bit selector helpers the compiler emits calls to.
    uint32_t GetLinearAddress(uint16_t selector, uint32_t offset);
    bool VerifySelectorAccess(uint16_t selector, bool write);
    static void UpdateSegBaseStub(CpuContext* ctx, uint8_t* mem, JitEngine* engine, int regId, uint16_t selector);
    static void UpdateSegRegFromContextStub(CpuContext* ctx, uint8_t* mem, JitEngine* engine, int regId);
    void UpdateSegBase(int regId, uint16_t selector);

    // Planar VGA shadow-plane hooks. The kit's frontend reads the palette and the A0000h window
    // directly, so these are no-ops (kept because the compiler emits calls to them).
    void WriteDosVram(uint32_t, uint32_t, uint32_t) {}
    void ReadDosVram(uint32_t, uint32_t) {}

    // API thunk page: the kit does not use thunks, but the call/jmp paths still query it.
    struct ApiTrap {
        std::string library, function;
        void* hostStub = nullptr;
        uint32_t argCount = 0;
        bool isStub = false, isCdecl = false;
    };
    bool IsTrapAddress(uint32_t addr, uint32_t& outTrapIndex) const {
        if (addr >= trapPageBase && addr < trapPageBase + 0x10000) {
            outTrapIndex = (uint32_t)((addr - trapPageBase) / 8);
            return outTrapIndex < traps.size();
        }
        return false;
    }
    bool ConsumeDeferredTrapReturn() {
        if (!deferCurrentTrapReturn) return false;
        deferCurrentTrapReturn = false;
        return true;
    }
    void DeferCurrentTrapReturn() { deferCurrentTrapReturn = true; }

    // The register file (public: CompileBlock's emitted code uses offsetof on this class).
    CpuContext context;
    bool isRunning = false;
    bool isNE = false;
    bool isMZ = false;
    bool isCOM = false;
    bool deferCurrentTrapReturn = false;

    uint64_t chainHotJumps = 0;
    uint64_t chainSlowCacheMisses = 0;
    uint64_t chainSlowBudgetExits = 0;
    uint64_t chainSlowPendingInterruptExits = 0;
    uint64_t chainSlowStopRequestExits = 0;

    uint32_t trapPageBase = 0;
    uint32_t gdtBase = 0;
    std::vector<ApiTrap> traps;

private:
    static constexpr uint32_t kMaxChainBudget = 64;
    typedef void (*JitFunction)(CpuContext* ctx, uint8_t* memory, JitEngine* engine);

    uint8_t* guestMemory = nullptr;
    size_t memorySize = 0;

    asmjit::JitRuntime jitRuntime;

    // One translation: where its guest bytes are, a copy of them, and the chain slots it owns.
    struct Link {
        void** slot;       // pointer embedded in the owner's code: target hot entry or slow path
        void* slowPath;
        uint32_t owner;    // start EIP of the block that owns the slot
    };
    struct Block {
        CachedBlock entry;
        uint32_t start, end;
        std::vector<uint8_t> source;
        std::vector<uint32_t> exitTargets;   // targets of this block's chain slots
        std::vector<std::pair<uint32_t, Link>> exits; // slots to relink if this version returns
    };
    void StoreBlock(uint32_t eip, uint32_t end, const CachedBlock& entry,
                    std::vector<std::pair<uint32_t, Link>>&& exits);
    void DropBlock(uint32_t eip, bool park = false);
    void ProtectRange(uint32_t start, uint32_t end);

    std::unordered_map<uint32_t, Block> blocks;
    // Changed code often cycles through a few byte patterns. Park old translations, with
    // their chains unlinked, and restore one only when its complete source bytes match.
    struct DormantBlock { uint32_t eip; Block block; };
    static constexpr size_t kDormantLimit = 8192;
    std::list<DormantBlock> dormant;
    std::unordered_multimap<uint32_t, std::list<DormantBlock>::iterator> dormantIndex;
    // Run-loop lookups are frequent even with chaining. Keep a small direct-mapped
    // front cache; unordered_map keeps Block addresses stable until erasure.
    struct LookupEntry {
        uint32_t eip = 0;
        CachedBlock* block = nullptr;
    };
    static constexpr size_t kLookupSize = 1 << 14;
    LookupEntry lookup[kLookupSize]{};
    std::unordered_map<uint32_t, std::vector<Link>> links;      // target EIP -> slots aimed at it
    std::vector<std::vector<uint32_t>> pageBlocks;              // host page -> blocks overlapping it
    std::vector<uint8_t> pageProtected;                         // host page is read-only
    volatile uint8_t* pageDirty = nullptr;                      // written since protected
    // The dirty pages, so SyncDirtyCode need not scan them all (filled from the signal handler;
    // on overflow it falls back to a full scan).
    static constexpr uint32_t kDirtyList = 64;
    uint32_t dirtyList[kDirtyList];
    volatile uint32_t dirtyCount = 0;
    void MarkDirty(size_t page);
    std::vector<uint8_t> pageDirtyStore;
    uint32_t hostPageShift = 12;
    uintptr_t hostPageMask = 0xFFF;
};
