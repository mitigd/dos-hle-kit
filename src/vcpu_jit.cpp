// The portable JIT backend: the AsmJit engine in src/jit behind hlekit::Vcpu.
//
// Responsibilities of this layer:
//   - guest RAM is the kit's Vm::mem, mapped flat at 0 (the JIT just points at it);
//   - CpuState <-> CpuContext synchronisation at every run boundary (the JIT owns the x87/MMX/
//     SSE files, which CpuState does not model, so a save/restore around a guest call never
//     disturbs them);
//   - the run loop: compile/execute blocks until a kit event, then Exit::Hlt / Exit::Io /
//     Exit::Intr. A hlt byte is a kit trap (IDT stub, NativeFunction, seam return): it is never
//     executed, and EIP is reported past it, exactly as KVM reports it;
//   - int n: push the interrupt frame and jump through the guest IDT, so the kit's hlt stubs
//     and Machine::OnInt keep working unchanged;
//   - in/out: the compiler's pendingIo handshake becomes Exit::Io; the kit answers 0 (no device
//     is emulated) and reports the unseamed access.
//
// The guest is flat 32-bit (DOS/4GW): isNE/isMZ are false, which selects CompileBlock's flat
// protected-mode paths. NE/Phar Lap (16-bit, ring 3) is not covered yet and is reported.
//
// Real-mode (MZ/COM) guests turn on the compiler's isMZ paths (16-bit decode, segment * 16
// addressing). The engine keeps EIP as a *linear* address there, while the kit's CpuState holds the
// 16-bit IP and a separate CS base, so the two are converted at every sync; software interrupts go
// through the IVT with a 16-bit IP/CS/FLAGS frame instead of an IDT gate.
#include "hlekit/vcpu.h"

#include "jit/JitEngine.h"
#include "jit/JitPlatform.h"

#include <algorithm>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace hlekit {

namespace {

constexpr uint32_t kBlocksPerRun = 128;   // then Exit::Intr, so the kit can deliver tasks

// A ring of the block entry EIPs. On a wild jump the guest is gone but the path that got
// there is not: HLEKIT_JIT_EIPLOG=1 prints the tail on any stop, and a SIGSEGV handler prints
// it with the faulting context (the JIT's version of HLEKIT_TRACE).
constexpr size_t kEipRing = 512;
uint32_t g_eips[kEipRing];
size_t g_eipAt = 0;
bool g_eipLog = false;

class JitVcpu;
JitVcpu* g_current = nullptr;

void EipRingDump(const char* why) {
    if (!g_eipLog && !why) return;
    fprintf(stderr, "[cpu] jit: %s; last block entries:\n", why ? why : "stop");
    const size_t n = std::min(g_eipAt, kEipRing);
    for (size_t i = g_eipAt - n; i < g_eipAt; ++i)
        fprintf(stderr, "  %08x%s", g_eips[i % kEipRing], (i + 1) % 8 == 0 ? "\n" : "");
    fprintf(stderr, "\n");
}

class JitVcpu final : public Vcpu {
public:
    ~JitVcpu() override {
        if (g_eipLog) EipRingDump("exit");
        if (g_eipLog || getenv("HLEKIT_JIT_LOG") || getenv("HLEKIT_JIT_STATS"))
            fprintf(stderr, "[cpu] jit: %llu code-write faults, %llu translations dropped, %llu reused, %llu evicted\n",
                    (unsigned long long)jit_.smcFaults, (unsigned long long)jit_.smcInvalidated,
                    (unsigned long long)jit_.smcRestored, (unsigned long long)jit_.smcEvicted);
        if (g_current == this) g_current = nullptr;
        jit_.ClearCachedBlocks();                  // unprotects guest RAM before it goes
        if (mem_) munmap(mem_, kRam);
    }

    const char* Name() const override { return "jit"; }
    uint8_t* Ram() override { return mem_; }
    CpuState& State() override { return state_; }
    void Touch() override { /* RunOnce re-syncs unconditionally */ }

    bool SetRealMode(std::string&) override {
        real_ = true;
        jit_.isMZ = true;
        jit_.isNE = false;
        return true;
    }

    bool Init(std::string& err) override {
        // Page-aligned (and zeroed): pages holding translated code are write-protected.
        void* m = mmap(nullptr, kRam, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED) return err = "jit: cannot allocate guest RAM", false;
        mem_ = (uint8_t*)m;
        jit_.isNE = false;
        jit_.isMZ = false;
        jit_.isRunning = false;
        if (!jit_.Initialize(mem_, kRam, err)) return false;
        g_eipLog = getenv("HLEKIT_JIT_EIPLOG") != nullptr;
        profile_ = getenv("HLEKIT_PROFILE") != nullptr;
        g_current = this;
        static bool handlerInstalled = false;
        if (!handlerInstalled) {
            handlerInstalled = true;
            struct sigaction sa {};
            sa.sa_sigaction = [](int, siginfo_t* info, void*) {
                // A write to a page holding translated code: note it and retry the store.
                if (g_current && info && g_current->jit_.OnWriteFault(info->si_addr)) return;
                if (g_current) {
                    const uintptr_t a = (uintptr_t)(info ? info->si_addr : nullptr), m = (uintptr_t)g_current->mem_;
                    fprintf(stderr, "[cpu] jit: SIGSEGV at host %p (%s %08llx), guest eip %08x\n",
                            info ? info->si_addr : nullptr, a - m < kRam ? "guest" : "outside guest RAM, offset",
                            (unsigned long long)(a - m), g_current->jit_.context.eip);
                    EipRingDump("crash");
                }
                _exit(3);
            };
            sa.sa_flags = SA_SIGINFO;
            sigaction(SIGSEGV, &sa, nullptr);
            sigaction(SIGBUS, &sa, nullptr);
        }
        return true;
    }

    bool RunOnce(std::string& err) override {
        exit = ExitInfo{};
        SyncFromState();
        jit_.isRunning = true;

        uint32_t blockLimit = kBlocksPerRun;
        if (profile_) {
            // Machine samples EIP when RunOnce returns. A fixed block count aliases tightly
            // with short loops and makes the sampled "hot function" misleading.
            profileRng_ ^= profileRng_ << 13;
            profileRng_ ^= profileRng_ >> 17;
            profileRng_ ^= profileRng_ << 5;
            blockLimit = 64 + (profileRng_ & 127);
        }
        for (uint32_t blocks = 0; blocks < blockLimit; ++blocks) {
            const uint32_t eip = jit_.context.eip;
            g_eips[g_eipAt++ % kEipRing] = eip;
            if (eip >= kRam) {
                SyncToState();
                exit.reason = Exit::Mmio;
                exit.addr = eip;
                return true;
            }
            const uint8_t op = mem_[eip];

            if (op == 0xF4) {                      // hlt: a kit trap, not an instruction
                jit_.context.eip = eip + 1;
                SyncToState();
                exit.reason = Exit::Hlt;
                return true;
            }
            if (state_.ring3 && op == 0xCC) {      // int3: ring-3 trap (reported like KVM's debug exit)
                exit.reason = Exit::Debug;
                exit.exception = 3;
                exit.pc = eip;
                SyncToState();
                return true;
            }

            if (jit_.smcPending) jit_.SyncDirtyCode();   // code was written since the last block

            if (jit_.context.pendingInt != 0xFF) {
                if (!DeliverInterrupt(err)) { SyncToState(); return false; }
                continue;
            }
            if (jit_.context.pendingIo != 0) {
                TakeIoExit();
                return true;
            }
            if (!jit_.isRunning) {                 // Kick() from another thread
                SyncToState();
                exit.reason = Exit::Intr;
                return true;
            }

            void* code = BlockAt(eip);
            if (!code) {
                char buf[160];
                snprintf(buf, sizeof buf, "jit: no translation for %08x (%02x %02x %02x %02x)", eip,
                         mem_[eip], mem_[(eip + 1) % kRam], mem_[(eip + 2) % kRam], mem_[(eip + 3) % kRam]);
                err = buf;
                SyncToState();
                return false;
            }
            jit_.ExecuteJit(code);
            // An int/in/out the block just ended on belongs to this run: it must not be left in
            // CpuContext (which CpuState does not carry) when the run ends on its block budget,
            // or a task's guest call would take the interrupted code's int 21h with its own
            // registers.
            if (jit_.context.pendingInt != 0xFF) {
                if (!DeliverInterrupt(err)) { SyncToState(); return false; }
            }
            if (jit_.context.pendingIo != 0) {
                TakeIoExit();
                return true;
            }
        }
        SyncToState();
        exit.reason = Exit::Intr;
        return true;
    }

    void Kick() override { jit_.isRunning = false; }

    bool SetDebug(uint32_t bp, bool step, uint32_t watch, std::string& err) override {
        if (!bp && !step && !watch) return true;
        err = "jit: breakpoints/watchpoints are not implemented (use --cpu kvm for HLEKIT_TRACE/HLEKIT_WATCH)";
        return false;
    }

    void Invalidate(uint32_t addr, uint32_t len) override { jit_.Invalidate(addr, len); }

private:
    // CpuState (the kit's view) -> CpuContext (what the generated code touches). The x87, MMX
    // and SSE files are left alone: the kit does not model them and they must survive seam
    // calls and guest calls.
    void SyncFromState() {
        auto& c = jit_.context;
        c.eax = state_.reg[(int)Reg::Eax];
        c.ebx = state_.reg[(int)Reg::Ebx];
        c.ecx = state_.reg[(int)Reg::Ecx];
        c.edx = state_.reg[(int)Reg::Edx];
        c.esi = state_.reg[(int)Reg::Esi];
        c.edi = state_.reg[(int)Reg::Edi];
        c.ebp = state_.reg[(int)Reg::Ebp];
        c.esp = state_.reg[(int)Reg::Esp];
        c.eip = state_.reg[(int)Reg::Eip];
        c.eflags = state_.reg[(int)Reg::Eflags];
        c.df = (state_.reg[(int)Reg::Eflags] >> 10) & 1;       // DF lives in its own byte
        auto seg = [&](Seg s, uint16_t& sel, uint32_t& base) {
            sel = state_.seg[(int)s].sel;
            base = state_.seg[(int)s].base;
        };
        if (real_) c.eip = state_.seg[(int)Seg::Cs].base + (state_.reg[(int)Reg::Eip] & 0xFFFF);   // linear
        seg(Seg::Cs, c.cs, c.csBase);
        seg(Seg::Ds, c.ds, c.dsBase);
        seg(Seg::Es, c.es, c.esBase);
        seg(Seg::Ss, c.ss, c.ssBase);
        seg(Seg::Fs, c.fs, c.fsBase);
        seg(Seg::Gs, c.gs, c.gsBase);
        jit_.gdtBase = (uint32_t)state_.gdtBase;
    }

    void SyncToState() {
        const auto& c = jit_.context;
        state_.reg[(int)Reg::Eax] = c.eax;
        state_.reg[(int)Reg::Ebx] = c.ebx;
        state_.reg[(int)Reg::Ecx] = c.ecx;
        state_.reg[(int)Reg::Edx] = c.edx;
        state_.reg[(int)Reg::Esi] = c.esi;
        state_.reg[(int)Reg::Edi] = c.edi;
        state_.reg[(int)Reg::Ebp] = c.ebp;
        state_.reg[(int)Reg::Esp] = c.esp;
        state_.reg[(int)Reg::Eip] = real_ ? (c.eip - c.csBase) & 0xFFFF : c.eip;   // IP, not linear
        state_.reg[(int)Reg::Eflags] = (c.eflags & ~0x400u) | ((uint32_t)(c.df & 1) << 10);
        auto seg = [&](Seg s, uint16_t sel, uint32_t base) {
            state_.seg[(int)s].sel = sel;
            state_.seg[(int)s].base = base;
        };
        seg(Seg::Cs, c.cs, c.csBase);
        seg(Seg::Ds, c.ds, c.dsBase);
        seg(Seg::Es, c.es, c.esBase);
        seg(Seg::Ss, c.ss, c.ssBase);
        seg(Seg::Fs, c.fs, c.fsBase);
        seg(Seg::Gs, c.gs, c.gsBase);
    }

    void* BlockAt(uint32_t eip) {
        if (JitEngine::CachedBlock* b = jit_.FindCachedBlock(eip)) return b->coldEntry;
        if (jit_.RestoreCachedBlock(eip)) return jit_.FindCachedBlock(eip)->coldEntry;
        if (!jit_.CompileBlock(eip)) return nullptr;
        JitEngine::CachedBlock* b = jit_.FindCachedBlock(eip);
        return b ? b->coldEntry : nullptr;
    }

    // int n: what the CPU does before the handler runs. The kit's IDT gates are 32-bit interrupt
    // gates into the hlt stubs, which is why this is the only interrupt machinery the backend
    // needs: EFLAGS, CS and EIP go on the guest stack and IF is cleared.
    bool DeliverInterrupt(std::string& err) {
        auto& c = jit_.context;
        const uint8_t v = c.pendingInt;
        c.pendingInt = 0xFF;
        if (real_) {                                // IVT entry: IP, CS words; frame IP, CS, FLAGS
            const uint32_t ip = (c.eip - c.csBase) & 0xFFFF;
            c.esp = (c.esp & ~0xFFFFu) | ((c.esp - 6) & 0xFFFF);
            const uint32_t sp = c.ssBase + (c.esp & 0xFFFF);
            Wr16(sp, (uint16_t)ip);
            Wr16(sp + 2, c.cs);
            Wr16(sp + 4, (uint16_t)((c.eflags & ~0x400u) | ((uint32_t)(c.df & 1) << 10)));
            c.eflags &= ~0x300u;                    // IF and TF clear
            uint16_t newIp = 0, newCs = 0;
            memcpy(&newIp, mem_ + v * 4u, 2);
            memcpy(&newCs, mem_ + v * 4u + 2, 2);
            c.cs = newCs;
            c.csBase = (uint32_t)newCs << 4;
            c.eip = c.csBase + newIp;
            return true;
        }
        const uint32_t at = (uint32_t)state_.idtBase + v * 8u;
        uint64_t gate = 0;
        if (at + 8 > kRam) return err = "jit: IDT outside guest RAM", false;
        memcpy(&gate, mem_ + at, 8);
        const uint32_t off = (uint32_t)(gate & 0xFFFF) | (uint32_t)((gate >> 48) << 16);
        const uint16_t sel = (uint16_t)((gate >> 16) & 0xFFFF);
        const uint8_t type = (uint8_t)((gate >> 40) & 0xFF);
        const bool gate32 = (type & 0x1F) == 0xE;
        auto push = [&](uint32_t value) {
            if (gate32) {
                c.esp -= 4;
                Wr32(c.ssBase + c.esp, value);
            } else {
                c.esp = (c.esp - 2) & 0xFFFF;
                Wr16(c.ssBase + c.esp, (uint16_t)value);
            }
        };
        push((c.eflags & ~0x400u) | ((uint32_t)(c.df & 1) << 10));
        push(c.cs);
        push(c.eip);
        c.eflags &= ~0x4100u;                     // TF and NT clear for any gate
        if (!(type & 0x1)) c.eflags &= ~0x200u;   // interrupt gate (0x6/0xE): IF = 0 too
        c.cs = sel;
        c.csBase = jit_.GetLinearAddress(sel, 0);
        c.eip = off;
        return true;
    }

    void TakeIoExit() {
        auto& c = jit_.context;
        exit.reason = Exit::Io;
        exit.port = c.pendingIoPort;
        exit.size = c.pendingIoWidth ? c.pendingIoWidth : 1;
        exit.ioCount = 1;
        exit.out = c.pendingIo == 2;
        exit.data = nullptr;                       // the backend answers 0 itself
        if (!exit.out) {                           // in: no device, reads 0
            if (exit.size == 1) c.eax &= ~0xFFu;
            else if (exit.size == 2) c.eax &= ~0xFFFFu;
            else c.eax = 0;
        }
        c.pendingIo = 0;
        SyncToState();
    }

    void Wr16(uint32_t a, uint16_t v) { if (a + 2 <= kRam) memcpy(mem_ + a, &v, 2); }
    void Wr32(uint32_t a, uint32_t v) { if (a + 4 <= kRam) memcpy(mem_ + a, &v, 4); }

    uint8_t* mem_ = nullptr;
    CpuState state_;
    JitEngine jit_;
    bool real_ = false;
    bool profile_ = false;
    uint32_t profileRng_ = 0x9e3779b9u;
    friend void EipRingDump(const char*);
};

}  // namespace

std::unique_ptr<Vcpu> CreateJit(std::string& err) {
    auto v = std::make_unique<JitVcpu>();
    if (!v->Init(err)) return nullptr;
    return v;
}

}  // namespace hlekit
