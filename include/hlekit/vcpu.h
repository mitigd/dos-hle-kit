// The CPU engine: KVM (Linux), WHPX (Windows) or the portable JIT. Everything above this line -
// the extenders' services, the seam table, the loaders and the frontend - only sees CpuState and
// ExitInfo, so it does not know which engine is running the original code.
//
// The contract, in one paragraph: one 32-bit protected-mode vCPU, no paging, guest RAM mapped
// flat at physical 0; every IDT gate points at a `hlt` (or ring-3 `int3`) stub, so software
// interrupts, extender services and native functions all leave through the trap byte; `hlt` and
// port I/O end a run; registers and segment descriptors are readable after each exit and
// writeable before the next; and any thread may Kick() a run out of the engine.
//
// Each backend maps these onto its own register file and exit mechanism.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace hlekit {

enum class Reg { Eax, Ebx, Ecx, Edx, Esi, Edi, Ebp, Esp, Eip, Eflags };
enum class Seg { Cs, Ds, Es, Fs, Gs, Ss };

inline constexpr int kRegCount = 10;
inline constexpr int kSegCount = 6;
inline constexpr uint32_t kRam = 64u << 20;   // guest RAM, physical 0..64 MB

// One segment register, in descriptor terms. `access` is the descriptor's access byte
// (type | S | DPL | P) so a backend can hand it to the CPU unchanged.
struct SegState {
    uint16_t sel = 0;
    uint32_t base = 0, limit = 0;
    uint8_t access = 0;
    bool big = false;        // D/B: 32-bit default operand/stack size
    bool gran = false;       // G: limit is in 4 KB pages
    bool unusable = false;   // null selector (KVM kills it; a JIT keeps it as {0,0})
};

struct CpuState {
    uint32_t reg[kRegCount] = {};     // indexed by Reg
    SegState seg[kSegCount] = {};     // indexed by Seg
    SegState ldt;                     // segmented (NE) programs: an LDT over the GDT
    bool hasLdt = false;
    uint64_t gdtBase = 0;
    uint16_t gdtLimit = 0;
    uint64_t idtBase = 0;
    uint16_t idtLimit = 0;
    uint32_t cr0 = 0x33, cr4 = 0, efer = 0;
    bool ring3 = false;               // Phar Lap 286 (ring-3) guests
};

enum class Exit {
    Hlt,          // executed a trap byte (hlt, or int3 at ring 3)
    Io,           // in/out: `port`, `size`, `out`, and `data` for an IN
    Mmio,         // an access outside guest RAM
    Intr,         // a host kick or signal ended the run early
    Window,       // the interrupt window opened (a Kick hint only)
    Shutdown,     // triple fault
    FailEntry,    // the engine refused to enter the guest
    Internal,     // engine error
    Debug,        // breakpoint / single step
    Other
};

struct ExitInfo {
    Exit reason = Exit::Other;
    // Io
    uint32_t ioCount = 1;
    uint8_t size = 1;
    bool out = false;
    uint16_t port = 0;
    uint8_t* data = nullptr;      // IN: the host's answer; null = the backend already answered 0
    // Mmio (also the faulting address of a failed access)
    uint64_t addr = 0;
    bool write = false;
    uint32_t len = 0;
    // FailEntry / Internal
    uint64_t failReason = 0;
    uint32_t suberror = 0;
    // Debug: the trapping instruction, the exception vector and the debug status
    uint64_t pc = 0;
    uint32_t exception = 0;
    uint32_t dr6 = 0;
    // Engine exit number, for diagnostics
    uint32_t raw = 0;
};

class Vcpu {
public:
    virtual ~Vcpu() = default;
    virtual const char* Name() const = 0;

    // Map kRam of guest RAM (physical 0) and create the vCPU. Ram() is valid afterwards.
    virtual bool Init(std::string& err) = 0;
    virtual uint8_t* Ram() = 0;

    // Registers, segments and tables: the kit reads and writes the engine's canonical copy
    // between runs. Touch() says "State() was modified"; a backend that keeps its own hardware
    // copy flushes it at the next RunOnce.
    virtual CpuState& State() = 0;
    virtual void Touch() = 0;

    virtual bool RunOnce(std::string& err) = 0;        // one run; result in exit
    virtual void Kick() = 0;                           // any thread: leave RunOnce soon
    virtual void SetInterruptWindow(bool) {}           // "wake me when IF=1" hint (Kick does the rest)
    virtual bool SetDebug(uint32_t bp, bool step, uint32_t watch, std::string& err) = 0;

    // Real-mode (MZ/COM) programs: called once before the first run, ahead of State() being set up
    // as a real-mode CPU (16-bit IP/SP, segment base = selector << 4, interrupts through the IVT at 0).
    // A backend that cannot run it says why.
    virtual bool SetRealMode(std::string& err) { err = "this backend runs 32-bit protected mode only"; return false; }
    ExitInfo exit;

    // The guest wrote code through the host (a seam planted a trap byte, DOS loaded an overlay,
    // a seam edited a handler): drop any cached translation of [addr, addr+len).
    virtual void Invalidate(uint32_t, uint32_t) {}

    // `name`: kvm, whpx, jit or web (= jit in a browser build); empty = Default().
    // Available() is the list this build can create. Create() returns null and sets err if it
    // cannot; the engine is initialised and ready to run when it returns non-null.
    static std::unique_ptr<Vcpu> Create(const std::string& name, std::string& err);
    static std::vector<std::string> Available();
    static std::string Default();
};

}  // namespace hlekit
