// The virtual CPU the kit runs the original code on, plus the guest-memory and descriptor
// helpers every seam uses. The engine behind it is a backend (vcpu.h): KVM, WHPX or the JIT.
//
// Guest address == host offset into `mem`, and the LE image sits at its linked addresses (except
// an object moved out of the A0000h hole, le.h), so a guest address is also a decomp address.
// Only the original code runs: no device is emulated.
#pragma once
#include "hlekit/vcpu.h"

#include <cstdint>
#include <cstring>
#include <string>

namespace hlekit {

class Vm {
public:
    // memory map (see the kit's layout notes)
    static constexpr uint32_t kRam = hlekit::kRam;
    static constexpr uint32_t kPsp = 0x500, kEnv = 0x600;
    static constexpr uint32_t kGdt = 0x800, kGdtEntries = 256;          // 0x800-0xfff
    static constexpr uint32_t kIdt = 0x2000;                             // 256 gates, 0x2000-0x27ff
    static constexpr uint32_t kStubs = 0x2800;                           // per vector: hlt; iret
    static constexpr uint32_t kCallReturn = 0x2A00;                      // hlt: end of a host->guest call
    static constexpr uint32_t kCallReturnIret = 0x2A02;                  // hlt: same, entered by iret
    static constexpr uint32_t kScratch = 0x2A10;                         // 0x2a10-0x2aff: out-params of such calls
    static constexpr uint32_t kBiosIrq = 0x2B00;                         // 16 x (hlt; iret): BIOS default IRQ handlers
    static constexpr uint32_t kNative = 0x3000, kNativeEnd = 0x4000;     // hlt stubs of NativeFunction()
    static constexpr uint32_t kTrampolines = 0x8000, kTrampolinesEnd = 0xA000;   // CallOriginal: copied entries
    static constexpr uint16_t kCodeSel = 0x08, kDataSel = 0x10, kStackSel = 0xF8;
    static constexpr uint16_t kPspSel = 0xE0, kEnvSel = 0xE8;
    static constexpr uint16_t kFirstFreeSel = 0x100;                     // DPMI allocations
    static constexpr uint16_t kLdtSel = 0x18;                            // segmented: the LDT (= the GDT's memory)

    ~Vm();

    // Choose the CPU engine: `backend` empty -> HLEKIT_CPU, else Vcpu::Default(). The engine is
    // created and ready when this returns true; `Backend()` names it.
    bool Create(std::string& err);
    bool Create(const std::string& backend, std::string& err);
    const std::string& Backend() const { return backend_; }

    void BuildTables();                       // GDT, IDT, stubs
    bool Enter(uint32_t eip, uint32_t esp, std::string& err);
    // Segmented entry (NE): CS:IP, SS:SP, DS and ES from GDT selectors (16-bit descriptors).
    // LDTR = kLdtSel, an LDT descriptor over the GDT itself: programs that read and edit "their
    // LDT" (sldt + a mapped selector) edit the descriptors the CPU uses, TI=1 or not.
    bool EnterSegmented(uint16_t cs, uint16_t ip, uint16_t ss, uint16_t sp, uint16_t ds, uint16_t es, std::string& err);
    // Real mode (DOS COM/MZ programs, KVM only): segment base = selector << 4, 64 KB limits,
    // 16-bit code; the IVT at 0 points every vector at its `hlt; iret` stub (BuildRealTables).
    bool real = false;
    void BuildRealTables();
    bool EnterReal(uint16_t cs, uint16_t ip, uint16_t ss, uint16_t sp, uint16_t ds, uint16_t es, std::string& err);
    uint32_t RealLinear(uint16_t seg, uint16_t off) const { return ((uint32_t)seg << 4) + off; }

    // ---- memory (host memory; every write drops stale JIT translations)
    uint8_t* mem = nullptr;
    uint8_t* Ptr(uint32_t a, uint32_t n = 1) { return (uint64_t)a + n <= kRam ? mem + a : nullptr; }
    uint8_t Rd8(uint32_t a) { auto p = Ptr(a); return p ? *p : 0; }
    uint16_t Rd16(uint32_t a) { uint16_t v = 0; if (auto p = Ptr(a, 2)) memcpy(&v, p, 2); return v; }
    uint32_t Rd32(uint32_t a) { uint32_t v = 0; if (auto p = Ptr(a, 4)) memcpy(&v, p, 4); return v; }
    void Wr8(uint32_t a, uint8_t v) { if (auto p = Ptr(a)) { *p = v; cpu_->Invalidate(a, 1); } }
    void Wr16(uint32_t a, uint16_t v) { if (auto p = Ptr(a, 2)) { memcpy(p, &v, 2); cpu_->Invalidate(a, 2); } }
    void Wr32(uint32_t a, uint32_t v) { if (auto p = Ptr(a, 4)) { memcpy(p, &v, 4); cpu_->Invalidate(a, 4); } }
    bool Write(uint32_t a, const void* src, uint32_t n) {
        auto p = Ptr(a, n);
        if (p) { memcpy(p, src, n); cpu_->Invalidate(a, n); }
        return p;
    }
    std::string CStr(uint32_t a, size_t max = 256);

    // ---- descriptors (in guest memory, the CPU reads them on every selector load)
    uint64_t Desc(uint16_t sel) { uint64_t v = 0; if (auto p = Ptr(gdtBase + (sel & ~7u), 8)) memcpy(&v, p, 8); return v; }
    void SetDesc(uint16_t sel, uint64_t d) { if (auto p = Ptr(gdtBase + (sel & ~7u), 8)) memcpy(p, &d, 8); }
    // The GDT: kGdt / kGdtEntries for flat DOS/4GW programs; segmented (NE) programs need
    // thousands of selectors and move it (Machine::LoadNe) before BuildTables.
    uint32_t gdtBase = kGdt, gdtEntries = kGdtEntries;
    // Flat programs: every unused entry loads flat (some DOS/4GW code invents selectors).
    // Segmented programs keep unused entries empty (not present): BioForge's own selector
    // manager collects the free ones.
    bool fillFlat = true;
    // Ring 3 (Phar Lap 286 programs run there and depend on DPL-3 descriptors): traps are int3
    // (KVM software breakpoints exit to the host; hlt would fault), gates are DPL 3 into a
    // conforming flat code segment (no privilege change, no TSS), IOPL 3 (in/out still exit).
    bool ring3 = false;
    uint8_t Trap() const { return ring3 ? 0xCC : 0xF4; }
    uint16_t Rpl() const { return ring3 ? 3 : 0; }
    bool Is32(Seg s);                         // the segment register's descriptor has D/B set
    static uint64_t MakeDesc(uint32_t base, uint32_t limit, uint8_t access, bool big = true);
    static uint32_t DescBase(uint64_t d) { return (uint32_t)(((d >> 16) & 0xFFFFFF) | ((d >> 56) << 24)); }
    static uint32_t DescLimit(uint64_t d) {
        uint32_t l = (uint32_t)((d & 0xFFFF) | ((d >> 32) & 0xF0000));
        return (d >> 55) & 1 ? (l << 12) | 0xFFF : l;
    }
    uint32_t SelBase(uint16_t sel) { return DescBase(Desc(sel)); }

    // ---- registers (the engine's canonical state; written back before the next run)
    uint32_t Get(Reg r) const { return cpu_->State().reg[(int)r]; }
    void Set(Reg r, uint32_t v);
    uint16_t Get16(Reg r) const { return (uint16_t)Get(r); }
    void Set16(Reg r, uint16_t v) { Set(r, (Get(r) & 0xFFFF0000u) | v); }
    uint16_t GetSeg(Seg s) const { return cpu_->State().seg[(int)s].sel; }
    uint32_t SegBase(Seg s) const { return cpu_->State().seg[(int)s].base; }
    bool LoadSeg(Seg s, uint16_t sel);        // as a `mov sreg` would, from the GDT
    void LoadIdt(uint32_t base, uint16_t limit);  // native extender service for guest IDTR switches
    CpuState State() const { return cpu_->State(); }       // for save/restore around guest calls
    void Restore(const CpuState& s) { cpu_->State() = s; cpu_->Touch(); }

    // ---- run
    bool RunOnce(std::string& err);           // one run; the result is Exit()
    ExitInfo& Exit() { return cpu_->exit; }
    const ExitInfo& Exit() const { return cpu_->exit; }
    void Kick() { cpu_->Kick(); }             // any thread
    void SetInterruptWindow(bool on) { cpu_->SetInterruptWindow(on); }
    // Diagnostics (HLEKIT_TRACE): an execute breakpoint at `bp` (0 = none) and/or single-step;
    // both end a run with Exit::Debug. `watch` (HLEKIT_WATCH) is a 4-byte write watchpoint.
    bool SetDebug(uint32_t bp, bool step, std::string& err) { return cpu_->SetDebug(bp, step, watch, err); }
    uint32_t watch = 0;
    void InvalidateCode(uint32_t addr, uint32_t len) { cpu_->Invalidate(addr, len); }

private:
    std::unique_ptr<Vcpu> cpu_;
    std::string backend_;
};

}  // namespace hlekit
