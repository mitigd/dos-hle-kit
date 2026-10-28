#include "hlekit/vm.h"

#include <cctype>
#include <cstdlib>

namespace hlekit {

Vm::~Vm() = default;

bool Vm::Create(std::string& err) {
    const char* env = getenv("HLEKIT_CPU");
    return Create(env ? env : "", err);
}

bool Vm::Create(const std::string& backend, std::string& err) {
    std::string name = backend;
    if (name.empty()) name = Vcpu::Default();
    if (name == "web" || name == "Web") name = "jit";
    cpu_ = Vcpu::Create(name, err);
    if (!cpu_) return false;
    backend_ = cpu_->Name();
    mem = cpu_->Ram();
    return true;
}

uint64_t Vm::MakeDesc(uint32_t base, uint32_t limit, uint8_t access, bool big) {
    bool gran = limit > 0xFFFFF;
    if (gran) limit >>= 12;
    uint64_t flags = (gran ? 0x8 : 0) | (big ? 0x4 : 0);
    return (uint64_t)(limit & 0xFFFF) | (uint64_t)(base & 0xFFFFFF) << 16 | (uint64_t)access << 40 |
           (uint64_t)((limit >> 16) & 0xF) << 48 | flags << 52 | (uint64_t)(base >> 24) << 56;
}

// A descriptor as the engine needs it (the CPU loads one on every `mov sreg`).
static SegState SegFromDesc(uint16_t sel, uint64_t d) {
    SegState s;
    s.sel = sel;
    s.base = Vm::DescBase(d);
    s.limit = Vm::DescLimit(d);
    s.access = (uint8_t)((d >> 40) & 0xFF);
    s.big = ((d >> 54) & 1) != 0;
    s.gran = ((d >> 55) & 1) != 0;
    s.unusable = ((d >> 47) & 1) == 0;
    return s;
}

void Vm::BuildTables() {
    // GDT: every selector the guest might name loads flat. CS (0x08) and SS (0xF8) are ring 0
    // (SS needs DPL == CPL); data is DPL 3 so RPL-3 loads work. PSP and env have real bases.
    // Accessed bits preset: the CPU would otherwise write them on the first load.
    for (uint32_t i = 1; i < gdtEntries; ++i)
        SetDesc(i * 8, fillFlat ? MakeDesc(0, 0xFFFFFFFF, (i % 2) ? 0xFB : 0xF3) : 0);
    SetDesc(kCodeSel, MakeDesc(0, 0xFFFFFFFF, ring3 ? 0x9F : 0x9B));   // ring 3: conforming
    SetDesc(kStackSel, MakeDesc(0, 0xFFFFFFFF, 0x93));
    SetDesc(kPspSel, MakeDesc(kPsp, 0xFF, 0xF3));
    SetDesc(kEnvSel, MakeDesc(kEnv, 0x1FF, 0xF3));

    // IDT: every vector enters a `hlt; iret` stub, so software ints (21h, 31h, 10h) and CPU
    // exceptions exit to the host with a normal interrupt frame on the guest stack. There are no
    // hardware IRQs: the hardware is replaced function by function (seams), never emulated.
    for (uint32_t v = 0; v < 256; ++v) {
        uint32_t off = kStubs + v * 2;
        Wr8(off, Trap());
        Wr8(off + 1, 0xCF);
        uint64_t gate = (off & 0xFFFF) | (uint64_t)kCodeSel << 16 | (uint64_t)(ring3 ? 0xEE00 : 0x8E00) << 32 |
                        (uint64_t)(off >> 16) << 48;
        Write(kIdt + v * 8, &gate, 8);
    }
    Wr8(kCallReturn, Trap());
    Wr8(kCallReturnIret, Trap());
    for (uint32_t i = 0; i < 16; ++i) {                  // what int 21h/35h hands out for IRQ vectors
        Wr8(kBiosIrq + i * 2, Trap());
        Wr8(kBiosIrq + i * 2 + 1, 0xCF);
    }
}

bool Vm::Enter(uint32_t eip, uint32_t esp, std::string& err) {
    if (!cpu_) return err = "no CPU backend", false;
    CpuState& s = cpu_->State();
    s = CpuState{};
    s.seg[(int)Seg::Cs] = SegFromDesc(kCodeSel, Desc(kCodeSel));
    s.seg[(int)Seg::Ds] = s.seg[(int)Seg::Fs] = s.seg[(int)Seg::Gs] = SegFromDesc(kDataSel, Desc(kDataSel));
    s.seg[(int)Seg::Ss] = SegFromDesc(kStackSel, Desc(kStackSel));
    s.seg[(int)Seg::Es] = SegFromDesc(kPspSel, Desc(kPspSel));      // DOS/4GW: PSP selector in ES
    s.gdtBase = gdtBase;
    s.gdtLimit = (uint16_t)(gdtEntries * 8 - 1);
    s.idtBase = kIdt;
    s.idtLimit = 256 * 8 - 1;
    s.cr0 = 0x33;                                        // PE MP ET NE; caches on
    s.cr4 = 0;
    s.efer = 0;
    s.ring3 = ring3;
    s.reg[(int)Reg::Eip] = eip;
    s.reg[(int)Reg::Esp] = esp;
    s.reg[(int)Reg::Eflags] = 0x202;
    cpu_->Touch();
    return true;
}

bool Vm::EnterSegmented(uint16_t cs, uint16_t ip, uint16_t ss, uint16_t sp, uint16_t ds, uint16_t es, std::string& err) {
    if (!Enter(ip, sp, err)) return false;
    CpuState& s = cpu_->State();
    if (ring3) s.reg[(int)Reg::Eflags] = 0x3202;          // IOPL 3, IF
    s.seg[(int)Seg::Cs] = SegFromDesc(cs, Desc(cs));
    s.seg[(int)Seg::Ss] = SegFromDesc(ss, Desc(ss));
    s.seg[(int)Seg::Ds] = SegFromDesc(ds, Desc(ds));
    s.seg[(int)Seg::Es] = SegFromDesc(es, Desc(es));
    s.seg[(int)Seg::Fs] = s.seg[(int)Seg::Gs] = SegState{};   // null
    s.seg[(int)Seg::Fs].unusable = s.seg[(int)Seg::Gs].unusable = true;
    SetDesc(kLdtSel, MakeDesc(gdtBase, gdtEntries * 8 - 1, 0x82, false));   // present, LDT type
    s.ldt = SegFromDesc(kLdtSel, Desc(kLdtSel));
    s.hasLdt = true;
    cpu_->Touch();
    return !ring3 || SetDebug(0, false, err);
}

std::string Vm::CStr(uint32_t a, size_t max) {
    std::string s;
    for (size_t i = 0; i < max; ++i) {
        auto p = Ptr(a + (uint32_t)i);
        if (!p || !*p) break;
        s.push_back((char)*p);
    }
    return s;
}

void Vm::Set(Reg r, uint32_t v) {
    CpuState& s = cpu_->State();
    s.reg[(int)r] = r == Reg::Eflags ? v | 2 : v;
    cpu_->Touch();
}

bool Vm::Is32(Seg s) { return cpu_->State().seg[(int)s].big; }

bool Vm::LoadSeg(Seg s, uint16_t sel) {
    cpu_->State().seg[(int)s] = SegFromDesc(sel, Desc(sel));
    cpu_->Touch();
    return true;
}

void Vm::LoadIdt(uint32_t base, uint16_t limit) {
    CpuState& s = cpu_->State();
    s.idtBase = base;
    s.idtLimit = limit;
    cpu_->Touch();
}

bool Vm::RunOnce(std::string& err) {
    if (!cpu_) return err = "no CPU backend", false;
    return cpu_->RunOnce(err);
}

}  // namespace hlekit
