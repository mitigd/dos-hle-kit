#include "hlekit/phar286.h"

#include "hlekit/dos.h"
#include "hlekit/machine.h"

#include <cstring>
#include <iterator>
#include <map>

namespace hlekit {

namespace {

// Every segment gets a 64 KB slot of linear memory: DosReallocSeg only moves the limit, never
// the base (BioForge resizes the segment it is using as SS).
constexpr uint32_t kSlot = 0x10000;
constexpr uint16_t kHugeShift = 3;                  // consecutive selectors: increment 8 = 1 << 3

struct Block { uint32_t base, cap; };
std::map<uint16_t, Block> g_blocks;                 // selector -> its linear slot
struct HugeBlock { uint16_t first, maxSegs; };
std::map<uint16_t, HugeBlock> g_huge;
struct FarPtr { uint16_t sel = 0, off = 0; };

// DosAllocLinMem / DosFreeLinMem: a first-fit arena with real frees (BioForge probes how much it
// can get, frees it all, then allocates its fragments). Carved from the kit's heap once.
constexpr uint32_t kLinArena = 24u << 20;
struct LinArena {
    uint32_t start = 0;
    std::map<uint32_t, uint32_t> free, used;              // base -> size
    bool Init(Machine& m) {
        if (start) return true;
        start = m.dos->Alloc(kLinArena, 4096);
        if (!start) return false;
        free[start] = kLinArena;
        return true;
    }
    uint32_t Alloc(uint32_t size) {
        size = (size + 4095) & ~4095u;
        for (auto it = free.begin(); it != free.end(); ++it)
            if (it->second >= size) {
                const uint32_t base = it->first, rest = it->second - size;
                free.erase(it);
                if (rest) free[base + size] = rest;
                used[base] = size;
                return base;
            }
        return 0;
    }
    bool Free(uint32_t base) {
        auto u = used.find(base);
        if (u == used.end()) return false;
        uint32_t b = base, s = u->second;
        used.erase(u);
        auto next = free.lower_bound(b);
        if (next != free.end() && b + s == next->first) { s += next->second; next = free.erase(next); }
        if (next != free.begin()) {
            auto prev = std::prev(next);
            if (prev->first + prev->second == b) { b = prev->first; s += prev->second; free.erase(prev); }
        }
        free[b] = s;
        return true;
    }
} g_lin;
std::map<uint16_t, FarPtr> g_excHandlers, g_pmVectors;

// Arguments of a pascal far function, read from the last parameter (lowest address) upwards.
struct Args {
    Machine& m;
    int i = 0;
    uint16_t W() { return m.ArgW(i++); }
    uint32_t D() { const uint32_t lo = W(); return lo | (uint32_t)W() << 16; }
    uint32_t P() { const uint16_t off = W(); return m.vm.SelBase(W()) + off; }     // far pointer, linear
    FarPtr F() { FarPtr f; f.off = W(); f.sel = W(); return f; }
};

void Ret(Machine& m, uint16_t ax) { m.vm.Set16(Reg::Eax, ax); }

// DPL 3: the program ORs RPL 3 onto selectors (Phar Lap 286 runs it at ring 3)
uint16_t Data16(Machine& m, uint32_t base, uint32_t limit) { return m.dos->NewSelector(base, limit, 0xF3, false); }

// Reload any segment register holding `sel` (its descriptor changed under it).
void Refresh(Machine& m, uint16_t sel) {
    for (Seg s : {Seg::Ds, Seg::Es, Seg::Fs, Seg::Gs, Seg::Ss})
        if ((m.vm.GetSeg(s) & ~7u) == (sel & ~7u) && m.vm.GetSeg(s) >= 8) m.vm.LoadSeg(s, m.vm.GetSeg(s));
}

Block* BlockOf(Machine& m, uint16_t sel) {
    auto it = g_blocks.find(sel & ~7u);
    if (it != g_blocks.end()) return &it->second;
    for (auto& g : m.neSegs)                          // the program's own segments: 64 KB slots
        if ((g.sel & ~7u) == (sel & ~7u)) return &(g_blocks[sel & ~7u] = {g.base, kSlot});
    return nullptr;
}

uint16_t NewSegment(Machine& m, uint32_t size) {
    const uint32_t base = m.dos->Alloc(kSlot, 16);
    if (!base) return 0;
    const uint16_t sel = Data16(m, base, (size ? size : 0x10000) - 1);
    if (sel) g_blocks[sel & ~7u] = {base, kSlot};
    return sel;
}

void SetLimit(Machine& m, uint16_t sel, uint32_t size) {
    uint64_t d = m.vm.Desc(sel);
    const uint32_t base = Vm::DescBase(d);
    const uint8_t access = (uint8_t)(d >> 40);
    m.vm.SetDesc(sel, Vm::MakeDesc(base, (size ? size : 0x10000) - 1, access, false));
    Refresh(m, sel);
}

void Imp(Machine& m, const char* key, uint16_t pop, std::function<void(Machine&)> fn) {
    Machine::ImportImpl i;
    i.fn = std::move(fn);
    i.pop = pop;
    m.importImpls[key] = i;
}

}  // namespace

void RegisterPharLap286(Machine& m) {
    // ---- DOSCALLS (OS/2 1.x ordinals; pascal; AX = 0 or an error code). Signatures checked
    // against BioForge's call sites (pushes before each `call far`).
    Machine::ImportImpl ahshift;                       // DOSCALLS.135 = __AHSHIFT, a value
    ahshift.value = true;
    ahshift.valueOff = kHugeShift;
    m.importImpls["DOSCALLS.135"] = ahshift;

    Imp(m, "DOSCALLS.7", 6, [](Machine& m) {           // DosExitList(USHORT fn, PFNEXITLIST)
        Args a{m};
        a.F();
        m.Count("DosExitList " + std::to_string(a.W()));
        Ret(m, 0);
    });
    Imp(m, "DOSCALLS.34", 8, [](Machine& m) {          // DosAllocSeg(USHORT size, PSEL, USHORT flags)
        Args a{m};
        a.W();
        const uint32_t psel = a.P();
        const uint16_t sel = NewSegment(m, a.W());
        if (!sel) return Ret(m, 8);
        m.vm.Wr16(psel, sel);
        Ret(m, 0);
    });
    Imp(m, "DOSCALLS.38", 4, [](Machine& m) {          // DosReallocSeg(USHORT size, SEL)
        Args a{m};
        const uint16_t sel = a.W();
        const uint32_t size = a.W();
        Block* b = BlockOf(m, sel);
        if (!b) return Ret(m, 5);
        SetLimit(m, sel, size);
        Ret(m, 0);
    });
    Imp(m, "DOSCALLS.39", 2, [](Machine& m) {          // DosFreeSeg(SEL)
        Args a{m};
        g_blocks.erase(a.W() & ~7u);                   // slots are not reused
        Ret(m, 0);
    });
    Imp(m, "DOSCALLS.40", 12, [](Machine& m) {         // DosAllocHuge(cSegs, cbPartial, PSEL, cMaxSegs, flags)
        Args a{m};
        a.W();
        uint16_t maxSegs = a.W();
        const uint32_t psel = a.P();
        const uint16_t partial = a.W(), segs = a.W();
        const uint16_t n = (uint16_t)(segs + (partial ? 1 : 0));
        if (maxSegs < n) maxSegs = n;
        const uint32_t base = m.dos->Alloc((uint32_t)maxSegs * kSlot, 16);
        if (!base || !n) return Ret(m, 8);
        uint16_t first = 0;
        for (uint16_t k = 0; k < maxSegs; ++k) {          // reserve the selectors for growth
            const uint32_t size = k < segs ? 0x10000 : (k == segs && partial ? partial : 1);
            const uint16_t sel = Data16(m, base + k * kSlot, size - 1);
            if (!sel) return Ret(m, 8);
            if (!first) first = sel;
            g_blocks[sel & ~7u] = {base + k * kSlot, kSlot};
        }
        g_huge[first & ~7u] = {first, maxSegs};
        m.vm.Wr16(psel, first);
        Ret(m, 0);
    });
    Imp(m, "DOSCALLS.41", 4, [](Machine& m) {          // DosGetHugeShift(PUSHORT)
        Args a{m};
        m.vm.Wr16(a.P(), kHugeShift);
        Ret(m, 0);
    });
    Imp(m, "DOSCALLS.42", 6, [](Machine& m) {          // DosReallocHuge(cSegs, cbPartial, SEL)
        Args a{m};
        const uint16_t sel = a.W(), partial = a.W(), segs = a.W();
        auto it = g_huge.find(sel & ~7u);
        const uint16_t n = (uint16_t)(segs + (partial ? 1 : 0));
        if (it == g_huge.end() || n > it->second.maxSegs) return Ret(m, 8);
        for (uint16_t k = 0; k < it->second.maxSegs; ++k)
            SetLimit(m, (uint16_t)(it->second.first + 8 * k), k < segs ? 0x10000 : (k == segs && partial ? partial : 1));
        Ret(m, 0);
    });
    Imp(m, "DOSCALLS.43", 6, [](Machine& m) {          // DosCreateCSAlias(SEL ds, PSEL cs)
        Args a{m};
        const uint32_t pcs = a.P();
        const uint64_t d = m.vm.Desc(a.W());
        m.vm.Wr16(pcs, m.dos->NewSelector(Vm::DescBase(d), Vm::DescLimit(d), 0xFB, false));
        Ret(m, 0);
    });
    Imp(m, "DOSCALLS.89", 10, [](Machine& m) {         // DosSetVec(USHORT vec, PFN, PPFN prev)
        Args a{m};
        const uint32_t prev = a.P();
        const FarPtr h = a.F();
        const uint16_t vec = a.W();
        m.vm.Wr32(prev, (uint32_t)g_excHandlers[vec].sel << 16 | g_excHandlers[vec].off);
        g_excHandlers[vec] = h;
        m.Count("DosSetVec " + std::to_string(vec));
        Ret(m, 0);
    });

    // ---- PHAPI (Phar Lap 286 API; pascal unless the name starts with '_')
    Imp(m, "PHAPI.DOSCREATEDSALIAS", 6, [](Machine& m) {   // DosCreateDSAlias(SEL cs, PSEL ds)
        Args a{m};
        const uint32_t pds = a.P();
        const uint64_t d = m.vm.Desc(a.W());
        m.vm.Wr16(pds, Data16(m, Vm::DescBase(d), Vm::DescLimit(d)));
        Ret(m, 0);
    });
    Imp(m, "PHAPI.DOSALLOCREALSEG", 12, [](Machine& m) {   // DosAllocRealSeg(ULONG size, PUSHORT para, PSEL)
        Args a{m};
        const uint32_t psel = a.P(), ppara = a.P(), size = a.D();
        uint16_t seg = 0, largest = 0;
        if (!m.dos->DosAlloc((uint16_t)((size + 15) / 16), seg, largest)) return Ret(m, 8);
        m.vm.Wr16(ppara, seg);
        m.vm.Wr16(psel, Data16(m, (uint32_t)seg << 4, size ? size - 1 : 0));
        Ret(m, 0);
    });
    Imp(m, "PHAPI.DOSMAPREALSEG", 10, [](Machine& m) {     // DosMapRealSeg(USHORT para, ULONG size, PSEL)
        Args a{m};
        const uint32_t psel = a.P(), size = a.D();
        const uint16_t para = a.W();
        m.vm.Wr16(psel, Data16(m, (uint32_t)para << 4, size ? size - 1 : 0));
        Ret(m, 0);
    });
    Imp(m, "PHAPI.DOSMAPLINSEG", 12, [](Machine& m) {      // DosMapLinSeg(ULONG lin, ULONG size, PSEL)
        Args a{m};
        const uint32_t psel = a.P(), size = a.D(), lin = a.D();
        m.vm.Wr16(psel, Data16(m, lin, size ? size - 1 : 0));
        Ret(m, 0);
    });
    Imp(m, "PHAPI.DOSALLOCLINMEM", 8, [](Machine& m) {     // DosAllocLinMem(ULONG size, PULONG lin)
        Args a{m};
        const uint32_t plin = a.P(), size = a.D();
        const uint32_t lin = g_lin.Init(m) ? g_lin.Alloc(size) : 0;
        if (!lin) return Ret(m, 8);
        memset(m.vm.Ptr(lin, size), 0, size);
        m.vm.Wr32(plin, lin);
        Ret(m, 0);
    });
    Imp(m, "PHAPI.DOSFREELINMEM", 4, [](Machine& m) {      // DosFreeLinMem(ULONG lin)
        Args a{m};
        Ret(m, g_lin.Free(a.D()) ? 0 : 5);
    });
    Imp(m, "PHAPI.DOSGETBIOSSEG", 4, [](Machine& m) {      // DosGetBIOSSeg(PSEL): 0040h
        Args a{m};
        m.vm.Wr16(a.P(), Data16(m, 0x400, 0xFF));
        Ret(m, 0);
    });
    Imp(m, "PHAPI.DOSSETEXCEPTIONHANDLER", 10, [](Machine& m) {   // (USHORT exc, PEHANDLER, PEHANDLER far* prev)
        Args a{m};
        const uint32_t prev = a.P();
        const FarPtr h = a.F();
        const uint16_t exc = a.W();
        m.vm.Wr32(prev, (uint32_t)g_excHandlers[exc].sel << 16 | g_excHandlers[exc].off);
        g_excHandlers[exc] = h;
        m.Count("DosSetExceptionHandler " + std::to_string(exc));
        Ret(m, 0);
    });
    Imp(m, "PHAPI.DOSSETREALPROTVEC", 18, [](Machine& m) {    // (vec, PIHANDLER pm, REALPTR rm, PIHANDLER* prevPm, REALPTR* prevRm)
        Args a{m};
        const uint32_t prevRm = a.P(), prevPm = a.P();
        a.D();
        const FarPtr pm = a.F();
        const uint16_t vec = a.W();
        m.vm.Wr32(prevPm, (uint32_t)g_pmVectors[vec].sel << 16 | g_pmVectors[vec].off);
        m.vm.Wr32(prevRm, 0);
        g_pmVectors[vec] = pm;
        m.Count("DosSetRealProtVec " + std::to_string(vec));
        Ret(m, 0);
    });
    Imp(m, "PHAPI.DOSSETPASSTOPROTVEC", 14, [](Machine& m) {  // (vec, PIHANDLER pm, PIHANDLER* prevPm, REALPTR* prevRm)
        Args a{m};
        const uint32_t prevRm = a.P(), prevPm = a.P();
        const FarPtr pm = a.F();
        const uint16_t vec = a.W();
        m.vm.Wr32(prevPm, (uint32_t)g_pmVectors[vec].sel << 16 | g_pmVectors[vec].off);
        m.vm.Wr32(prevRm, 0);
        g_pmVectors[vec] = pm;
        m.Count("DosSetPassToProtVec " + std::to_string(vec));
        Ret(m, 0);
    });
    Imp(m, "PHAPI.BORISREALINTR", 4, [](Machine& m) {      // BorIsRealIntr(far *): never from real mode here
        Ret(m, 0);
    });
    // _DosRealIntr(int intno, REGS16 far* regs, ULONG reserved, int nwords) - cdecl, caller pops.
    // REGS16 (from BioForge's use): es, ds, di, si, bp, sp, bx, dx, cx, ax (words, +0 .. +12h).
    // Translated to the DPMI real-mode register image the kit answers for int 31h/0300h.
    Imp(m, "PHAPI._DosRealIntr", 0, [](Machine& m) {
        Args a{m};
        const uint16_t intno = a.W();
        const uint32_t regs = a.P();
        constexpr uint32_t rm = Vm::kScratch;               // 50-byte DPMI image
        Vm& vm = m.vm;
        uint8_t zero[0x32] = {};
        vm.Write(rm, zero, sizeof zero);
        auto r16 = [&](uint32_t o) { return vm.Rd16(regs + o); };
        vm.Wr16(rm + 0x22, r16(0x00));                      // es
        vm.Wr16(rm + 0x24, r16(0x02));                      // ds
        vm.Wr16(rm + 0x00, r16(0x04));                      // di
        vm.Wr16(rm + 0x04, r16(0x06));                      // si
        vm.Wr16(rm + 0x08, r16(0x08));                      // bp
        vm.Wr16(rm + 0x10, r16(0x0C));                      // bx
        vm.Wr16(rm + 0x14, r16(0x0E));                      // dx
        vm.Wr16(rm + 0x18, r16(0x10));                      // cx
        vm.Wr16(rm + 0x1C, r16(0x12));                      // ax
        m.dos->RealModeInt((uint8_t)intno, rm);
        auto w16 = [&](uint32_t o, uint32_t from) { vm.Wr16(regs + o, vm.Rd16(rm + from)); };
        w16(0x00, 0x22); w16(0x02, 0x24); w16(0x04, 0x00); w16(0x06, 0x04); w16(0x08, 0x08);
        w16(0x0C, 0x10); w16(0x0E, 0x14); w16(0x10, 0x18); w16(0x12, 0x1C);
        Ret(m, 0);
    });
}

}  // namespace hlekit
