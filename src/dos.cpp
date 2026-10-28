#include "hlekit/dos.h"

#include "hlekit/machine.h"

#include <algorithm>
#include <map>
#include <ctime>
#include <filesystem>
#include <cstdlib>
#include <iostream>
#include <unistd.h>

namespace hlekit {

namespace fs = std::filesystem;

namespace {
// DOS 2Ch is polled in tight loops. The calendar fields only change once per
// second, while the hundredths below still come from the machine clock.
const tm& LocalTime(time_t t) {
    static thread_local time_t cachedSecond = 0;
    static thread_local tm cached{};
    static thread_local bool valid = false;
    if (!valid || t != cachedSecond) {
        localtime_r(&t, &cached);
        cachedSecond = t;
        valid = true;
    }
    return cached;
}

// The handler a vector had before the game hooked it: for hardware IRQ vectors the BIOS's
// (Vm::kBiosIrq stubs, which do what the BIOS did, e.g. count the tick); otherwise the stub that
// reports the vector to the host.
uint32_t DefaultHandler(uint8_t v) {
    if (v >= 0x08 && v <= 0x0F) return Vm::kBiosIrq + (v - 0x08) * 2;
    if (v >= 0x70 && v <= 0x77) return Vm::kBiosIrq + (v - 0x70 + 8) * 2;
    return Vm::kStubs + v * 2;
}

std::string Lower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

}  // namespace

Dos::Dos(Machine& m) : m_(m), dta_(Vm::kPsp + 0x80), dtaSel_(Vm::kDataSel),
                       dtaOff_(Vm::kPsp + 0x80), nextSel_(Vm::kFirstFreeSel) {}

Dos::~Dos() {
    for (auto& [h, f] : files_) fclose(f);
}

bool Dos::Hooked(uint8_t v, uint32_t& off) const {
    auto it = vectors_.find(v);
    if (it == vectors_.end()) return false;
    off = it->second.linear;
    return true;
}

bool Dos::HookedFar(uint8_t v, uint16_t& sel, uint32_t& off) const {
    auto it = vectors_.find(v);
    if (it == vectors_.end()) return false;
    sel = it->second.sel;
    off = it->second.off;
    return true;
}

void Dos::Ok() { m_.SetFrameFlag(0x1, false); }
void Dos::Fail(uint16_t code) {
    m_.vm.Set16(Reg::Eax, code);
    m_.SetFrameFlag(0x1, true);
}

std::string Dos::GuestPath(uint32_t addr) { return m_.files.GuestRel(addr); }

std::string Dos::Resolve(const std::string& rel, bool forWrite) { return m_.files.Resolve(rel, forWrite); }

uint32_t Dos::Alloc(uint32_t size, uint32_t align) {
    heap_ = (heap_ + align - 1) & ~(align - 1);
    if ((uint64_t)heap_ + size > Vm::kRam) return 0;
    uint32_t a = heap_;
    heap_ += std::max<uint32_t>(size, 16);
    memset(m_.vm.mem + a, 0, size);
    return a;
}

uint16_t Dos::FreeHandle() const {
    // DOS hands out the lowest free entry of the process's handle table (20 by default; C
    // run-times size their own tables on that - Watcom's read() rejects a handle beyond its
    // table before it reaches DOS). 0-4 are the standard devices.
    for (uint16_t h = 5; h < 20; ++h)
        if (!files_.count(h)) return h;
    return 0;
}

bool Dos::DosAlloc(uint16_t paras, uint16_t& seg, uint16_t& largest) {
    const uint32_t size = (uint32_t)paras * 16;
    const uint32_t a = (dosPool_ + 15) & ~15u;
    if (a + size > 0xA0000) { largest = (uint16_t)((0xA0000 - a) >> 4); return false; }
    dosPool_ = a + size;
    memset(m_.vm.mem + a, 0, size);
    seg = (uint16_t)(a >> 4);
    return true;
}

void Dos::RealModeInt(uint8_t v, uint32_t rm) {
    // int 31h/0300h: the real-mode interrupt `v` with the register image at ES:EDI (DPMI 0.9
    // layout: EDI ESI EBP - EBX EDX ECX EAX, then flags ES DS FS GS IP CS SP SS). Answered
    // like the real-mode services the extender's DOS would run - nothing beyond them; unknown
    // functions are counted and return unchanged registers (no handler behind the vector).
    Vm& vm = m_.vm;
    const uint32_t eax = vm.Rd32(rm + 0x1C);
    const uint16_t ax = (uint16_t)eax, bx = vm.Rd16(rm + 0x10);
    const uint8_t ah = (uint8_t)(ax >> 8);
    auto setCf = [&](bool on) { vm.Wr16(rm + 0x20, (uint16_t)((vm.Rd16(rm + 0x20) & ~1u) | (on ? 1 : 0))); };
    char tag[64];
    snprintf(tag, sizeof tag, "int31 0300 int %02x ax %04x", v, v == 0x21 ? ax & 0xFF00 : ax);
    m_.Count(tag);
    Ok();
    if (v == 0x21 && ah == 0x48) {                          // allocate BX paragraphs -> AX segment
        uint16_t seg = 0, largest = 0;
        if (DosAlloc(bx, seg, largest)) { vm.Wr16(rm + 0x1C, seg); setCf(false); }
        else { vm.Wr16(rm + 0x1C, 8); vm.Wr16(rm + 0x10, largest); setCf(true); }
        return;
    }
    if (v == 0x21 && (ah == 0x49 || ah == 0x4A)) { setCf(false); return; }   // free / resize: the pool only grows
    if (v == 0x21 && ah == 0x34) {                          // InDOS flag address: a zero byte, DOS is never busy
        vm.Wr8(0x4F0, 0);
        vm.Wr16(rm + 0x22, 0x004F);                         // ES
        vm.Wr16(rm + 0x10, 0x0000);                         // BX
        return;
    }
    if (v == 0x2F && ax == 0x1500) { vm.Wr16(rm + 0x10, 0); return; }        // MSCDEX: not installed (no CD drive)
    m_.Count("int31 0300: no real-mode handler (registers unchanged)");
}

uint16_t Dos::NewSelector(uint32_t base, uint32_t limit, uint8_t access, bool big) {
    // Segmented programs share the table with their own selector managers: take the next entry
    // nobody uses (access byte 0).
    if (!m_.vm.fillFlat)
        while (nextSel_ < m_.vm.gdtEntries * 8 && ((m_.vm.Desc(nextSel_) >> 40) & 0xFF)) nextSel_ += 8;
    if (nextSel_ >= m_.vm.gdtEntries * 8) return 0;
    uint16_t sel = nextSel_;
    nextSel_ += 8;
    m_.vm.SetDesc(sel, Vm::MakeDesc(base, limit, access, big));
    return sel | m_.vm.Rpl();
}

void Dos::FindFill(uint32_t dta) {
    auto& [list, next] = finds_[dta];
    if (next >= list.size()) return Fail(0x12);                  // no more files
    const Found& f = list[next++];
    Vm& vm = m_.vm;
    vm.Wr8(dta + 0x15, f.dir ? 0x10 : 0x20);
    vm.Wr16(dta + 0x16, 0);
    vm.Wr16(dta + 0x18, (16 << 9) | (12 << 5) | 24);             // 1996-12-24, as the files
    vm.Wr32(dta + 0x1A, f.size);
    std::string up = f.name;
    for (auto& c : up) c = (char)toupper((unsigned char)c);
    char name[13] = {};
    memcpy(name, up.c_str(), std::min<size_t>(up.size(), 12));
    vm.Write(dta + 0x1E, name, 13);
    Ok();
}

// ------------------------------------------------------------------------------------- int 21h
void Dos::Int21() {
    Vm& vm = m_.vm;
    const uint32_t eax = vm.Get(Reg::Eax), ebx = vm.Get(Reg::Ebx), ecx = vm.Get(Reg::Ecx),
                   edx = vm.Get(Reg::Edx);
    const uint8_t ah = (uint8_t)(eax >> 8), al = (uint8_t)eax;
    char tag[32];
    if (ah == 0x2C) {
        m_.Count("int21 2c");
    } else {
        snprintf(tag, sizeof tag, "int21 %02x", ah);
        m_.Count(tag);
    }
    auto log = [&](const std::string& s) { if (m_.logServices) std::cerr << "[dos] " << s << "\n"; };
    // Addresses are DS-relative: DS:EDX for flat 32-bit callers (DS base 0), DS:DX with 16-bit
    // offsets and CX counts for 16-bit (segmented) callers.
    const bool w16 = m_.CallerIs16();
    const uint32_t count = w16 ? (uint16_t)ecx : ecx;
    auto ds = [&](uint32_t off) { return vm.SegBase(Seg::Ds) + (w16 ? (off & 0xFFFF) : off); };

    switch (ah) {
    case 0x30:                                              // DOS version: AL major, AH minor
        vm.Set(Reg::Eax, 0x0005);                           // high word 0: not Phar Lap ('DX')
        return Ok();
    case 0xFF:
        if (al == 0x00 && (uint16_t)edx == 0x0078) {        // DOS/4GW presence check
            vm.Set(Reg::Eax, (eax & ~0xFFu) | 0x01);        // AL != 0: Rational path in cstrt386
            return Ok();
        }
        return Fail(1);
    case 0x4C: {
        m_.Stop("exit(" + std::to_string(al) + ")");
        return;
    }
    case 0x25: {                                            // set vector AL = DS:DX / DS:EDX
        const uint16_t sel = w16 ? vm.GetSeg(Seg::Ds) : Vm::kCodeSel;
        const uint32_t off = w16 ? (uint16_t)edx : edx;
        vectors_[al] = {vm.SelBase(sel) + off, sel, off};
        log("set vector " + std::to_string(al));
        return Ok();
    }
    case 0x35: {                                            // get vector AL -> ES:EBX
        auto it = vectors_.find(al);
        vm.Set(Reg::Ebx, it == vectors_.end() ? DefaultHandler(al) : it->second.off);
        vm.LoadSeg(Seg::Es, it == vectors_.end() ? (uint16_t)(Vm::kCodeSel | vm.Rpl()) : it->second.sel);
        return Ok();
    }
    case 0x62: vm.Set(Reg::Ebx, Vm::kPspSel); return Ok();
    case 0x19: vm.Set(Reg::Eax, (eax & ~0xFFu) | 2); return Ok();         // C:
    case 0x0E: vm.Set(Reg::Eax, (eax & ~0xFFu) | 26); return Ok();
    case 0x3B: log("chdir " + GuestPath(ds(edx))); return Ok();            // chdir
    case 0x39: {                                            // mkdir: overlay only
        const std::string rel = GuestPath(ds(edx));
        std::error_code ec;
        fs::create_directories(fs::path(m_.overlayDir) / Lower(rel), ec);
        log("mkdir " + rel + (ec ? " -> failed" : ""));
        if (ec) return Fail(3);
        return Ok();
    }
    case 0x3A: {                                            // rmdir: overlay only
        const std::string rel = GuestPath(ds(edx));
        std::error_code ec;
        fs::remove(fs::path(m_.overlayDir) / Lower(rel), ec);
        if (ec) return Fail(3);
        return Ok();
    }
    case 0x47: vm.Wr8(ds(vm.Get(Reg::Esi)), 0); return Ok();                   // getcwd: root
    case 0x1A:
        dtaSel_ = vm.GetSeg(Seg::Ds);
        dtaOff_ = w16 ? (uint16_t)edx : edx;
        dta_ = ds(edx);
        dtaSet_ = true;
        return Ok();
    case 0x2F:
        vm.Set(Reg::Ebx, dtaSet_ ? dtaOff_ : w16 ? 0x80 : dtaOff_);
        vm.LoadSeg(Seg::Es, dtaSet_ ? dtaSel_ : w16 ? (uint16_t)(Vm::kPspSel | vm.Rpl()) : dtaSel_);
        return Ok();
    case 0x2A: case 0x2C: {
        timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);                 // one clock for seconds and hundredths
        const time_t t = ts.tv_sec;
        const tm& lt = LocalTime(t);
        if (ah == 0x2A) {
            vm.Set(Reg::Ecx, (uint32_t)(lt.tm_year + 1900));
            vm.Set(Reg::Edx, (uint32_t)((lt.tm_mon + 1) << 8 | lt.tm_mday));
            vm.Set(Reg::Eax, (eax & ~0xFFu) | (uint32_t)lt.tm_wday);
        } else {
            const uint32_t cs = (uint32_t)(ts.tv_nsec / 10000000);
            vm.Set(Reg::Ecx, (uint32_t)(lt.tm_hour << 8 | lt.tm_min));
            vm.Set(Reg::Edx, (uint32_t)(lt.tm_sec << 8) | cs);
        }
        return Ok();
    }
    case 0x48: {                                            // allocate BX paragraphs
        uint32_t a = Alloc((uint32_t)(uint16_t)ebx * 16, 16);
        if (!a) return Fail(8);
        vm.Set(Reg::Eax, a >> 4);
        return Ok();
    }
    case 0x49: case 0x4A: return Ok();
    case 0x3C: case 0x3D: {                                 // create / open DS:EDX
        std::string rel = GuestPath(ds(edx));
        const bool create = ah == 0x3C;
        const bool write = create || (al & 3) != 0;
        if (rel.empty()) return Fail(3);                    // an empty path names nothing (it would resolve to a directory)
        std::string host = Resolve(rel, write);
        FILE* f = host.empty() ? nullptr : fopen(host.c_str(), create ? "w+b" : (write ? "r+b" : "rb"));
        log((create ? "create " : "open ") + rel + (f ? "" : " -> not found"));
        m_.Count(std::string(create ? "create " : "open ") + Lower(rel));
        if (!f) return Fail(create ? 3 : 2);
        const uint16_t h = FreeHandle();
        if (!h) { fclose(f); return Fail(4); }               // too many open files
        files_[h] = f;
        vm.Set(Reg::Eax, h);
        return Ok();
    }
    case 0x3E: {
        auto it = files_.find((uint16_t)ebx);
        if (it == files_.end()) return Fail(6);
        fclose(it->second);
        files_.erase(it);
        return Ok();
    }
    case 0x3F: {                                            // read ECX bytes to DS:EDX
        auto it = files_.find((uint16_t)ebx);
        if ((uint16_t)ebx == 0) { vm.Set(Reg::Eax, 0); return Ok(); }
        if (it == files_.end()) return Fail(6);
        uint8_t* dst = vm.Ptr(ds(edx), count);
        if (!dst) return Fail(5);
        vm.InvalidateCode(ds(edx), count);                  // fread may let the kernel write: unprotect first
        const size_t got = fread(dst, 1, count, it->second);
        if (getenv("HLEKIT_LOG_READS")) {
            uint32_t sum = 0;
            for (size_t k = 0; k < got; ++k) sum = sum * 31 + dst[k];
            long pos = ftell(it->second);
            fprintf(stderr, "[read] h=%u n=%u got=%zu dst=%08x eip=%08x pos=%ld sum=%08x\n", (uint16_t)ebx, count, got,
                    ds(edx), vm.Get(Reg::Eip), pos, sum);
        }
        vm.Set(Reg::Eax, (uint32_t)got);
        return Ok();
    }
    case 0x40: {                                            // write ECX bytes from DS:EDX
        const uint16_t h = (uint16_t)ebx;
        uint8_t* src = vm.Ptr(ds(edx), count);
        if (!src) return Fail(5);
        if (h == 1 || h == 2) {
            fwrite(src, 1, count, stderr);
        } else {
            auto it = files_.find(h);
            if (it == files_.end()) return Fail(6);
            if (count == 0) { fflush(it->second); }
            else fwrite(src, 1, count, it->second);
        }
        vm.Set(Reg::Eax, count);
        return Ok();
    }
    case 0x42: {                                            // seek: CX:DX offset, DX:AX result
        auto it = files_.find((uint16_t)ebx);
        if (it == files_.end()) return Fail(6);
        const int32_t off = (int32_t)(((ecx & 0xFFFF) << 16) | (edx & 0xFFFF));
        const int whence = al == 1 ? SEEK_CUR : al == 2 ? SEEK_END : SEEK_SET;
        if (fseek(it->second, off, whence) != 0) return Fail(0x19);
        const long pos = ftell(it->second);
        if (getenv("HLEKIT_LOG_READS"))
            fprintf(stderr, "[seek] h=%u off=%d wh=%d pos=%ld eip=%08x\n", (uint16_t)ebx, off, whence, pos,
                    vm.Get(Reg::Eip));
        vm.Set(Reg::Eax, (uint32_t)pos & 0xFFFF);
        vm.Set(Reg::Edx, ((uint32_t)pos >> 16) & 0xFFFF);
        return Ok();
    }
    case 0x41: {                                            // delete: overlay copies only
        std::error_code ec;
        fs::remove(fs::path(m_.overlayDir) / Lower(GuestPath(ds(edx))), ec);
        return Ok();
    }
    case 0x56: {                                            // rename DS:EDX -> ES:EDI
        std::string from = Resolve(GuestPath(ds(edx)), true);
        std::string to = (fs::path(m_.overlayDir) / Lower(GuestPath(vm.SegBase(Seg::Es) + (w16 ? (uint16_t)vm.Get(Reg::Edi) : vm.Get(Reg::Edi))))).string();
        std::error_code ec;
        fs::rename(from, to, ec);
        return ec ? Fail(5) : Ok();
    }
    case 0x43: {                                            // get/set attributes
        const std::string guest = GuestPath(ds(edx));
        std::string host = Resolve(guest, false);
        log("attributes " + guest + (host.empty() ? " -> not found" : " -> found"));
        if (host.empty()) return Fail(2);
        if (al == 0) vm.Set(Reg::Ecx, fs::is_directory(host) ? 0x10 : 0x20);
        return Ok();
    }
    case 0x44: {                                            // IOCTL: get device info
        const uint16_t h = (uint16_t)ebx;
        if (al == 0x00) vm.Set(Reg::Edx, h <= 2 ? 0x80D3 : 0x0002);
        else vm.Set(Reg::Eax, 0);
        return Ok();
    }
    case 0x45: {                                            // dup
        auto it = files_.find((uint16_t)ebx);
        if (it == files_.end()) return Fail(6);
        FILE* f = fdopen(dup(fileno(it->second)), "r+b");
        if (!f) f = fdopen(dup(fileno(it->second)), "rb");
        const uint16_t h = FreeHandle();
        if (!h || !f) { if (f) fclose(f); return Fail(4); }
        files_[h] = f;
        vm.Set(Reg::Eax, h);
        return Ok();
    }
    case 0x57: vm.Set(Reg::Ecx, 0); vm.Set(Reg::Edx, (16 << 9) | (12 << 5) | 24); return Ok();
    case 0x36:                                              // disk free: plenty
        vm.Set(Reg::Eax, 8); vm.Set(Reg::Ebx, 0x7FFF); vm.Set(Reg::Ecx, 512); vm.Set(Reg::Edx, 0xFFFF);
        return Ok();
    case 0x4E: case 0x4F: {                                 // find first (DS:EDX, CX attr) / next
        if (ah == 0x4E) {
            std::string pat = GuestPath(ds(edx));
            std::string dir = pat.find('/') == std::string::npos ? "" : pat.substr(0, pat.rfind('/'));
            std::string mask = pat.substr(pat.find('/') == std::string::npos ? 0 : pat.rfind('/') + 1);
            std::vector<Found> list;
            for (auto& e : m_.files.List(dir, mask, ecx & 0x10)) list.push_back({e.name, e.size, e.dir});
            log("findfirst " + pat + " -> " + std::to_string(list.size()));
            finds_[dta_] = {list, 0};
            if (list.empty()) return Fail(2);              // FindFirst: file not found
        }
        return FindFill(dta_);                             // FindNext: no more files (18)
    }
    case 0x0B: vm.Set(Reg::Eax, eax & ~0xFFu); return Ok();               // no key on stdin
    case 0x01: case 0x07: case 0x08: vm.Set(Reg::Eax, (eax & ~0xFFu) | 0x0D); return Ok();
    case 0x02: fputc((char)edx, stderr); return Ok();
    case 0x06:                                                             // direct console
        if ((uint8_t)edx == 0xFF) { m_.SetFrameFlag(0x40, true); vm.Set(Reg::Eax, eax & ~0xFFu); }
        else fputc((char)edx, stderr);
        return Ok();
    case 0x09: {
        std::string s;
        for (uint32_t a = ds(edx); s.size() < 1000; ++a) { char c = (char)vm.Rd8(a); if (c == '$') break; s += c; }
        std::cerr << s;
        return Ok();
    }
    default:
        snprintf(tag, sizeof tag, "int21 UNHANDLED ax=%04x", (uint16_t)eax);
        m_.Count(tag);
        log(tag);
        return Fail(1);
    }
}

// ------------------------------------------------------------------------------------- int 31h
void Dos::Int31() {
    Vm& vm = m_.vm;
    const uint32_t eax = vm.Get(Reg::Eax), ebx = vm.Get(Reg::Ebx), ecx = vm.Get(Reg::Ecx),
                   edx = vm.Get(Reg::Edx), esi = vm.Get(Reg::Esi), edi = vm.Get(Reg::Edi);
    const uint16_t ax = (uint16_t)eax, bx = (uint16_t)ebx, cx = (uint16_t)ecx, dx = (uint16_t)edx;
    char tag[40];
    snprintf(tag, sizeof tag, "int31 %04x", ax);
    m_.Count(tag);
    auto mine = [&](uint16_t sel) { return sel >= Vm::kFirstFreeSel; };   // never touch the fixed ones
    auto esEdi = [&]() { return vm.SegBase(Seg::Es) + edi; };

    switch (ax) {
    case 0x0000: {                                          // allocate CX descriptors
        uint16_t first = 0;
        for (uint16_t i = 0; i < std::max<uint16_t>(cx, 1); ++i) {
            uint16_t s = NewSelector(0, 0xFFFFFFFF);
            if (!s) return Fail(0x8011);
            if (!first) first = s;
        }
        vm.Set16(Reg::Eax, first);
        return Ok();
    }
    case 0x0001: return Ok();
    case 0x0002: {                                          // real-mode segment -> descriptor
        uint16_t s = NewSelector((uint32_t)bx << 4, 0xFFFF);
        if (!s) return Fail(0x8011);
        vm.Set16(Reg::Eax, s);
        return Ok();
    }
    case 0x0003: vm.Set16(Reg::Eax, 8); return Ok();
    case 0x0006: {                                          // get base -> CX:DX
        uint32_t base = vm.SelBase(bx);
        vm.Set16(Reg::Ecx, (uint16_t)(base >> 16));
        vm.Set16(Reg::Edx, (uint16_t)base);
        return Ok();
    }
    case 0x0007: case 0x0008: case 0x0009: {
        if (!mine(bx)) { m_.Count("int31 refused change of fixed selector"); return Ok(); }
        uint64_t d = vm.Desc(bx);
        uint32_t base = Vm::DescBase(d), limit = Vm::DescLimit(d);
        uint8_t access = (uint8_t)(d >> 40);
        if (ax == 0x0007) base = (uint32_t)cx << 16 | dx;
        if (ax == 0x0008) limit = (uint32_t)cx << 16 | dx;
        if (ax == 0x0009) access = (uint8_t)cx | 0x60;      // DPL 3
        if (!vm.ring3 && (access & 0x18) == 0x18) access &= ~0x60;   // code is entered by far call from ring 0: DPL 0
        vm.SetDesc(bx, Vm::MakeDesc(base, limit, access, true));
        return Ok();
    }
    case 0x000A: {                                          // alias (data copy of BX)
        uint64_t d = vm.Desc(bx);
        uint16_t s = NewSelector(Vm::DescBase(d), Vm::DescLimit(d));
        if (!s) return Fail(0x8011);
        vm.Set16(Reg::Eax, s);
        return Ok();
    }
    case 0x000B: { uint64_t d = vm.Desc(bx); vm.Write(esEdi(), &d, 8); return Ok(); }
    case 0x000C: {
        if (!mine(bx)) { m_.Count("int31 refused change of fixed selector"); return Ok(); }
        uint64_t d = 0;
        memcpy(&d, vm.Ptr(esEdi(), 8), 8);
        if (!vm.ring3 && ((d >> 40) & 0x18) == 0x18) d &= ~(3ull << 45);   // code: DPL 0, see 0009h
        vm.SetDesc(bx, d);
        return Ok();
    }
    case 0x0100: {                                          // DOS memory: BX paras -> AX seg, DX sel
        uint16_t seg = 0, largest = 0;
        if (!DosAlloc(bx, seg, largest)) { vm.Set16(Reg::Ebx, largest); return Fail(8); }
        const uint32_t size = (uint32_t)bx * 16;
        uint16_t s = NewSelector((uint32_t)seg << 4, size ? size - 1 : 0);
        vm.Set16(Reg::Eax, seg);
        vm.Set16(Reg::Edx, s);
        return Ok();
    }
    case 0x0101: case 0x0102: return Ok();
    case 0x0200: vm.Set16(Reg::Ecx, 0); vm.Set16(Reg::Edx, 0); return Ok();
    case 0x0201: case 0x0203: return Ok();
    case 0x0202: case 0x0204: {                             // get exception / PM vector BL
        auto it = vectors_.find((uint8_t)bx);
        const bool hooked = ax == 0x0204 && it != vectors_.end();
        vm.Set16(Reg::Ecx, hooked ? it->second.sel : (uint16_t)(Vm::kCodeSel | vm.Rpl()));
        vm.Set(Reg::Edx, hooked ? it->second.off : ax == 0x0204 ? DefaultHandler((uint8_t)bx) : Vm::kStubs + (uint8_t)bx * 2);
        return Ok();
    }
    case 0x0205: {
        const uint16_t sel = m_.segmented ? cx : Vm::kCodeSel;
        const uint32_t off = m_.segmented ? dx : edx;
        vectors_[(uint8_t)bx] = {vm.SelBase(sel) + off, sel, off};
        return Ok();
    }
    case 0x0300: return RealModeInt((uint8_t)bx, esEdi());
    case 0x0301: case 0x0302:
        m_.Count("int31 real-mode far call (not run)");
        return Ok();
    case 0x0303: vm.Set16(Reg::Ecx, 0); vm.Set16(Reg::Edx, 0); return Ok();
    case 0x0400:                                            // version 0.90, 32-bit, 486
        vm.Set16(Reg::Eax, 0x005A); vm.Set16(Reg::Ebx, 0x0005); vm.Set16(Reg::Ecx, 4); vm.Set16(Reg::Edx, 0x0870);
        return Ok();
    case 0x0500: {                                          // free memory info at ES:EDI
        uint32_t freeBytes = Vm::kRam - heap_, pages = freeBytes >> 12;
        uint32_t info[12] = {freeBytes, pages, pages, Vm::kRam >> 12, pages, pages, Vm::kRam >> 12,
                             0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0};
        vm.Write(esEdi(), info, sizeof info);
        return Ok();
    }
    case 0x0501: case 0x0503: {                             // alloc / resize: BX:CX size
        uint32_t size = (uint32_t)bx << 16 | cx;
        uint32_t a = Alloc(size, 0x1000);
        if (!a) return Fail(0x8012);
        if (ax == 0x0503) {
            auto it = blocks_.find((uint32_t)(uint16_t)esi << 16 | (uint16_t)edi);
            if (it != blocks_.end()) {
                memcpy(vm.mem + a, vm.mem + it->second.first, std::min(size, it->second.second));
                blocks_.erase(it);
            }
        }
        blocks_[a] = {a, size};
        vm.Set16(Reg::Ebx, (uint16_t)(a >> 16)); vm.Set16(Reg::Ecx, (uint16_t)a);
        vm.Set16(Reg::Esi, (uint16_t)(a >> 16)); vm.Set16(Reg::Edi, (uint16_t)a);
        return Ok();
    }
    case 0x0502: blocks_.erase((uint32_t)(uint16_t)esi << 16 | (uint16_t)edi); return Ok();
    case 0x0600: case 0x0601: case 0x0E01: return Ok();
    case 0x0800: return Ok();                               // physical -> linear: identity
    case 0x0900: case 0x0901: case 0x0902: vm.Set(Reg::Eax, (eax & ~0xFFu) | 1); return Ok();
    case 0x0E00: vm.Set16(Reg::Eax, 0x0045); return Ok(); // FPU present, 387
    default:
        snprintf(tag, sizeof tag, "int31 UNHANDLED ax=%04x", ax);
        m_.Count(tag);
        return Fail(0x8001);
    }
}

// ------------------------------------------------------------------------------------- int 10h
void Dos::Int10() {
    Vm& vm = m_.vm;
    const uint32_t eax = vm.Get(Reg::Eax);
    const uint8_t ah = (uint8_t)(eax >> 8), al = (uint8_t)eax;
    char tag[32];
    snprintf(tag, sizeof tag, ah == 0 ? "int10 mode %02x" : "int10 ah=%02x", ah == 0 ? al : ah);
    m_.Count(tag);
    switch (ah) {
    case 0x00:                                              // set mode
        m_.videoMode = al & 0x7F;
        if ((al & 0x7F) == 0x13 && !(al & 0x80)) memset(vm.mem + 0xA0000, 0, 64000);
        return;
    case 0x0F:
        vm.Set(Reg::Eax, (eax & 0xFFFF0000u) | (m_.videoMode == 0x13 ? 40 : 80) << 8 | (uint32_t)m_.videoMode);
        vm.Set16(Reg::Ebx, 0);
        return;
    case 0x10:
        if (al == 0x10 || al == 0x12) {                     // set one / a block of DAC registers
            std::lock_guard<std::mutex> lock(m_.paletteMutex);
            if (al == 0x10) {
                uint8_t i = (uint8_t)vm.Get(Reg::Ebx);
                uint32_t ecx = vm.Get(Reg::Ecx), edx = vm.Get(Reg::Edx);
                m_.palette[i * 3] = (edx >> 8) & 0x3F;
                m_.palette[i * 3 + 1] = (ecx >> 8) & 0x3F;
                m_.palette[i * 3 + 2] = ecx & 0x3F;
            } else {
                uint32_t start = vm.Get16(Reg::Ebx), n = vm.Get16(Reg::Ecx);
                uint32_t src = vm.SegBase(Seg::Es) + vm.Get(Reg::Edx);
                for (uint32_t i = 0; i < n * 3 && start * 3 + i < 768; ++i) m_.palette[start * 3 + i] = vm.Rd8(src + i) & 0x3F;
            }
        }
        return;
    case 0x12:                                              // alternate select
        if ((uint8_t)vm.Get(Reg::Ebx) == 0x10) {            // EGA/VGA information: colour, 256K
            vm.Set16(Reg::Ebx, 0x0003);
            vm.Set16(Reg::Ecx, 0x0009);
        }
        return;
    case 0x1A:                                              // display combination: VGA, analog colour
        vm.Set16(Reg::Eax, 0x001A);
        vm.Set16(Reg::Ebx, 0x0008);
        return;
    case 0x4F:                                              // VBE: the BIOS answers for a linear-framebuffer-less card
        switch (al) {
        case 0x02: m_.videoMode = (uint32_t)vm.Get16(Reg::Ebx) & 0x1FF; break;   // set mode
        case 0x05: {                                         // window (bank) select: answered, but reported:
            static bool told = false;                        // the writes that follow go to the VGA window,
            if (!told) {                                     // which nothing shows - an unseamed screen copy
                told = true;
                std::cerr << "[hw] unseamed banked screen write: VBE window select (int 10h/4F05h) from "
                          << m_.labels.Of(m_.vm.Rd32(m_.StackAddr(12))) << "\n";
            }
            m_.Count("int10 vbe 4f05 (banked write, not seamed)");
            break;
        }
        case 0x07: break;                                    // display start: accepted
        default: vm.Set16(Reg::Eax, 0x014F); return;         // info calls: not supported
        }
        vm.Set16(Reg::Eax, 0x004F);                         // AL = function supported, AH = success
        return;
    default: return;
    }
}

}  // namespace hlekit
