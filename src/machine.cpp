#include "hlekit/machine.h"

#include <Zydis/Zydis.h>

#include "hlekit/dos.h"
#include "hlekit/le.h"
#include "hlekit/ne.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>

namespace hlekit {

namespace {
uint32_t RegOf(const CpuState& s, Reg r) { return s.reg[(int)r]; }

std::string Trim(std::string s) {
    const auto ws = [](unsigned char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!s.empty() && ws((unsigned char)s.front())) s.erase(s.begin());
    while (!s.empty() && ws((unsigned char)s.back())) s.pop_back();
    return s;
}

// Minimal CSV split: quoted fields, doubled quotes, commas inside quotes.
std::vector<std::string> SplitCsv(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    bool quoted = false;
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '"') {
            if (quoted && i + 1 < line.size() && line[i + 1] == '"') { cur.push_back('"'); ++i; }
            else quoted = !quoted;
        } else if (c == ',' && !quoted) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}
}  // namespace

// ------------------------------------------------------------------------------------- labels
bool Labels::Load(const std::string& csvPath) {
    std::ifstream in(csvPath);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto fields = SplitCsv(line);
        if (fields.size() < 2) continue;
        const std::string addrText = Trim(fields[0]);
        char* end = nullptr;
        const unsigned long addr = std::strtoul(addrText.c_str(), &end, 16);
        if (addrText.empty() || end == addrText.c_str() || *end) continue;   // header or comment
        unsigned long size = 0;
        if (fields.size() > 2) {
            const std::string sizeText = Trim(fields[2]);
            char* sizeEnd = nullptr;
            size = std::strtoul(sizeText.c_str(), &sizeEnd, 0);
            if (sizeText.empty() || sizeEnd == sizeText.c_str() || *sizeEnd) size = 0;
        }
        funcs_.push_back({(uint32_t)addr, (uint32_t)size, Trim(fields[1])});
    }
    std::sort(funcs_.begin(), funcs_.end(), [](const F& a, const F& b) { return a.addr < b.addr; });
    return !funcs_.empty();
}

void Labels::Remap(const std::function<uint32_t(uint32_t)>& to) {
    for (auto& f : funcs_) f.addr = to(f.addr);
    Sort();
}

void Labels::Add(uint32_t addr, uint32_t size, const std::string& name) { funcs_.push_back({addr, size, name}); }

void Labels::Sort() {
    std::sort(funcs_.begin(), funcs_.end(), [](const F& a, const F& b) { return a.addr < b.addr; });
    for (size_t i = 0; i + 1 < funcs_.size(); ++i)                    // size 0 = up to the next label
        if (!funcs_[i].size) funcs_[i].size = std::min<uint32_t>(funcs_[i + 1].addr - funcs_[i].addr, 0x10000);
}

std::string Labels::Of(uint32_t addr) const {
    char buf[96];
    auto it = std::upper_bound(funcs_.begin(), funcs_.end(), addr, [](uint32_t a, const F& f) { return a < f.addr; });
    if (it != funcs_.begin()) {
        --it;
        if (addr < it->addr + std::max<uint32_t>(it->size, 1)) {
            snprintf(buf, sizeof buf, "%s+%x", it->name.c_str(), addr - it->addr);
            return buf;
        }
    }
    snprintf(buf, sizeof buf, "%08x", addr);
    return buf;
}

// ------------------------------------------------------------------------------------- machine
Machine::Machine() : dos(std::make_unique<Dos>(*this)), t0(std::chrono::steady_clock::now()) {}

Machine::~Machine() {
    StopSound();
    if (ticker_.joinable()) ticker_.join();
}

double Machine::Seconds() const {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

bool Machine::IsCode(uint32_t addr) const {
    for (auto& r : regions)
        if ((r.flags & 4) && addr >= r.base && addr < r.base + r.size) return true;
    return false;
}

uint32_t Machine::Data(uint32_t linkAddr) const {
    for (auto& r : regions)
        if (linkAddr >= r.linkBase && linkAddr - r.linkBase < r.size) return r.base + (linkAddr - r.linkBase);
    return linkAddr;
}

uint32_t Machine::Link(uint32_t guestAddr) const {
    for (auto& r : regions)
        if (guestAddr >= r.base && guestAddr - r.base < r.size) return r.linkBase + (guestAddr - r.base);
    return guestAddr;
}

bool Machine::Load(const std::string& path, std::string& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return err = "cannot open " + path, false;
    char magic[8] = {};
    in.read(magic, 8);
    regions.clear();
    const bool mz = magic[0] == 'M' && magic[1] == 'Z';
    {
        // NE (16-bit segmented): MZ with an "NE" header at [3Ch]
        uint32_t ne = 0;
        char sig[2] = {};
        in.seekg(0x3C);
        in.read((char*)&ne, 4);
        in.seekg(ne);
        in.read(sig, 2);
        in.clear();
        in.seekg(8);
        if (mz && sig[0] == 'N' && sig[1] == 'E') return LoadNe(path, err);
        if (mz && sig[0] == 'P' && sig[1] == 'E') return err = path + ": PE (Windows) executable, not a DOS program", false;
    }
    std::string ext = path.size() > 4 ? path.substr(path.size() - 4) : "";
    for (auto& c : ext) c = (char)tolower((unsigned char)c);
    if (ext == ".com" && !mz) return err = path + ": COM (real-mode) executable; runtime COM execution is not implemented yet (analysis: tools/analysis/find_seams.py)", false;
    const bool v2 = memcmp(magic, "AHLEIMG2", 8) == 0;
    if (!v2 && memcmp(magic, "AHLEIMG1", 8) != 0) {
        LeImage img;
        if (!LoadLe(path, Vm::kCodeSel, Vm::kDataSel, img, err, loadHigh)) {
            if (mz) err = path + ": plain MZ (real-mode) executable; runtime MZ execution is not implemented yet (analysis: tools/analysis/find_seams.py)";
            return false;
        }
        for (auto& r : img.regions) {
            if (!vm.Write(r.base, r.data.data(), (uint32_t)r.data.size())) return err = "LE object outside guest RAM", false;
            regions.push_back({r.base, (uint32_t)r.data.size(), r.flags, r.linkBase});
        }
        entry = img.entry;
        stack = img.stack;
        fixups = img.fixups;
        if (img.unsupported) Count("le: unsupported fixups " + std::to_string(img.unsupported));
        return Placed(err);
    }
    uint32_t hdr[3];
    in.read((char*)hdr, sizeof hdr);
    if (!in) return err = path + ": truncated image", false;
    entry = hdr[0];
    stack = hdr[1];
    for (uint32_t i = 0; i < hdr[2]; ++i) {
        uint32_t r[4];
        in.read((char*)r, v2 ? 16 : 12);
        if (!v2) r[3] = r[0];
        uint8_t* dst = vm.Ptr(r[0], r[1]);
        if (!in || !dst) return err = "bad region in image", false;
        in.read((char*)dst, r[1]);
        regions.push_back({r[0], r[1], r[2], r[3]});
    }
    return Placed(err);
}

bool Machine::Placed(std::string& err) {
    // The extender's memory around the image: conventional memory (int 31h/0100h) after the
    // objects below the A0000h hole, DPMI / DOS 48h memory after everything.
    uint32_t low = loadHigh ? 0x10000 : 0x70000, high = 0x100000;
    for (auto& r : regions) {
        const uint32_t end = (r.base + r.size + 0xFFF) & ~0xFFFu;
        if (r.base < kLeHoleStart && end > kLeHoleStart) return err = "object across A0000h after loading", false;
        if (r.base < kLeHoleStart) low = std::max(low, end);
        else high = std::max(high, end + 0x10000);          // a gap: programs reach past their object (DD)
    }
    if (low >= kLeHoleStart) return err = "no conventional memory left below A0000h", false;
    if (high >= Vm::kRam) return err = "image does not fit guest RAM", false;
    dos->SetLayout(low, high);
    return true;
}

bool Machine::DumpImage(const std::string& path) {
    std::ofstream out(path, std::ios::binary);
    uint32_t hdr[3] = {entry, stack, (uint32_t)regions.size()};
    out.write("AHLEIMG2", 8);
    out.write((const char*)hdr, sizeof hdr);
    for (auto& r : regions) {
        uint32_t h[4] = {r.base, r.size, r.flags, r.linkBase};
        out.write((const char*)h, sizeof h);
        out.write((const char*)vm.Ptr(r.base, r.size), r.size);
    }
    return (bool)out;
}

bool Machine::Start(const std::string& programName, std::string& err) {
    vm.BuildTables();
    // PSP: int 20h, environment selector at 2Ch, command tail at 80h (" args\r"); environment:
    // strings, double NUL, count, program path (argv[0] for Watcom's cstrt386), then for OS/2-style
    // startup (Phar Lap 286) the arguments and a final NUL.
    uint8_t psp[256] = {0xCD, 0x20};
    psp[0x2C] = Vm::kEnvSel & 0xFF;
    psp[0x2D] = Vm::kEnvSel >> 8;
    const std::string tail = commandLine.empty() ? "" : " " + commandLine.substr(0, 125);
    psp[0x80] = (uint8_t)tail.size();
    memcpy(psp + 0x81, tail.data(), tail.size());
    psp[0x81 + tail.size()] = 0x0D;
    vm.Write(Vm::kPsp, psp, sizeof psp);
    std::string up = programName;
    for (auto& c : up) c = (char)toupper((unsigned char)c);
    std::string env = std::string("PATH=C:\\\0COMSPEC=C:\\COMMAND.COM\0\0\x01\0", 34) + "C:\\" + up;
    env.push_back('\0');
    env += commandLine;
    env.push_back('\0');
    vm.Write(Vm::kEnv, env.data(), (uint32_t)std::min<size_t>(env.size(), 0x200));
    // BIOS data area as a PC in text mode 3 leaves it: programs read the screen size back from it.
    vm.Wr16(0x463, 0x3D4);                                  // CRTC base port
    vm.Wr8(0x449, 3);                                       // video mode
    vm.Wr16(0x44A, 80);                                     // columns
    vm.Wr8(0x484, 24);                                      // rows - 1
    vm.Wr16(0x485, 16);                                     // character height
    vm.Wr16(0x410, 0x0021);                                 // equipment: colour adapter, one drive
    vm.Wr16(0x413, 640);                                    // conventional memory, KB
    if (!segmented) return vm.Enter(entry, stack ? stack : 0x3F0000, err);
    // NE: the segments' descriptors (BuildTables made every entry flat), then the OS/2 entry
    // convention Phar Lap 286 follows: AX = environment selector, BX = offset of the program
    // name in it (command line follows), CX = size of DGROUP, DS = DGROUP, SS:SP from the header.
    for (size_t i = 0; i < neDescs_.size(); ++i) vm.SetDesc(neSegs[i].sel, neDescs_[i]);
    for (auto& [sel, d] : neExtraDescs_) vm.SetDesc(sel, d);
    vm.SetDesc(Vm::kPspSel, Vm::MakeDesc(Vm::kPsp, 0xFF, 0xF3, false));
    vm.SetDesc(0x40, Vm::MakeDesc(0x400, 0xFFFF, 0xF3, false));   // 0040h = the BIOS data segment, as extenders provide
    vm.SetDesc(Vm::kEnvSel, Vm::MakeDesc(Vm::kEnv, 0x1FF, 0xF3, false));
    if (!vm.EnterSegmented(neCs_, neIp_, neSs_, neSp_, neDs_, Vm::kPspSel, err)) return false;
    vm.Set(Reg::Eax, Vm::kEnvSel);
    vm.Set(Reg::Ebx, 34);                                   // the program path after "\0\0\x01\0"
    vm.Set(Reg::Ecx, neDsSize_);
    return true;
}

bool Machine::LoadNe(const std::string& path, std::string& err) {
    // Layout: GDT (8000 entries) at 1 MB, then every segment in its own 64 KB slot, then a 16-bit
    // stub segment with one `hlt` per imported function. Selector of segment n: 200h + 8(n-1).
    NeImage img;
    if (!ParseNe(path, img, err)) return false;
    segmented = true;
    vm.ring3 = true;
    vm.gdtBase = 0x100000;
    vm.gdtEntries = 8000;          // limit F9FFh: BioForge maps "limit + 1" in 16 bits (FFFFh wraps to 0)
    vm.fillFlat = false;
    constexpr uint16_t kFirstSel = 0x200;
    uint32_t at = vm.gdtBase + vm.gdtEntries * 8;
    neSegs.clear();
    for (size_t i = 0; i < img.segs.size(); ++i) {
        const auto& s = img.segs[i];
        neSegs.push_back({at, s.size, (uint16_t)((kFirstSel + 8 * i) | 3), !s.IsData()});
        at += 0x10000;                                      // a 64 KB slot: DosReallocSeg never moves it
    }
    const uint16_t stubSel = (uint16_t)((kFirstSel + 8 * img.segs.size()) | 3);
    const uint32_t stubBase = at, stubSize = (uint32_t)std::max<size_t>(16, img.imports.size() * 4);
    at = (at + stubSize + 15) & ~15u;
    NeLayout layout;
    layout.selector = [&](uint16_t seg) { return SegSel(seg); };
    std::map<std::string, uint16_t> stubOff;
    for (size_t j = 0; j < img.imports.size(); ++j) stubOff[img.imports[j].Key()] = (uint16_t)(4 * j);
    layout.importValue = [&](const NeImage::Import& im, uint16_t& sel, uint16_t& off) {
        auto it = importImpls.find(im.Key());
        if (it != importImpls.end() && it->second.value) { sel = it->second.valueSel; off = it->second.valueOff; return true; }
        sel = stubSel;
        off = stubOff[im.Key()];
        return true;
    };
    RelocateNe(img, layout);
    if (img.unsupported) Count("ne: unsupported relocations " + std::to_string(img.unsupported));
    fixups = img.relocations;
    neDescs_.clear();
    for (size_t i = 0; i < img.segs.size(); ++i) {
        const NeSeg& g = neSegs[i];
        if (!vm.Write(g.base, img.segs[i].data.data(), g.size)) return err = "NE segment outside guest RAM", false;
        regions.push_back({g.base, g.size, g.code ? 4u : 0u, g.base});
        // Ring 3 as under Phar Lap 286: DPL-3 code and data (BioForge derives data aliases from
        // code descriptors and ORs RPL 3 onto selectors).
        neDescs_.push_back(Vm::MakeDesc(g.base, g.size - 1, g.code ? 0xFB : 0xF3, false));
    }
    // import stubs: hlt per function import; native body or a stop naming it
    neExtraDescs_ = {{stubSel, Vm::MakeDesc(stubBase, stubSize - 1, 0xFB, false)}};
    for (size_t j = 0; j < img.imports.size(); ++j) {
        const std::string key = img.imports[j].Key();
        auto it = importImpls.find(key);
        if (it != importImpls.end() && it->second.value) continue;
        Seam s;
        s.addr = stubBase + 4 * (uint32_t)j;
        s.ret = Seam::Ret::Far16;
        natives_.push_back(s);
        Seam& n = natives_.back();
        n.name = strdup(("import " + key).c_str());
        n.area = "import";
        n.doc = "an imported function, answered natively";
        if (it != importImpls.end()) { n.fn = it->second.fn; n.pop = it->second.pop; }
        else n.fn = [key](Machine& m) {
            const uint32_t ra = m.StackAddr(0);
            m.Stop("import " + key + " not implemented (called from " +
                   m.labels.Of(m.vm.SelBase(m.vm.Rd16(ra + 2)) + m.vm.Rd16(ra)) + ")");
        };
        vm.Wr8(n.addr, vm.Trap());
        seams_[n.addr] = &n;
        labels.Add(n.addr, 4, "import_" + key);
    }
    labels.Add(stubBase, 0, "import stubs");
    regions.push_back({stubBase, stubSize, 4u, stubBase});
    dos->SetFirstSelector((uint16_t)std::max(0x800, (int)stubSel + 8));
    neCs_ = SegSel(img.csSeg);
    neIp_ = img.ip;
    neSs_ = SegSel(img.ssSeg);
    neSp_ = img.sp ? img.sp : (uint16_t)(neSegs[img.ssSeg - 1].size & 0xFFFE);
    neDs_ = SegSel(img.autoData);
    neDsSize_ = img.autoData ? (uint16_t)neSegs[img.autoData - 1].size : 0;
    entry = neSegs[img.csSeg - 1].base + img.ip;
    stack = neSegs[img.ssSeg - 1].base + neSp_;
    return Placed(err);
}

bool Machine::LoadMap(const std::string& mapPath) {
    // "Publics by Value" lines: "  ssss:oooo [idle|Abs]  name"; ssss = NE segment number.
    std::ifstream in(mapPath);
    if (!in) return false;
    std::string line;
    bool publics = false;
    int n = 0;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.find("Publics by Value") != std::string::npos) { publics = true; continue; }
        if (!publics) continue;
        unsigned seg, off;
        char rest[512] = {};
        if (sscanf(line.c_str(), " %4x:%4x %511[^\n]", &seg, &off, rest) != 3 || !seg) continue;
        std::string name = rest;
        for (const char* tag : {"idle", "Abs"})
            if (name.rfind(tag, 0) == 0) name = name.substr(strlen(tag));
        name.erase(0, name.find_first_not_of(' '));
        if (const uint32_t a = SegOff((uint16_t)seg, off)) { labels.Add(a, 0, name); ++n; }
    }
    labels.Sort();
    return n > 0;
}

uint32_t Machine::StackAddr(uint32_t n) {
    const uint32_t esp = vm.Get(Reg::Esp);
    return vm.SegBase(Seg::Ss) + (vm.Is32(Seg::Ss) ? esp + n : (uint16_t)(esp + n));
}

void Machine::SetSp(uint32_t sp) {
    if (vm.Is32(Seg::Ss)) vm.Set(Reg::Esp, sp);
    else vm.Set(Reg::Esp, (vm.Get(Reg::Esp) & 0xFFFF0000u) | (sp & 0xFFFF));
}

bool Machine::CallerIs16() {
    // The IDT uses 32-bit interrupt gates even for 16-bit callers. The frame is EIP,
    // CS, EFLAGS in dwords; the interrupted CS descriptor tells us the caller's width.
    return segmented && !((vm.Desc(vm.Rd16(StackAddr(4))) >> 54) & 1);
}

uint32_t Machine::Linear(Seg s, uint32_t off) {
    return vm.SegBase(s) + (segmented && CallerIs16() ? (off & 0xFFFF) : off);
}

void Machine::InstallSeams(const std::vector<Seam>& seams, const std::vector<std::string>& disabled) {
    // Disabled by name, by area, or by an area prefix ("decomp" covers "decomp/image1").
    auto off = [&](const Seam& s) {
        const std::string area = s.area ? s.area : "";
        for (const std::string& d : disabled)
            if (d == s.name || d == area || area.rfind(d + "/", 0) == 0) return true;
        return false;
    };
    for (const Seam& s : seams) {
        if (off(s)) continue;
        const uint32_t at = s.seg ? SegOff(s.seg, s.addr) : Data(s.addr);
        if (!originalByte_.count(at)) originalByte_[at] = vm.Rd8(at);
        vm.Wr8(at, vm.Trap());                              // hlt (int3 at ring 3) at the entry
        seams_[at] = &s;
    }
}

void Machine::Stop(const std::string& why) {
    {
        std::lock_guard<std::mutex> lock(stopMutex_);
        if (stopReason.empty()) stopReason = why;
    }
    stopping = true;
    vm.Kick();
}

void Machine::Post(Task t) {
    {
        std::lock_guard<std::mutex> lock(taskMutex_);
        tasks_.push_back(std::move(t));
    }
    vm.Kick();
}

void Machine::SetFrameFlag(uint32_t bit, bool on) {
    // Our IDT gates are 32-bit, so the saved EFLAGS is at +8 for both caller widths.
    const uint32_t at = StackAddr(8);
    const uint32_t fl = vm.Rd32(at);
    vm.Wr32(at, on ? fl | bit : fl & ~bit);
}

void Machine::DeliverTasks() {
    // Tasks stand in for the hardware interrupts the seams replaced. They may only run where the
    // real IRQ could have arrived: with interrupts enabled, outside the game's cli/sti sections.
    if (holdTasks_) return;
    {
        std::lock_guard<std::mutex> lock(taskMutex_);
        if (tasks_.empty()) return vm.SetInterruptWindow(false);
    }
    if (!(vm.Get(Reg::Eflags) & 0x200)) return vm.SetInterruptWindow(true);
    vm.SetInterruptWindow(false);
    std::deque<Task> batch;
    {
        std::lock_guard<std::mutex> lock(taskMutex_);
        batch.swap(tasks_);
    }
    for (auto& t : batch) {
        t(*this);
        if (stopping) return;
    }
}

void Machine::Run() {
    profile_ = getenv("HLEKIT_PROFILE") != nullptr;
    if (const char* a = getenv("HLEKIT_WATCH_AFTER")) watchAfter_ = atof(a);
    if (const char* w = getenv("HLEKIT_WATCH")) {
        vm.watch = (uint32_t)strtoul(w, nullptr, 16);
        if (const char* c = strchr(w, ',')) watchLimit_ = (uint32_t)strtoul(c + 1, nullptr, 0);
        else watchLimit_ = 0, watchAny_ = true;
        std::string err;
        if (!vm.SetDebug(0, false, err)) std::cerr << "watch: " << err << "\n";
    }
    if (const char* t = getenv("HLEKIT_TRACE")) {
        traceBp_ = (uint32_t)strtoul(t, nullptr, 16);
        const char* c = strchr(t, ',');
        traceSteps_ = c ? (uint32_t)strtoul(c + 1, nullptr, 0) : 100000;
        traceRing_.assign(256, 0);
        std::string err;
        if (traceBp_ && !vm.SetDebug(traceBp_, false, err)) std::cerr << "trace: " << err << "\n";
    }
    ticker_ = std::thread([this] { Ticker(); });
    while (!stopping) Step();
    if (profile_) {
        std::vector<std::pair<uint64_t, std::string>> top;
        uint64_t total = 0;
        for (auto& [f, n] : profileHits_) { top.emplace_back(n, f); total += n; }
        std::sort(top.rbegin(), top.rend());
        fprintf(stderr, "profile: %llu samples\n", (unsigned long long)total);
        for (size_t i = 0; i < top.size() && i < 30; ++i)
            fprintf(stderr, "  %5.1f%%  %s\n", 100.0 * top[i].first / total, top[i].second.c_str());
    }
    if (timerFired_) {
        counts["timer: host ticks"] = timerFired_;
        counts["timer: coalesced (guest busy or IF=0)"] = timerCoalesced_;
    }
}

bool Machine::HookedVector(uint8_t v, uint32_t& off) const { return dos->Hooked(v, off); }

void Machine::QueueBiosKey(uint8_t scan, uint8_t ascii) {
    if (biosKeys_.size() < 16) biosKeys_.push_back((uint16_t)scan << 8 | ascii);
}

void Machine::SetTimer(double hz, Task t) {
    std::lock_guard<std::mutex> lock(timerMutex_);
    timerHz_ = hz;
    timerTask_ = std::move(t);
    timerNext_ = std::chrono::steady_clock::now();
}

uint32_t Machine::NativeFunction(const Seam& seam) {
    if (nextNative_ + 1 > Vm::kNativeEnd) { Stop("out of native function stubs"); return 0; }
    natives_.push_back(seam);
    natives_.back().addr = nextNative_;
    vm.Wr8(nextNative_, vm.Trap());
    seams_[nextNative_] = &natives_.back();
    return nextNative_++;
}

void Machine::CallGuestFar(uint16_t sel, uint32_t off, bool interruptFrame) {
    const CpuState saved = vm.State();
    uint32_t esp = (vm.Get(Reg::Esp) - 64) & ~3u;
    if (interruptFrame) {
        esp -= 4; vm.Wr32(esp, vm.Get(Reg::Eflags) & ~0x300u);   // IF/TF clear, as an interrupt gate
        esp -= 4; vm.Wr32(esp, Vm::kCodeSel | vm.Rpl());
        esp -= 4; vm.Wr32(esp, Vm::kCallReturnIret);
    } else {
        esp -= 4; vm.Wr32(esp, Vm::kCodeSel | vm.Rpl());
        esp -= 4; vm.Wr32(esp, Vm::kCallReturn);
    }
    vm.Set(Reg::Esp, esp);
    vm.Set(Reg::Eip, off);
    if (sel != Vm::kCodeSel) vm.LoadSeg(Seg::Cs, sel);
    callReturned_ = false;
    while (!stopping && !callReturned_) Step();
    callReturned_ = false;
    vm.Restore(saved);
    vm.LoadSeg(Seg::Cs, Vm::kCodeSel);
}

uint32_t Machine::CallGuestFar16(uint16_t sel, uint16_t off, uint16_t dataSel,
                                 std::initializer_list<uint16_t> args) {
    const CpuState saved = vm.State();
    const uint16_t savedCs = vm.GetSeg(Seg::Cs);
    const uint16_t savedDs = vm.GetSeg(Seg::Ds);
    const uint16_t savedEs = vm.GetSeg(Seg::Es);
    const uint16_t savedFs = vm.GetSeg(Seg::Fs);
    const uint16_t savedGs = vm.GetSeg(Seg::Gs);
    const bool wasHoldingTasks = holdTasks_;
    holdTasks_ = true;  // the guest callback must finish before another host timer task runs
    const uint16_t sp = (uint16_t)((vm.Get(Reg::Esp) - 64 - 4 - 2 * args.size()) & ~1u);
    const uint32_t frame = vm.SegBase(Seg::Ss) + sp;
    vm.Wr16(frame, Vm::kCallReturn);
    vm.Wr16(frame + 2, Vm::kCodeSel | vm.Rpl());
    uint32_t at = frame + 4;
    for (uint16_t arg : args) { vm.Wr16(at, arg); at += 2; }
    SetSp(sp);
    if (dataSel) vm.LoadSeg(Seg::Ds, dataSel);
    vm.LoadSeg(Seg::Cs, sel);
    vm.Set(Reg::Eip, off);
    callReturned_ = false;
    while (!stopping && !callReturned_) Step();
    callReturned_ = false;
    const uint32_t result = (uint32_t)vm.Get16(Reg::Edx) << 16 | vm.Get16(Reg::Eax);
    vm.Restore(saved);
    vm.LoadSeg(Seg::Cs, savedCs);
    vm.LoadSeg(Seg::Ds, savedDs);
    vm.LoadSeg(Seg::Es, savedEs);
    vm.LoadSeg(Seg::Fs, savedFs);
    vm.LoadSeg(Seg::Gs, savedGs);
    holdTasks_ = wasHoldingTasks;
    return result;
}

void Machine::WaitUntil(std::chrono::steady_clock::time_point t) {
    while (!stopping) {
        DeliverTasks();
        const auto now = std::chrono::steady_clock::now();
        if (now >= t) break;
        std::this_thread::sleep_for(std::min<std::chrono::steady_clock::duration>(t - now, std::chrono::microseconds(200)));
    }
    vm.SetInterruptWindow(false);
}

void Machine::TakeSnapshot(Snapshot& s) {
    s.ranges.clear();
    auto add = [&](uint32_t a, uint32_t n) {
        if (n && vm.Ptr(a, n)) s.ranges.emplace_back(a, std::vector<uint8_t>(vm.Ptr(a, n), vm.Ptr(a, n) + n));
    };
    add(0x400, 0x100);                                       // BIOS data area (tick count)
    for (auto& r : regions)
        if (!(r.flags & 4)) add(r.base, r.size);             // data objects
    add(dos->PoolStart(), kLeHoleStart - dos->PoolStart());  // conventional memory pool (int 31h/0100h)
    add(dos->HeapStart(), dos->HeapTop() - dos->HeapStart()); // DPMI / DOS heap
}

void Machine::RestoreSnapshot(const Snapshot& s) {
    for (auto& [a, bytes] : s.ranges) vm.Write(a, bytes.data(), (uint32_t)bytes.size());
}

void Machine::PresentFrame(const uint8_t* pixels, int width, int height, double aspect) {
    std::lock_guard<std::mutex> lock(frameMutex_);
    frame_.pixels.assign(pixels, pixels + (size_t)width * height);
    frame_.width = width;
    frame_.height = height;
    frame_.aspect = aspect;
    ++frame_.serial;
    frameShown_ = true;
}

void Machine::ClearFrame() {
    std::lock_guard<std::mutex> lock(frameMutex_);
    frameShown_ = false;
}

bool Machine::LatestFrame(HostFrame& out) {
    std::lock_guard<std::mutex> lock(frameMutex_);
    if (!frameShown_) return false;
    out = frame_;
    return true;
}

void Machine::BiosIrq(uint8_t irq) {
    // What the BIOS's own handler would have done for a chained IRQ: IRQ 0 counts the tick at
    // 0040:006Ch (and the midnight flag at 0040:0070h after 1800B0h ticks). No device is touched.
    Count("bios irq " + std::to_string(irq));
    if (irq == 0) {
        uint32_t t = vm.Rd32(0x46C) + 1;
        if (t >= 0x1800B0) { t = 0; vm.Wr8(0x470, 1); }
        vm.Wr32(0x46C, t);
    }
}

void Machine::Ticker() {
    // Host time sources: the periodic timer (SetTimer) and the "DMA finished" moment of a
    // replaced sound card, taken from the host audio queue.
    while (!stopping) {
        {
            std::lock_guard<std::mutex> lock(timerMutex_);
            const auto now = std::chrono::steady_clock::now();
            if (timerHz_ > 0 && timerTask_ && now >= timerNext_) {
                const auto period = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                    std::chrono::duration<double>(1.0 / timerHz_));
                timerNext_ += period;
                if (now - timerNext_ > period * 4) timerNext_ = now + period;   // fell behind: resync
                ++timerFired_;
                if (timerPending_.exchange(true)) {
                    ++timerCoalesced_;
                } else {
                    Task t = timerTask_;
                    Post([this, t](Machine& m) {
                        m.Count("timer tick");
                        t(m);                               // no re-entry: later ticks coalesce
                        timerPending_ = false;
                    });
                }
            }
        }
        if (soundRunning_ && !soundDue_ && audio && audio->QueuedSeconds() < soundBufferSeconds_) {
            soundDue_ = true;
            Post([](Machine& m) {
                m.soundDue_ = false;
                if (m.soundRunning_ && m.onBufferDue_) {
                    m.Count("sound buffer due");
                    m.onBufferDue_(m);
                }
            });
        }
        std::this_thread::sleep_for(std::chrono::microseconds(timerHz_ > 250 ? 250 : 1000));
    }
}

uint32_t Machine::CallGuestCdecl(uint32_t fn, std::initializer_list<uint32_t> args) {
    const CpuState saved = vm.State();
    uint32_t esp = (vm.Get(Reg::Esp) - 64) & ~3u;           // below everything the caller owns
    esp -= 4 * (uint32_t)args.size();
    uint32_t at = esp;
    for (uint32_t a : args) { vm.Wr32(at, a); at += 4; }    // first argument lowest
    esp -= 4;
    vm.Wr32(esp, Vm::kCallReturn);
    vm.Set(Reg::Esp, esp);
    vm.Set(Reg::Eip, fn);
    callReturned_ = false;
    while (!stopping && !callReturned_) Step();
    callReturned_ = false;
    const uint32_t result = vm.Get(Reg::Eax);
    vm.Restore(saved);
    return result;
}

uint32_t Machine::CallGuest(uint32_t fn, std::initializer_list<uint32_t> args) {
    static const Reg order[] = {Reg::Eax, Reg::Edx, Reg::Ebx, Reg::Ecx};
    const CpuState saved = vm.State();
    uint32_t esp = (vm.Get(Reg::Esp) - 64) & ~3u;           // below everything the caller owns
    esp -= 4;
    vm.Wr32(esp, Vm::kCallReturn);
    vm.Set(Reg::Esp, esp);
    int i = 0;
    for (uint32_t a : args) vm.Set(order[i++], a);
    vm.Set(Reg::Eip, fn);
    callReturned_ = false;
    while (!stopping && !callReturned_) Step();
    callReturned_ = false;
    const uint32_t result = vm.Get(Reg::Eax);
    vm.Restore(saved);
    return result;
}

uint32_t Machine::CallGuestWatcom(uint32_t fn, const std::vector<uint32_t>& args) {
    static const Reg order[] = {Reg::Eax, Reg::Edx, Reg::Ebx, Reg::Ecx};
    const CpuState saved = vm.State();
    uint32_t esp = (vm.Get(Reg::Esp) - 64) & ~3u;           // below everything the caller owns
    for (size_t i = args.size(); i > 4; --i) { esp -= 4; vm.Wr32(esp, args[i - 1]); }
    esp -= 4;
    vm.Wr32(esp, Vm::kCallReturn);
    vm.Set(Reg::Esp, esp);
    for (size_t i = 0; i < args.size() && i < 4; ++i) vm.Set(order[i], args[i]);
    vm.Set(Reg::Eip, fn);
    callReturned_ = false;
    while (!stopping && !callReturned_) Step();
    callReturned_ = false;
    const uint32_t result = vm.Get(Reg::Eax);
    vm.Restore(saved);
    return result;
}

uint32_t Machine::WatcomArg(int n) {
    static const Reg order[] = {Reg::Eax, Reg::Edx, Reg::Ebx, Reg::Ecx};
    return n < 4 ? vm.Get(order[n]) : vm.Rd32(vm.Get(Reg::Esp) + 4 + 4 * (uint32_t)(n - 4));
}

uint32_t Machine::Trampoline(uint32_t fn) {
    auto it = trampolines_.find(fn);
    if (it != trampolines_.end()) return it->second;
    auto orig = originalByte_.find(fn);
    if (orig == originalByte_.end()) return fn;              // not replaced: the entry is the original
    uint8_t code[16];
    for (int i = 0; i < 16; ++i) code[i] = vm.Rd8(fn + (uint32_t)i);
    code[0] = orig->second;
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (ZYAN_FAILED(ZydisDecoderDecodeFull(&dec, code, sizeof code, &ins, ops))) {
        Stop("CallOriginal: cannot decode the entry of " + labels.Of(fn));
        return fn;
    }
    const uint32_t len = ins.length, t = nextTrampoline_;
    if (t + len + 5 > Vm::kTrampolinesEnd) { Stop("CallOriginal: out of trampoline space"); return fn; }
    if (ins.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
        if ((code[0] == 0xE8 || code[0] == 0xE9) && len == 5) {   // call/jmp rel32: re-aim from the copy
            const uint32_t target = fn + 5 + (uint32_t)(code[1] | code[2] << 8 | code[3] << 16 | code[4] << 24);
            const uint32_t rel = target - (t + 5);
            memcpy(code + 1, &rel, 4);
        } else {
            Stop("CallOriginal: the entry of " + labels.Of(fn) + " is a short relative branch");
            return fn;
        }
    }
    for (uint32_t i = 0; i < len; ++i) vm.Wr8(t + i, code[i]);
    vm.Wr8(t + len, 0xE9);                                  // jmp fn + len
    vm.Wr32(t + len + 1, fn + len - (t + len + 5));
    nextTrampoline_ = (t + len + 5 + 15) & ~15u;
    trampolines_[fn] = t;
    return t;
}

uint32_t Machine::CallOriginal(uint32_t fn, const std::vector<uint32_t>& args) {
    return CallGuestWatcom(Trampoline(fn), args);
}

bool Machine::StartSound(int rate, int channels, int bits, uint32_t bufferBytes, Task onBufferDue) {
    if (!audio || !audio->Open(rate, channels, bits)) return false;
    soundBytesPerSample_ = channels * bits / 8;
    soundBufferSeconds_ = (double)bufferBytes / (rate * soundBytesPerSample_);
    onBufferDue_ = std::move(onBufferDue);
    soundRunning_ = true;
    return true;
}

void Machine::StopSound() {
    if (!soundRunning_.exchange(false)) return;
    if (audio) audio->Close();
}

void Machine::QueueAudio(uint32_t guestAddr, uint32_t bytes) {
    const uint8_t* src = vm.Ptr(guestAddr, bytes);
    if (!src || !audio) return;
    std::vector<uint8_t> pcm(src, src + bytes);
    const float g = gain;
    if (g < 0.999f) {
        if (soundBytesPerSample_ % 2 == 0) {                // 16-bit signed
            for (size_t i = 0; i + 1 < pcm.size(); i += 2) {
                int16_t v = (int16_t)(pcm[i] | pcm[i + 1] << 8);
                v = (int16_t)(v * g);
                pcm[i] = (uint8_t)v;
                pcm[i + 1] = (uint8_t)(v >> 8);
            }
        } else {
            for (auto& s : pcm) s = (uint8_t)(128 + (int)((s - 128) * g));
        }
    }
    audio->Queue(pcm.data(), pcm.size());
}

void Machine::Step() {
    std::string err;
    DeliverTasks();
    if (stopping) return;
    if (!vm.RunOnce(err)) return Stop(err);
    const uint32_t eip = vm.Get(Reg::Eip);
    char buf[160];
    switch (vm.Exit().reason) {
    case Exit::Hlt: OnHlt(); break;
    case Exit::Io: OnIo(); break;
    case Exit::Intr: case Exit::Window:
        if (profile_) {                                     // where the guest was when the host interrupted it
            std::string f = labels.Of(eip);
            profileHits_[f.substr(0, f.find('+'))]++;
        }
        break;
    case Exit::Debug: OnDebug(); break;
    case Exit::Mmio: {
        // The engine may report EIP after a write that it already retired: the registers and the
        // code bytes say which instruction it was.
        std::string why(512, '\0');
        const CpuState r = vm.State();
        const int n = snprintf(why.data(), why.size(),
                 "access outside guest RAM at %08llx (%s, %u bytes) from %s\n"
                 "  eax=%08llx ebx=%08llx ecx=%08llx edx=%08llx esi=%08llx edi=%08llx ebp=%08llx esp=%08llx\n"
                 "  code at eip %08x:",
                 (unsigned long long)vm.Exit().addr, vm.Exit().write ? "write" : "read",
                 vm.Exit().len, labels.Of(eip).c_str(), (unsigned long long)RegOf(r, Reg::Eax), (unsigned long long)RegOf(r, Reg::Ebx),
                 (unsigned long long)RegOf(r, Reg::Ecx), (unsigned long long)RegOf(r, Reg::Edx), (unsigned long long)RegOf(r, Reg::Esi),
                 (unsigned long long)RegOf(r, Reg::Edi), (unsigned long long)RegOf(r, Reg::Ebp), (unsigned long long)RegOf(r, Reg::Esp), eip);
        why.resize(n > 0 ? std::min<size_t>(n, why.size() - 1) : 0);
        for (uint32_t k = 0; k < 12; ++k) {
            snprintf(buf, sizeof buf, " %02x", vm.Rd8(eip + k));
            why += buf;
        }
        why += "\n  stack:";
        for (uint32_t k = 0; k < 12; ++k) {
            snprintf(buf, sizeof buf, " %08x", vm.Rd32((uint32_t)RegOf(r, Reg::Esp) + 4 * k));
            why += buf;
        }
        why += "\n  frames (ebp chain):";
        uint32_t bp = (uint32_t)RegOf(r, Reg::Ebp);
        for (int k = 0; k < 8 && bp && vm.Ptr(bp, 8); ++k, bp = vm.Rd32(bp)) why += " " + labels.Of(vm.Rd32(bp + 4));
        if (const char* d = getenv("HLEKIT_DUMP_ON_FAULT")) DumpImage(d);  // memory as it was, for diffing
        Stop(why + TraceTail(120));
        break;
    }
    case Exit::Shutdown: {
        const CpuState r = vm.State();
        const uint16_t cs = vm.GetSeg(Seg::Cs);
        const uint16_t ss = vm.GetSeg(Seg::Ss);
        const uint32_t linear = vm.SegBase(Seg::Cs) + eip;
        snprintf(buf, sizeof buf,
                 "triple fault (shutdown) at %04x:%04x %s\n"
                 "  eax=%04llx ebx=%04llx ecx=%04llx edx=%04llx esp=%04llx ebp=%04llx ss=%04x flags=%08llx",
                 cs, eip & 0xFFFF, labels.Of(linear).c_str(),
                 (unsigned long long)RegOf(r, Reg::Eax) & 0xFFFF, (unsigned long long)RegOf(r, Reg::Ebx) & 0xFFFF,
                 (unsigned long long)RegOf(r, Reg::Ecx) & 0xFFFF, (unsigned long long)RegOf(r, Reg::Edx) & 0xFFFF,
                 (unsigned long long)RegOf(r, Reg::Esp) & 0xFFFF, (unsigned long long)RegOf(r, Reg::Ebp) & 0xFFFF,
                 ss, (unsigned long long)RegOf(r, Reg::Eflags));
        Stop(std::string(buf) + TraceTail(120));
        break;
    }
    case Exit::FailEntry:
        snprintf(buf, sizeof buf, "cpu entry failed, reason %llx",
                 (unsigned long long)vm.Exit().failReason);
        Stop(buf);
        break;
    case Exit::Internal:
        snprintf(buf, sizeof buf, "cpu internal error %u near %s", vm.Exit().suberror, labels.Of(eip).c_str());
        Stop(buf);
        break;
    default:
        snprintf(buf, sizeof buf, "unexpected cpu exit %u", vm.Exit().raw);
        Stop(buf);
    }
}

void Machine::OnDebug() {
    // A breakpoint or one single step (HLEKIT_TRACE). The instruction at EIP has not run yet.
    std::string err;
    const uint32_t eip = (segmented ? vm.SegBase(Seg::Cs) : 0) + vm.Get(Reg::Eip);
    if (vm.ring3 && vm.Exit().exception == 3)              // int3: a ring-3 trap (seam, stub, return)
        return OnTrap((uint32_t)vm.Exit().pc, true);
    if (vm.watch && (vm.Exit().dr6 & 0x2) &&
        (Seconds() < watchAfter_ || (!watchAny_ && (int32_t)vm.Rd32(vm.watch & ~3u) <= (int32_t)watchLimit_))) {
        Count("watch: writes within limit");
        if (traceRing_.empty()) return;
    } else if (vm.watch && (vm.Exit().dr6 & 0x2)) {          // DR1: the write has retired, EIP is after it
        char buf[200];
        const CpuState r = vm.State();
        snprintf(buf, sizeof buf, "watch: write to %08x (now %08x) before %s  eax=%08llx ebx=%08llx ecx=%08llx edx=%08llx esi=%08llx edi=%08llx",
                 vm.watch, vm.Rd32(vm.watch & ~3u), labels.Of(eip).c_str(), (unsigned long long)RegOf(r, Reg::Eax), (unsigned long long)RegOf(r, Reg::Ebx),
                 (unsigned long long)RegOf(r, Reg::Ecx), (unsigned long long)RegOf(r, Reg::Edx), (unsigned long long)RegOf(r, Reg::Esi), (unsigned long long)RegOf(r, Reg::Edi));
        return Stop(buf + TraceTail(60));
    }
    if (traceRing_.empty()) return;
    traceRing_[traceAt_++ % traceRing_.size()] = eip;
    if (!traceLeft_) {                                      // the breakpoint: start a window
        traceLeft_ = traceSteps_;
        Count("trace: windows");
        // step over the breakpoint itself: no breakpoint while stepping
        if (!vm.SetDebug(0, true, err)) Stop("trace: " + err);
        return;
    }
    if (--traceLeft_ == 0 && !vm.SetDebug(traceBp_, false, err)) Stop("trace: " + err);
}

std::string Machine::TraceTail(size_t n) const {
    std::string s;
    if (traceRing_.empty() || !traceAt_) return s;
    s = "\n  last instructions (HLEKIT_TRACE):";
    const size_t count = std::min({n, traceAt_, traceRing_.size()});
    for (size_t k = traceAt_ - count; k < traceAt_; ++k) {
        const uint32_t a = traceRing_[k % traceRing_.size()];
        s += "\n    " + labels.Of(a);
    }
    return s;
}

void Machine::OnHlt() {
    // hlt has retired: EIP is past it. Segmented programs: CS base + IP.
    OnTrap((segmented ? vm.SegBase(Seg::Cs) : 0) + vm.Get(Reg::Eip) - 1, false);
}

void Machine::OnTrap(uint32_t at, bool atTrap) {
    // A trap byte executed at `at`: hlt (EIP already past it) or, at ring 3, an int3 software
    // breakpoint (EIP still on it: paths that fall through to the next instruction step over it).
    auto past = [&] { if (atTrap) vm.Set(Reg::Eip, vm.Get(Reg::Eip) + 1); };
    if (at == Vm::kCallReturn || at == Vm::kCallReturnIret) { callReturned_ = true; return; }
    if (at >= Vm::kBiosIrq && at < Vm::kBiosIrq + 32) { past(); return BiosIrq((uint8_t)((at - Vm::kBiosIrq) / 2)); }
    if (at >= Vm::kStubs && at < Vm::kStubs + 512) { past(); return OnInt((uint8_t)((at - Vm::kStubs) / 2)); }
    auto it = seams_.find(at);
    if (it != seams_.end()) {
        const Seam& s = *it->second;
        Count(std::string("seam ") + s.name);
        s.fn(*this);
        if (stopping) return;
        if (s.ret == Seam::Ret::Resume) { vm.Set(Reg::Eip, at + s.pop); return; }   // instruction seam
        if (s.ret == Seam::Ret::Far16) {                    // retf N
            const uint32_t ra = StackAddr(0);
            const uint16_t ip = vm.Rd16(ra), cs = vm.Rd16(ra + 2);
            SetSp(vm.Get(Reg::Esp) + 4 + s.pop);
            vm.Set(Reg::Eip, ip);
            vm.LoadSeg(Seg::Cs, cs);
            return;
        }
        if (s.ret == Seam::Ret::Near16) {                   // ret N
            const uint16_t ip = vm.Rd16(StackAddr(0));
            SetSp(vm.Get(Reg::Esp) + 2 + s.pop);
            vm.Set(Reg::Eip, ip);
            return;
        }
        const uint32_t esp = vm.Get(Reg::Esp);              // the function's own return
        vm.Set(Reg::Eip, vm.Rd32(esp));
        vm.Set(Reg::Esp, esp + 4 + s.pop);
        return;
    }
    if (atTrap) { Stop("int3 at " + labels.Of(at) + " (not a seam)"); return; }
    Count("guest hlt");                                     // the game idling: nothing will wake it
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

void Machine::OnInt(uint8_t v) {
    char buf[160];
    switch (v) {
    case 0x21: return dos->Int21();
    case 0x31: return dos->Int31();
    case 0x10: return dos->Int10();
    case 0x1A:                                              // BIOS time of day: ticks at 0040:006Ch
        Count("int1a " + std::to_string((vm.Get(Reg::Eax) >> 8) & 0xFF));
        if (((vm.Get(Reg::Eax) >> 8) & 0xFF) == 0) {
            const uint32_t t = vm.Rd32(0x46C);
            vm.Set16(Reg::Ecx, (uint16_t)(t >> 16));
            vm.Set16(Reg::Edx, (uint16_t)t);
            vm.Set(Reg::Eax, vm.Get(Reg::Eax) & ~0xFFu);   // AL = midnight flag
        }
        return;
    case 0x15: {                                            // BIOS system services of a PC without a game port
        const uint8_t ah = (vm.Get(Reg::Eax) >> 8) & 0xFF;
        Count("int15 " + std::to_string(ah));
        vm.Set16(Reg::Eax, 0x8600);                         // AH=86h: function not supported
        SetFrameFlag(0x01, true);                           // CF=1 (84h joystick: no game port)
        return;
    }
    case 0x16: {                                            // BIOS keyboard buffer
        const uint8_t ah = (vm.Get(Reg::Eax) >> 8) & 0xFF;
        Count("int16 " + std::to_string(ah));
        if (ah == 0x01 || ah == 0x11) {
            SetFrameFlag(0x40, biosKeys_.empty());
            if (!biosKeys_.empty()) vm.Set16(Reg::Eax, biosKeys_.front());
        } else if (ah == 0x00 || ah == 0x10) {
            if (!biosKeys_.empty()) {
                vm.Set16(Reg::Eax, biosKeys_.front());
                biosKeys_.pop_front();
            } else vm.Set16(Reg::Eax, 0);
        } else if (ah == 0x02 || ah == 0x12) vm.Set16(Reg::Eax, vm.Rd8(0x417));
        return;
    }
    default: break;
    }
    uint32_t handler;
    if (v >= 0x20 && dos->Hooked(v, handler)) {             // a software int the game hooked
        uint16_t sel = 0;
        uint32_t off = 0;
        if (segmented && dos->HookedFar(v, sel, off)) {
            if (CallerIs16() && !((vm.Desc(sel) >> 54) & 1)) {
                // The host stub's 32-bit gate pushed three dwords. A 16-bit handler
                // returns with iret, which pops three words. Pack the frame at its
                // end so that iret restores the original SP.
                const uint16_t ip = vm.Rd16(StackAddr(0));
                const uint16_t cs = vm.Rd16(StackAddr(4));
                const uint16_t flags = vm.Rd16(StackAddr(8));
                vm.Wr16(StackAddr(6), ip);
                vm.Wr16(StackAddr(8), cs);
                vm.Wr16(StackAddr(10), flags);
                SetSp(vm.Get(Reg::Esp) + 6);
            }
            vm.LoadSeg(Seg::Cs, sel);
            vm.Set(Reg::Eip, off);
        } else vm.Set(Reg::Eip, handler);                   // its frame is already on the stack
        return;
    }
    if (v < 0x20) {
        static const bool hasCode[32] = {0,0,0,0,0,0,0,0,1,0,1,1,1,1,1,0,0,1};
        const uint32_t frame = StackAddr(0);
        const uint32_t code = hasCode[v] ? vm.Rd32(frame) : 0;
        const uint32_t faultEip = vm.Rd32(frame + (hasCode[v] ? 4 : 0));
        const uint16_t faultCs = vm.Rd16(frame + (hasCode[v] ? 8 : 4));
        const uint32_t lin = (segmented ? vm.SelBase(faultCs) : 0) + faultEip;
        snprintf(buf, sizeof buf, "CPU exception %02x (error code %x) at %04x:%08x %s", v, code, faultCs, faultEip,
                 labels.Of(lin).c_str());
        const CpuState r = vm.State();
        std::string why = buf;
        snprintf(buf, sizeof buf, "\n  eax=%08llx ebx=%08llx ecx=%08llx edx=%08llx esi=%08llx edi=%08llx ebp=%08llx  ds=%04x es=%04x ss=%04x",
                 (unsigned long long)RegOf(r, Reg::Eax), (unsigned long long)RegOf(r, Reg::Ebx), (unsigned long long)RegOf(r, Reg::Ecx), (unsigned long long)RegOf(r, Reg::Edx),
                 (unsigned long long)RegOf(r, Reg::Esi), (unsigned long long)RegOf(r, Reg::Edi), (unsigned long long)RegOf(r, Reg::Ebp),
                 vm.GetSeg(Seg::Ds), vm.GetSeg(Seg::Es), vm.GetSeg(Seg::Ss));
        why += buf;
        if (code & ~7u) {                                   // the error code names a selector
            const uint16_t sel = (uint16_t)(code & ~3u);
            const uint64_t d = vm.Desc(sel & ~4u);           // LDT = GDT memory here
            snprintf(buf, sizeof buf, "\n  selector %04x: descriptor %016llx (base %08x limit %x access %02x)", sel,
                     (unsigned long long)d, Vm::DescBase(d), Vm::DescLimit(d), (unsigned)((d >> 40) & 0xFF));
            why += buf;
        }
        return Stop(why);
    }
    std::string where;                                      // the code addresses on the stack: who asked
    for (uint32_t k = 0; k < 64 && where.size() < 240; ++k) {
        const uint32_t w = vm.Rd32(StackAddr(4 * k));
        if (IsCode(w)) where += " " + labels.Of(w);
    }
    snprintf(buf, sizeof buf, "int %02x (unhandled) from%s", v, where.c_str());
    Count(buf);
}

void Machine::OnIo() {
    // No device is emulated. A port access means a function that touches hardware is not a seam
    // yet: report it once (with the decomp name of the function) and read 0.
    auto& io = vm.Exit();
    if (!io.out && io.data) memset(io.data, 0, (size_t)io.size * io.ioCount);   // no device: reads 0
    std::string where = labels.Of((segmented ? vm.SegBase(Seg::Cs) : 0) + vm.Get(Reg::Eip));
    // Often this is inside a runtime inp()/outp() leaf helper; the caller is the seam
    // candidate, so name the first code address near the top of the stack too.
    if (segmented) {                                        // a far return address: offset, code selector
        for (uint32_t i = 0; i < 8; ++i) {
            const uint16_t off = vm.Rd16(StackAddr(2 * i)), sel = vm.Rd16(StackAddr(2 * i + 2));
            const uint64_t d = vm.Desc(sel);
            if (sel >= 8 && ((d >> 47) & 1) && ((d >> 43) & 3) == 3 && IsCode(Vm::DescBase(d) + off)) {
                where += " <- " + labels.Of(Vm::DescBase(d) + off);
                break;
            }
        }
    } else {
        const uint32_t esp = vm.Get(Reg::Esp);
        for (uint32_t i = 0; i < 4; ++i) {
            const uint32_t ret = vm.Rd32(esp + i * 4);
            if (IsCode(ret)) { where += " <- " + labels.Of(ret); break; }
        }
    }
    char buf[160];
    snprintf(buf, sizeof buf, "%s %04x", io.out ? "out" : "in ", io.port);
    std::string caller = where.find(" <- ") == std::string::npos ? where : where.substr(where.find(" <- ") + 4);
    const std::string key = std::string(buf) + " " + caller.substr(0, caller.find('+'));
    Count("port " + key);
    if (!reported_[key]) {
        reported_[key] = true;
        std::cerr << "[hw] unseamed hardware access: " << buf << " in " << where << "\n";
    }
}

}  // namespace hlekit
