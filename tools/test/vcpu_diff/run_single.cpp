// Differential test: one real-mode instruction at a time on KVM (reference) and the JIT.
#include "hlekit/vcpu.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <random>
#include <string>
#include <vector>
using namespace hlekit;

struct Case { uint8_t insn[16]; uint16_t r[8]; uint16_t flags, len; };
static SegState RealSeg(uint16_t sel, bool code) {
    SegState s; s.sel = sel; s.base = (uint32_t)sel << 4; s.limit = 0xFFFF; s.access = code ? 0x9B : 0x93; return s;
}
constexpr uint32_t kData = 0x20000, kSpan = 0x30000;    // DS=2000 SS=3000 ES=4000 (contiguous 192 KB)

static void Setup(Vcpu& c, const Case& k, const std::vector<uint8_t>& image) {
    uint8_t* m = c.Ram();
    memcpy(m + kData, image.data(), kSpan);
    // code at 1000:0000, a hlt trap at 1000:0100, every IVT vector to 0000:0500 (hlt)
    memset(m + 0x10000, 0x90, 0x200);
    memcpy(m + 0x10000, k.insn, k.len);
    const int rel = 0x100 - (k.len + 3);
    m[0x10000 + k.len] = 0xE9; m[0x10000 + k.len + 1] = (uint8_t)rel; m[0x10000 + k.len + 2] = (uint8_t)(rel >> 8);
    m[0x10100] = 0xF4;
    m[0x500] = 0xF4;
    for (int v = 0; v < 256; ++v) { m[v * 4] = 0x00; m[v * 4 + 1] = 0x05; m[v * 4 + 2] = 0; m[v * 4 + 3] = 0; }
    c.Invalidate(0x10000, 0x200);
    c.Invalidate(0, 0x1000);
    CpuState& s = c.State();
    s = CpuState{};
    s.seg[(int)Seg::Cs] = RealSeg(0x1000, true);
    s.seg[(int)Seg::Ds] = RealSeg(0x2000, false);
    s.seg[(int)Seg::Es] = RealSeg(0x4000, false);
    s.seg[(int)Seg::Fs] = RealSeg(0, false);
    s.seg[(int)Seg::Gs] = RealSeg(0, false);
    s.seg[(int)Seg::Ss] = RealSeg(0x3000, false);
    s.idtBase = 0; s.idtLimit = 0x3FF; s.cr0 = 0x30;
    s.reg[(int)Reg::Eax] = k.r[0]; s.reg[(int)Reg::Ebx] = k.r[1]; s.reg[(int)Reg::Ecx] = k.r[2]; s.reg[(int)Reg::Edx] = k.r[3];
    s.reg[(int)Reg::Esi] = k.r[4]; s.reg[(int)Reg::Edi] = k.r[5]; s.reg[(int)Reg::Ebp] = k.r[6]; s.reg[(int)Reg::Esp] = k.r[7];
    s.reg[(int)Reg::Eip] = 0; s.reg[(int)Reg::Eflags] = k.flags;
    c.Touch();
}

static bool Run(Vcpu& c, std::string& err) {
    for (int guard = 0; guard < 1000; ++guard) {
        if (!c.RunOnce(err)) return false;
        if (c.exit.reason == Exit::Intr || c.exit.reason == Exit::Window) continue;
        return true;
    }
    err = "no exit";
    return false;
}

static uint32_t FlagMask(const std::string& full) {
    std::string mn = full.substr(0, full.find(' '));
    if (mn == "rep" || mn == "repe" || mn == "repne" || mn == "repz" || mn == "repnz") mn = full.substr(full.find(' ') + 1, full.find(' ', full.find(' ') + 1) - full.find(' ') - 1);
    const uint32_t DF = 0x400;
    auto in = [&](std::initializer_list<const char*> l) { for (auto* s : l) if (mn == s) return true; return false; };
    if (in({"add", "adc", "sub", "sbb", "cmp", "neg", "inc", "dec", "cmpsb", "cmpsw", "scasb", "scasw"})) return 0x8D5 | DF;
    if (in({"and", "or", "xor", "test"})) return 0x8C5 | DF;
    if (in({"shl", "shr", "sar", "sal"})) return 0x0C5 | DF;
    if (in({"rol", "ror", "rcl", "rcr"})) return 0x001 | DF;
    if (in({"mul", "imul"})) return 0x801 | DF;
    if (in({"aam", "aad", "daa", "das", "aaa", "aas"})) return DF;
    return 0x8D5 | DF;
}

int main(int argc, char** argv) {
    std::string err;
    auto ref = Vcpu::Create("kvm", err);
    if (!ref) { fprintf(stderr, "kvm: %s\n", err.c_str()); return 2; }
    auto jit = Vcpu::Create("jit", err);
    if (!jit) { fprintf(stderr, "jit: %s\n", err.c_str()); return 2; }
    if (!ref->SetRealMode(err) || !jit->SetRealMode(err)) { fprintf(stderr, "real: %s\n", err.c_str()); return 2; }

    std::ifstream f("cases.bin", std::ios::binary), names("cases.txt");
    std::vector<uint8_t> image(kSpan);
    std::mt19937 rng(12345);
    for (auto& b : image) b = (uint8_t)rng();

    std::map<std::string, int> bad, total;
    int shown = 0, n = 0;
    const int maxShow = argc > 1 ? atoi(argv[1]) : 30;
    Case k;
    std::string name;
    while (f.read((char*)&k, sizeof k) && std::getline(names, name)) {
        ++n;
        std::string mn = name.substr(0, name.find(' '));
        if (mn == "rep" || mn == "repe" || mn == "repne" || mn == "repz" || mn == "repnz") { size_t a = name.find(' ') + 1; mn = "rep " + name.substr(a, name.find(' ', a) - a); }
        ++total[mn];
        std::string e1, e2;
        Setup(*ref, k, image); Setup(*jit, k, image);
        const bool ok1 = Run(*ref, e1), ok2 = Run(*jit, e2);
        std::string why;
        char buf[256];
        if (!ok1 || !ok2) { snprintf(buf, sizeof buf, "run failed: kvm[%s] jit[%s]", e1.c_str(), e2.c_str()); why = buf; }
        else if (ref->exit.reason != jit->exit.reason) { snprintf(buf, sizeof buf, "exit kvm %d jit %d", (int)ref->exit.reason, (int)jit->exit.reason); why = buf; }
        else {
            const char* rn[] = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"};
            const Reg ids[] = {Reg::Eax, Reg::Ebx, Reg::Ecx, Reg::Edx, Reg::Esi, Reg::Edi, Reg::Ebp, Reg::Esp};
            for (int i = 0; i < 8 && why.empty(); ++i) {
                const uint32_t a = ref->State().reg[(int)ids[i]], b = jit->State().reg[(int)ids[i]];
                if (a != b) { snprintf(buf, sizeof buf, "%s kvm %08x jit %08x", rn[i], a, b); why = buf; }
            }
            const uint32_t mask = FlagMask(name);
            const uint32_t fa = ref->State().reg[(int)Reg::Eflags] & mask, fb = jit->State().reg[(int)Reg::Eflags] & mask;
            if (why.empty() && fa != fb) { snprintf(buf, sizeof buf, "flags kvm %03x jit %03x (mask %03x)", fa, fb, mask); why = buf; }
            if (why.empty() && memcmp(ref->Ram() + kData, jit->Ram() + kData, kSpan)) {
                size_t i = 0; while (ref->Ram()[kData + i] == jit->Ram()[kData + i]) ++i;
                snprintf(buf, sizeof buf, "memory differs at +%zx: kvm %02x jit %02x", i, ref->Ram()[kData + i], jit->Ram()[kData + i]); why = buf;
            }
        }
        if (!why.empty()) {
            ++bad[mn];
            if (shown++ < maxShow) {
                printf("%-28s ", name.c_str());
                for (int i = 0; i < k.len; ++i) printf("%02x", k.insn[i]);
                printf("  ax=%04x bx=%04x cx=%04x dx=%04x si=%04x di=%04x bp=%04x sp=%04x fl=%03x\n      -> %s\n",
                       k.r[0], k.r[1], k.r[2], k.r[3], k.r[4], k.r[5], k.r[6], k.r[7], k.flags, why.c_str());
            }
        }
    }
    printf("\n%d cases, %d mismatches\n", n, shown);
    for (auto& [m, c] : bad) printf("  %-14s %d / %d\n", m.c_str(), c, total[m]);
    return 0;
}
