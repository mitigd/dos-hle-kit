// Deterministic protected-mode string regressions, with KVM as the reference.
// No game files or Python dependencies required.
#include "hlekit/vcpu.h"
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>
using namespace hlekit;

constexpr uint32_t kCode = 0x10000, kSpan = 0x70000;

static void Setup(Vcpu& cpu, const std::vector<uint8_t>& code,
                  const std::vector<uint8_t>& image, bool backward, bool shortIndex, int count) {
    // Invalidate before writing: previously translated pages may be protected.
    cpu.Invalidate(0, kSpan);
    memcpy(cpu.Ram(), image.data(), image.size());
    memcpy(cpu.Ram() + kCode, code.data(), code.size());
    auto& s = cpu.State();
    s = CpuState{};
    for (int i = 0; i < kSegCount; ++i) {
        auto& seg = s.seg[i];
        seg.sel = i == (int)Seg::Cs ? 8 : 16;
        seg.limit = 0xFFFFFFFF;
        seg.access = i == (int)Seg::Cs ? 0x9B : 0x93;
        seg.big = seg.gran = true;
    }
    s.reg[(int)Reg::Eip] = kCode;
    s.reg[(int)Reg::Esp] = 0x60000;
    s.reg[(int)Reg::Eax] = 0x12345678;
    s.reg[(int)Reg::Ebx] = 0x87654321;
    s.reg[(int)Reg::Ecx] = count | (shortIndex ? 0xABCD0000 : 0);
    s.reg[(int)Reg::Esi] = shortIndex ? 0x12348000 : 0x28000;
    s.reg[(int)Reg::Edi] = shortIndex ? 0x5678C000 : 0x4C000;
    s.reg[(int)Reg::Eflags] = 0xAD7 | (backward ? 0x400 : 0);
    cpu.Touch();
}

static bool Run(Vcpu& cpu, std::string& err) {
    for (int i = 0; i < 1000; ++i) {
        if (!cpu.RunOnce(err)) return false;
        if (cpu.exit.reason == Exit::Intr || cpu.exit.reason == Exit::Window) continue;
        if (cpu.exit.reason == Exit::Hlt) return true;
        err = "unexpected exit " + std::to_string((int)cpu.exit.reason);
        return false;
    }
    err = "execution budget exhausted";
    return false;
}

int main() {
    std::string err;
    auto ref = Vcpu::Create("kvm", err);
    if (!ref) { fprintf(stderr, "kvm: %s\n", err.c_str()); return 2; }
    auto jit = Vcpu::Create("jit", err);
    if (!jit) { fprintf(stderr, "jit: %s\n", err.c_str()); return 2; }
    std::vector<uint8_t> image(kSpan);
    std::mt19937 rng(12345);
    for (auto& b : image) b = (uint8_t)rng();
    int total = 0, bad = 0;
    // Prime the translator's scratch register with a nonzero upper half using
    // XCHG, then exercise the independent operand and address widths. LBA uses
    // byte/word LODS with 32-bit ESI in its resource decompressor.
    for (int family = 0; family < 3; ++family)
    for (int width : {1, 2, 4})
    for (bool shortIndex : {false, true})
    for (bool backward : {false, true})
    for (int count : {-1, 0, 1, 3}) {
        // Before the fix, a repeated LODS would fault on its second iteration
        // after corrupting ESI. The non-repeated cases report that corruption
        // directly, keeping the failing suite useful on the old engine too.
        std::vector<uint8_t> code = {0xB8, 0x78, 0x56, 0x34, 0x12, 0x93}; // mov eax,imm; xchg eax,ebx
        if (shortIndex) code.push_back(0x67);
        if (width == 2) code.push_back(0x66);
        if (count >= 0) code.push_back(0xF3);
        const uint8_t opcode = family == 0 ? 0xAC : family == 1 ? 0xA4 : 0xAA;
        code.push_back(opcode + (width != 1));
        // A branch publishes flags, checking that flag-neutral string ops
        // preserve guest flags even when REP has a zero count.
        code.insert(code.end(), {0xEB, 0x00, 0xF4});
        Setup(*ref, code, image, backward, shortIndex, count < 0 ? 3 : count);
        Setup(*jit, code, image, backward, shortIndex, count < 0 ? 3 : count);
        std::string e1, e2, why;
        const bool ok1 = Run(*ref, e1), ok2 = Run(*jit, e2);
        ++total;
        if (!ok1 || !ok2) why = "run: kvm[" + e1 + "] jit[" + e2 + "]";
        for (int i = 0; i < kRegCount && why.empty(); ++i) {
            const uint32_t mask = i == (int)Reg::Eflags ? 0xED5 : 0xFFFFFFFF;
            const uint32_t a = ref->State().reg[i] & mask, b = jit->State().reg[i] & mask;
            if (a != b) {
                char buf[128];
                snprintf(buf, sizeof buf, "reg %d: kvm %08x jit %08x", i, a, b);
                why = buf;
            }
        }
        if (why.empty() && memcmp(ref->Ram(), jit->Ram(), kSpan)) why = "memory differs";
        if (!why.empty()) {
            ++bad;
            printf("%s width=%d addr=%d DF=%d count=%d: %s\n",
                   family == 0 ? "lods" : family == 1 ? "movs" : "stos",
                   width, shortIndex ? 16 : 32, backward, count, why.c_str());
            // Avoid a host fault from a repeated LODS on an unfixed engine.
            if (family == 0 && count == -1 && !shortIndex) break;
        }
    }
    printf("%d protected-mode cases, %d mismatches\n", total, bad);
    return bad ? 1 : 0;
}
