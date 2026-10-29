// Real-mode callback frames, segment identity, state restoration, and nested seam calls.
#include "hlekit/machine.h"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace hlekit;

static void Check(bool ok, const char* message) {
    if (!ok) { fprintf(stderr, "%s\n", message); std::exit(1); }
}

static void SameState(const CpuState& a, const CpuState& b) {
    for (int i = 0; i < kRegCount; ++i) Check(a.reg[i] == b.reg[i], "callback changed a caller register");
    for (int i = 0; i < kSegCount; ++i) {
        Check(a.seg[i].sel == b.seg[i].sel && a.seg[i].base == b.seg[i].base &&
              a.seg[i].limit == b.seg[i].limit && a.seg[i].access == b.seg[i].access &&
              a.seg[i].big == b.seg[i].big, "callback changed a caller segment");
    }
}

int main() {
    Machine m;
    std::string err;
    Check(m.vm.Create("jit", err), err.c_str());
    m.realMode = true;
    m.vm.real = true;
    Check(m.vm.EnterReal(0x1000, 0x200, 0x4000, 0xf000, 0x5000, 0x6000, err), err.c_str());
    m.vm.Wr8(0x10200, 0x90); // trap byte here must be restored after each task callback
    // Far callee at 2000:0100; a near subroutine at 2000:0130 proves CS was preserved.
    const uint8_t farCode[] = {
        0x55, 0x89, 0xe5,             // push bp; mov bp,sp
        0x8b, 0x46, 0x06,             // mov ax,[bp+6]
        0x03, 0x46, 0x08,             // add ax,[bp+8]
        0xe8, 0x24, 0x00,             // call 0130
        0xba, 0x78, 0x56,             // mov dx,5678
        0x5d, 0xcb                    // pop bp; retf
    };
    const uint8_t subCode[] = {0x83, 0xc0, 0x03, 0xbb, 0x22, 0x22, 0x8e, 0xdb, 0x8e, 0xc3, 0xc3};
    Check(m.vm.Write(0x20100, farCode, sizeof farCode), "write far callee");
    Check(m.vm.Write(0x20130, subCode, sizeof subCode), "write near subroutine");
    const auto saved = m.vm.State();
    for (int i = 0; i < 2; ++i) {
        Check(m.CallGuestFar16(0x2000, 0x100, 0x7000, {0x1111, 0x2222}) == 0x56783336, "far call arguments/return/CS");
        Check(!m.stopping, m.stopReason.c_str());
        SameState(saved, m.vm.State());
        Check(m.vm.Rd8(0x10200) == 0x90, "return trap not restored");
    }
    const uint8_t nearCode[] = {0x55, 0x89, 0xe5, 0x8b, 0x46, 0x04, 0x03, 0x46, 0x06,
                                0xba, 0xcd, 0xab, 0x5d, 0xc3};
    Check(m.vm.Write(0x10300, nearCode, sizeof nearCode), "write near callee");
    Check(m.CallGuestNear16(0x10300, {12, 13}) == 0xabcd0019, "near call frame");
    SameState(saved, m.vm.State());
    // A translated far seam can call another guest function and then return through RETF.
    const SeamList seams = {{0x20200, "outer", "test", "nested callback", [](Machine& inner) {
        Check(inner.ArgW(0) == 9, "far seam argument offset");
        uint32_t value = inner.CallGuestFar16(0x2000, 0x100, 0, {4, 5});
        Check(value == 0x5678000c, "nested callback result");
        inner.vm.Set16(Reg::Eax, uint16_t(value));
        inner.vm.Set16(Reg::Edx, uint16_t(value >> 16));
    }, 0, 0, Seam::Ret::Far16}};
    m.vm.Wr8(0x20200, 0x90);
    m.InstallSeams(seams, {});
    Check(m.CallGuestFar16(0x2000, 0x200, 0, {9}) == 0x5678000c, "translated far seam return");
    SameState(saved, m.vm.State());
    Check(m.vm.Rd8(0x10200) == 0x90 && m.vm.Rd8(0x20200) == m.vm.Trap(), "nested traps not restored");
    return 0;
}
