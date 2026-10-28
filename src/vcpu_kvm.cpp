// KVM backend: Linux only, /dev/kvm. The hardware runs the original code; the kit only ever
// sees exits. One vCPU, protected mode, no paging, guest physical == host offset.
#include "hlekit/vcpu.h"

#include <linux/kvm.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>

namespace hlekit {

namespace {

void SigNop(int) {}   // SIGUSR1 only has to break KVM_RUN (-EINTR)

std::string Errno(const char* what) { return std::string(what) + ": " + strerror(errno); }

kvm_segment ToKvm(const SegState& st) {
    kvm_segment k{};
    k.base = st.base;
    k.limit = st.limit;
    k.selector = st.sel;
    k.type = st.access & 0x0F;
    k.s = (st.access >> 4) & 1;
    k.dpl = (st.access >> 5) & 3;
    k.present = (st.access >> 7) & 1;
    k.avl = 0;
    k.l = 0;
    k.db = st.big;
    k.g = st.gran;
    k.unusable = st.unusable ? 1 : 0;
    return k;
}

SegState FromKvm(const kvm_segment& k) {
    SegState st;
    st.base = k.base;
    st.limit = k.limit;
    st.sel = k.selector;
    st.access = (uint8_t)(k.type | k.s << 4 | k.dpl << 5 | k.present << 7);
    st.big = k.db != 0;
    st.gran = k.g != 0;
    st.unusable = k.unusable != 0;
    return st;
}

class KvmVcpu final : public Vcpu {
public:
    ~KvmVcpu() override {
        if (run_) munmap(run_, runSize_);
        if (mem_) munmap(mem_, kRam);
        for (int fd : {vcpu_, vm_, kvm_})
            if (fd >= 0) close(fd);
    }

    const char* Name() const override { return "kvm"; }
    uint8_t* Ram() override { return mem_; }
    CpuState& State() override { return state_; }
    void Touch() override { dirty_ = true; }

    bool Init(std::string& err) override {
        kvm_ = open("/dev/kvm", O_RDWR | O_CLOEXEC);
        if (kvm_ < 0) return err = Errno("open /dev/kvm"), false;
        if (ioctl(kvm_, KVM_GET_API_VERSION, 0) != KVM_API_VERSION) return err = "unexpected KVM API version", false;
        vm_ = ioctl(kvm_, KVM_CREATE_VM, 0);
        if (vm_ < 0) return err = Errno("KVM_CREATE_VM"), false;
        ioctl(vm_, KVM_SET_TSS_ADDR, 0xFFFBD000ul);   // required on Intel, unused by us
        mem_ = (uint8_t*)mmap(nullptr, kRam, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (mem_ == MAP_FAILED) return mem_ = nullptr, err = Errno("mmap guest RAM"), false;
        kvm_userspace_memory_region region{};
        region.slot = 0;
        region.guest_phys_addr = 0;
        region.memory_size = kRam;
        region.userspace_addr = (uint64_t)mem_;
        if (ioctl(vm_, KVM_SET_USER_MEMORY_REGION, &region) < 0) return err = Errno("KVM_SET_USER_MEMORY_REGION"), false;

        vcpu_ = ioctl(vm_, KVM_CREATE_VCPU, 0);
        if (vcpu_ < 0) return err = Errno("KVM_CREATE_VCPU"), false;
        int sz = ioctl(kvm_, KVM_GET_VCPU_MMAP_SIZE, 0);
        if (sz <= 0) return err = "KVM_GET_VCPU_MMAP_SIZE failed", false;
        runSize_ = (size_t)sz;
        run_ = (kvm_run*)mmap(nullptr, runSize_, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_, 0);
        if (run_ == MAP_FAILED) return run_ = nullptr, err = Errno("mmap kvm_run"), false;

        // Seed the state from the fresh vCPU: Enter() overrides what the kit controls, and the
        // fields it leaves alone (TR, APIC base) must stay what the hardware expects.
        kvm_regs r{};
        kvm_sregs s{};
        if (ioctl(vcpu_, KVM_GET_REGS, &r) < 0 || ioctl(vcpu_, KVM_GET_SREGS, &s) < 0)
            return err = Errno("KVM_GET_REGS/KVM_GET_SREGS"), false;
        PullRegs(r);
        PullSregs(s);
        auxSregs_ = s;

        // Minimal CPUID: vendor + a 486/Pentium-class feature set.
        auto* cpuid = (kvm_cpuid2*)calloc(1, sizeof(kvm_cpuid2) + 2 * sizeof(kvm_cpuid_entry2));
        cpuid->nent = 2;
        auto leaf = [&](int i, uint32_t fn, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
            kvm_cpuid_entry2& e = cpuid->entries[i];
            e.function = fn;
            e.eax = a; e.ebx = b; e.ecx = c; e.edx = d;
        };
        leaf(0, 0, 1, 0x756E6547, 0x6C65746E, 0x49656E69);                       // GenuineIntel
        leaf(1, 1, 0x000006F2, 0, 0, (1u << 0) | (1u << 4) | (1u << 8) | (1u << 15));   // FPU TSC CX8 CMOV
        if (ioctl(vcpu_, KVM_SET_CPUID2, cpuid) < 0) { free(cpuid); return err = Errno("KVM_SET_CPUID2"), false; }
        free(cpuid);

        struct sigaction sa{};
        sa.sa_handler = SigNop;
        sa.sa_flags = SA_RESTART;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR1, &sa, nullptr);
        return true;
    }

    bool RunOnce(std::string& err) override {
        thread_ = pthread_self();
        haveThread_ = true;
        exit = ExitInfo{};
        if (dirty_ && !Apply(err)) return false;
        dirty_ = false;
        int rc = ioctl(vcpu_, KVM_RUN, 0);
        int e = errno;
        run_->immediate_exit = 0;   // a kick after this point re-arms it, so none is lost
        kvm_regs r{};
        if (ioctl(vcpu_, KVM_GET_REGS, &r) < 0) return err = Errno("KVM_GET_REGS"), false;
        kvm_sregs s{};
        if (ioctl(vcpu_, KVM_GET_SREGS, &s) < 0) return err = Errno("KVM_GET_SREGS"), false;
        PullRegs(r);
        PullSregs(s);
        auxSregs_ = s;
        if (rc < 0) {
            if (e == EINTR || e == EAGAIN) { exit.reason = Exit::Intr; return true; }
            errno = e;
            return err = Errno("KVM_RUN"), false;
        }
        exit.raw = run_->exit_reason;
        switch (run_->exit_reason) {
            case KVM_EXIT_HLT: exit.reason = Exit::Hlt; break;
            case KVM_EXIT_IO:
                exit.reason = Exit::Io;
                exit.port = run_->io.port;
                exit.size = run_->io.size;
                exit.ioCount = run_->io.count;
                exit.out = run_->io.direction == KVM_EXIT_IO_OUT;
                exit.data = exit.out ? nullptr : (uint8_t*)run_ + run_->io.data_offset;
                break;
            case KVM_EXIT_MMIO:
                exit.reason = Exit::Mmio;
                exit.addr = run_->mmio.phys_addr;
                exit.write = run_->mmio.is_write != 0;
                exit.len = run_->mmio.len;
                break;
            case KVM_EXIT_INTR: exit.reason = Exit::Intr; break;
            case KVM_EXIT_IRQ_WINDOW_OPEN: exit.reason = Exit::Window; break;
            case KVM_EXIT_SHUTDOWN: exit.reason = Exit::Shutdown; break;
            case KVM_EXIT_FAIL_ENTRY:
                exit.reason = Exit::FailEntry;
                exit.failReason = run_->fail_entry.hardware_entry_failure_reason;
                break;
            case KVM_EXIT_INTERNAL_ERROR:
                exit.reason = Exit::Internal;
                exit.suberror = run_->internal.suberror;
                break;
            case KVM_EXIT_DEBUG:
                exit.reason = Exit::Debug;
                exit.pc = run_->debug.arch.pc;
                exit.exception = run_->debug.arch.exception;
                exit.dr6 = (uint32_t)run_->debug.arch.dr6;
                break;
            default: exit.reason = Exit::Other; break;
        }
        return true;
    }

    void Kick() override {
        if (run_) run_->immediate_exit = 1;
        if (haveThread_) pthread_kill(thread_, SIGUSR1);
    }

    void SetInterruptWindow(bool on) override {
        if (run_) run_->request_interrupt_window = on ? 1 : 0;
    }

    bool SetDebug(uint32_t bp, bool step, uint32_t watch, std::string& err) override {
        kvm_guest_debug dbg{};
        const bool ring3 = state_.ring3;
        if (bp || step || watch || ring3) dbg.control = KVM_GUESTDBG_ENABLE;
        if (ring3) dbg.control |= KVM_GUESTDBG_USE_SW_BP;      // int3 traps exit to the host
        if (step) dbg.control |= KVM_GUESTDBG_SINGLESTEP;
        if (bp || watch) dbg.control |= KVM_GUESTDBG_USE_HW_BP;
        if (bp) {
            dbg.arch.debugreg[0] = bp;
            dbg.arch.debugreg[7] |= 0x1;                        // L0, execute, 1 byte
        }
        if (watch) {
            dbg.arch.debugreg[1] = watch & ~3u;
            dbg.arch.debugreg[7] |= 0x4 | 0x1u << 20 | 0x3u << 22;   // L1, write, 4 bytes
        }
        if (ioctl(vcpu_, KVM_SET_GUEST_DEBUG, &dbg) < 0) return err = Errno("KVM_SET_GUEST_DEBUG"), false;
        return true;
    }

private:
    bool Apply(std::string& err) {
        kvm_regs r{};
        r.rax = state_.reg[(int)Reg::Eax];
        r.rbx = state_.reg[(int)Reg::Ebx];
        r.rcx = state_.reg[(int)Reg::Ecx];
        r.rdx = state_.reg[(int)Reg::Edx];
        r.rsi = state_.reg[(int)Reg::Esi];
        r.rdi = state_.reg[(int)Reg::Edi];
        r.rbp = state_.reg[(int)Reg::Ebp];
        r.rsp = state_.reg[(int)Reg::Esp];
        r.rip = state_.reg[(int)Reg::Eip];
        r.rflags = state_.reg[(int)Reg::Eflags];
        if (ioctl(vcpu_, KVM_SET_REGS, &r) < 0) return err = Errno("KVM_SET_REGS"), false;

        kvm_sregs s = auxSregs_;        // TR, APIC base and the rest are not ours: keep what the CPU had
        s.cs = ToKvm(state_.seg[(int)Seg::Cs]);
        s.ds = ToKvm(state_.seg[(int)Seg::Ds]);
        s.es = ToKvm(state_.seg[(int)Seg::Es]);
        s.fs = ToKvm(state_.seg[(int)Seg::Fs]);
        s.gs = ToKvm(state_.seg[(int)Seg::Gs]);
        s.ss = ToKvm(state_.seg[(int)Seg::Ss]);
        if (state_.hasLdt) s.ldt = ToKvm(state_.ldt);
        s.gdt.base = state_.gdtBase;
        s.gdt.limit = state_.gdtLimit;
        s.idt.base = state_.idtBase;
        s.idt.limit = state_.idtLimit;
        s.cr0 = state_.cr0;
        s.cr4 = state_.cr4;
        s.efer = state_.efer;
        if (ioctl(vcpu_, KVM_SET_SREGS, &s) < 0) return err = Errno("KVM_SET_SREGS"), false;
        return true;
    }

    void PullRegs(const kvm_regs& r) {
        state_.reg[(int)Reg::Eax] = (uint32_t)r.rax;
        state_.reg[(int)Reg::Ebx] = (uint32_t)r.rbx;
        state_.reg[(int)Reg::Ecx] = (uint32_t)r.rcx;
        state_.reg[(int)Reg::Edx] = (uint32_t)r.rdx;
        state_.reg[(int)Reg::Esi] = (uint32_t)r.rsi;
        state_.reg[(int)Reg::Edi] = (uint32_t)r.rdi;
        state_.reg[(int)Reg::Ebp] = (uint32_t)r.rbp;
        state_.reg[(int)Reg::Esp] = (uint32_t)r.rsp;
        state_.reg[(int)Reg::Eip] = (uint32_t)r.rip;
        state_.reg[(int)Reg::Eflags] = (uint32_t)r.rflags;
    }

    void PullSregs(const kvm_sregs& s) {
        state_.seg[(int)Seg::Cs] = FromKvm(s.cs);
        state_.seg[(int)Seg::Ds] = FromKvm(s.ds);
        state_.seg[(int)Seg::Es] = FromKvm(s.es);
        state_.seg[(int)Seg::Fs] = FromKvm(s.fs);
        state_.seg[(int)Seg::Gs] = FromKvm(s.gs);
        state_.seg[(int)Seg::Ss] = FromKvm(s.ss);
        state_.ldt = FromKvm(s.ldt);
        state_.hasLdt = s.ldt.present != 0;
        state_.gdtBase = s.gdt.base;
        state_.gdtLimit = (uint16_t)s.gdt.limit;
        state_.idtBase = s.idt.base;
        state_.idtLimit = (uint16_t)s.idt.limit;
        state_.cr0 = s.cr0;
        state_.cr4 = s.cr4;
        state_.efer = s.efer;
    }

    CpuState state_;
    kvm_sregs auxSregs_{};              // sregs the kit does not own (TR, APIC base, ...) are carried through
    bool dirty_ = true;
    uint8_t* mem_ = nullptr;
    kvm_run* run_ = nullptr;
    size_t runSize_ = 0;
    int kvm_ = -1, vm_ = -1, vcpu_ = -1;
    pthread_t thread_{};
    bool haveThread_ = false;
};

}  // namespace

std::unique_ptr<Vcpu> CreateKvm(std::string& err) {
    auto v = std::make_unique<KvmVcpu>();
    if (!v->Init(err)) return nullptr;
    return v;
}

}  // namespace hlekit
