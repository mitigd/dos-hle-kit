// Backend-selection regressions, independent of host KVM access and JIT execution.
#include "hlekit/vm.h"

#include <cstdio>
#include <cstdlib>
#include <string>

namespace {
bool kvmAvailable = false, jitAvailable = true;
int kvmCalls = 0, jitCalls = 0;

class StubVcpu final : public hlekit::Vcpu {
public:
    explicit StubVcpu(const char* name) : name_(name) {}
    const char* Name() const override { return name_; }
    bool Init(std::string&) override { return true; }
    uint8_t* Ram() override { return nullptr; }
    hlekit::CpuState& State() override { return state_; }
    void Touch() override {}
    bool RunOnce(std::string&) override { return true; }
    void Kick() override {}
    bool SetDebug(uint32_t, bool, uint32_t, std::string&) override { return true; }
private:
    const char* name_;
    hlekit::CpuState state_;
};

void Check(bool ok, const char* message) {
    if (!ok) {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}
}  // namespace

namespace hlekit {
std::unique_ptr<Vcpu> CreateKvm(std::string& err) {
    ++kvmCalls;
    if (!kvmAvailable) { err = "KVM unavailable"; return nullptr; }
    return std::make_unique<StubVcpu>("kvm");
}

std::unique_ptr<Vcpu> CreateJit(std::string& err) {
    ++jitCalls;
    if (!jitAvailable) { err = "JIT unavailable"; return nullptr; }
    return std::make_unique<StubVcpu>("jit");
}
}  // namespace hlekit

int main() {
    using hlekit::Vcpu;
    std::string err;
    auto cpu = Vcpu::Create("", err);
    Check(cpu && std::string(cpu->Name()) == "jit" && err.empty(), "automatic JIT fallback failed");
    Check(kvmCalls == 1 && jitCalls == 1, "automatic selection did not try KVM then JIT");

    kvmAvailable = true;
    cpu = Vcpu::Create("", err);
    Check(cpu && std::string(cpu->Name()) == "kvm" && jitCalls == 1, "available KVM was not preferred");

    kvmAvailable = false;
    cpu = Vcpu::Create("KvM", err);
    Check(!cpu && err == "KVM unavailable" && jitCalls == 1, "explicit KVM unexpectedly fell back");

    err.clear();
    const int previousKvmCalls = kvmCalls;
    cpu = Vcpu::Create("JiT", err);
    Check(cpu && std::string(cpu->Name()) == "jit" && kvmCalls == previousKvmCalls,
          "explicit JIT attempted KVM");

    jitAvailable = false;
    cpu = Vcpu::Create("", err);
    Check(!cpu && err.find("KVM unavailable") != std::string::npos &&
          err.find("JIT unavailable") != std::string::npos, "both initialization errors must be reported");
    jitAvailable = true;

    // Exercise the same overload the frontend calls, as well as the no-argument overload.
    Check(setenv("HLEKIT_CPU", "kvm", 1) == 0, "setenv failed");
    hlekit::Vm vm;
    Check(!vm.Create("", err), "empty frontend selection ignored explicit HLEKIT_CPU=kvm");
    Check(!vm.Create(err), "default VM selection ignored explicit HLEKIT_CPU=kvm");
    Check(vm.Create("jit", err) && vm.Backend() == "jit", "explicit backend did not override environment");

    Check(setenv("HLEKIT_CPU", "", 1) == 0, "setenv failed");
    Check(vm.Create("", err) && vm.Backend() == "jit", "empty environment disabled automatic fallback");
    Check(unsetenv("HLEKIT_CPU") == 0, "unsetenv failed");
    Check(vm.Create(err) && vm.Backend() == "jit", "unset environment disabled automatic fallback");
    puts("CPU selection regressions passed");
}
