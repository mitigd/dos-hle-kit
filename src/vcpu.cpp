// Backend selection. A kit build links one or more engines; this file knows their names and
// picks the default for the host.
#include "hlekit/vcpu.h"

#include <algorithm>
#include <cctype>

namespace hlekit {

#if defined(HLEKIT_HAVE_KVM)
std::unique_ptr<Vcpu> CreateKvm(std::string& err);
#endif
#if defined(HLEKIT_HAVE_WHPX)
std::unique_ptr<Vcpu> CreateWhpx(std::string& err);
#endif
#if defined(HLEKIT_HAVE_JIT)
std::unique_ptr<Vcpu> CreateJit(std::string& err);
#endif

namespace {

std::string Lower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

std::string Join(const std::vector<std::string>& v) {
    std::string s;
    for (auto& x : v) s += (s.empty() ? "" : ", ") + x;
    return s;
}

}  // namespace

std::vector<std::string> Vcpu::Available() {
    std::vector<std::string> v;
#if defined(HLEKIT_HAVE_KVM)
    v.push_back("kvm");
#endif
#if defined(HLEKIT_HAVE_WHPX)
    v.push_back("whpx");
#endif
#if defined(HLEKIT_HAVE_JIT)
    v.push_back("jit");
#endif
#if defined(__EMSCRIPTEN__)
    v.push_back("web");        // alias for jit in a browser build
#endif
    return v;
}

std::string Vcpu::Default() {
#if defined(__EMSCRIPTEN__)
    return "jit";              // no hardware virtualisation in a browser
#elif defined(_WIN32) && defined(HLEKIT_HAVE_WHPX)
    return "whpx";
#elif defined(__linux__) && defined(HLEKIT_HAVE_KVM)
    return "kvm";
#elif defined(HLEKIT_HAVE_JIT)
    return "jit";
#else
    return Available().empty() ? "" : Available().front();
#endif
}

std::unique_ptr<Vcpu> Vcpu::Create(const std::string& name, std::string& err) {
    const std::string n = Lower(name.empty() ? Default() : name);
    if (n.empty()) { err = "this kit build has no CPU backend"; return nullptr; }

    if (n == "kvm") {
#if defined(HLEKIT_HAVE_KVM)
        return CreateKvm(err);
#else
        return err = "kvm backend is not built into this kit (Linux only; available: " + Join(Available()) + ")", nullptr;
#endif
    }
    if (n == "whpx") {
#if defined(HLEKIT_HAVE_WHPX)
        return CreateWhpx(err);
#else
        return err = "whpx backend is not built into this kit (Windows 10+ only)", nullptr;
#endif
    }
    if (n == "jit" || n == "web") {
#if defined(HLEKIT_HAVE_JIT)
        return CreateJit(err);
#else
        return err = "jit backend is not built into this kit", nullptr;
#endif
    }
    err = "unknown cpu backend '" + name + "' (available: " + Join(Available()) + ")";
    return nullptr;
}

}  // namespace hlekit
