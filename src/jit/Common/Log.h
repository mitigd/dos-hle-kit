// Logging sink for the JIT compiler, writing to stderr.
//
// The kit's own diagnostics are the [hw]/[cpu] reports; block-compile chatter is opt-in:
// HLEKIT_JIT_LOG=1 (info) or 2 (debug).
#pragma once

#include <iostream>
#include <string>

namespace jitlog {

extern int g_level;

struct Logger {
    bool on;
    explicit Logger(int lvl) : on(g_level >= lvl) {}
    ~Logger() { if (on) std::cerr << "\n"; }
    template <class T>
    Logger& operator<<(const T& v) { if (on) std::cerr << v; return *this; }
    Logger& operator<<(std::ostream& (*f)(std::ostream&)) { if (on) f(std::cerr); return *this; }
};

}  // namespace jitlog

#define LOG_ERROR jitlog::Logger(0)
#define LOG_INFO jitlog::Logger(1)
#define LOG_DEBUG jitlog::Logger(2)
