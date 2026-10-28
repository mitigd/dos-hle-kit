// Lifecycle, block cache and the helpers the compiler calls back into. The kit owns guest RAM
// and loads the executable itself, so there are no loaders or host services here.
#include "../JitEngine.h"
#include "../JitPlatform.h"
#include "../JitLog.h"
#include "../Common/Log.h"
#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <sys/mman.h>
#include <unistd.h>

// ---- globals the compiler references -------------------------------------------------------
namespace jitlog {
int g_level = 0;
}
namespace {
struct LogLevelInit {
    LogLevelInit() {
        if (const char* e = getenv("HLEKIT_JIT_LOG")) jitlog::g_level = atoi(e);
        if (const char* e = getenv("HLEKIT_JIT_MAXBLOCK")) g_jitMaxBlockSize = atoi(e);
        if (getenv("HLEKIT_JIT_NOCHAIN")) g_jitDisableChaining = true;
        if (getenv("HLEKIT_JIT_EAGER_FLAGS")) g_jitEagerFlags = true;
    }
} logLevelInit;
}
FarRegisterOverrides g_farRegisterOverrides;
int g_jitMaxBlockSize = 0;
bool g_jitDisableChaining = false;
bool g_jitEagerFlags = false;

JitEngine::JitEngine() {
    guestMemory = nullptr;
    memorySize = 0;
    trapPageBase = 0xF1000000;   // outside guest RAM: 0 would make every low address a trap
    gdtBase = 0;
    memset(&context, 0, sizeof(context));
    context.pendingInt = 0xFF;
    context.fpuControl = 0x037F;
    context.fpuTag = 0xFFFF;
}

JitEngine::~JitEngine() {
    ClearCachedBlocks();
    guestMemory = nullptr;   // owned by the kit's Vm
}

bool JitEngine::Initialize(uint8_t* memory, size_t size, std::string& err) {
    guestMemory = memory;
    memorySize = size;
    if (!guestMemory) return err = "jit: no guest memory", false;
    const long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || (page & (page - 1)) || ((uintptr_t)memory & (page - 1)))
        return err = "jit: guest RAM must be host-page aligned", false;
    hostPageShift = (uint32_t)__builtin_ctzl((unsigned long)page);
    hostPageMask = (uintptr_t)page - 1;
    const size_t pages = (size + hostPageMask) >> hostPageShift;
    pageBlocks.assign(pages, {});
    pageProtected.assign(pages, 0);
    pageDirtyStore.assign(pages, 0);
    pageDirty = pageDirtyStore.data();
    context.eflags = 0x202;
    context.pendingInt = 0xFF;
    return true;
}

uint8_t JitEngine::Read8(uint64_t address) {
    return address < memorySize ? guestMemory[address] : 0;
}

uint32_t JitEngine::Read32(uint64_t address) {
    uint32_t v = 0;
    if (address + 4 <= memorySize) memcpy(&v, guestMemory + address, 4);
    return v;
}

// ---- block cache ----------------------------------------------------------------------------

JitEngine::CachedBlock* JitEngine::FindCachedBlock(uint32_t eip) {
    LookupEntry& cached = lookup[eip & (kLookupSize - 1)];
    if (cached.block && cached.eip == eip) return cached.block;
    auto it = blocks.find(eip);
    cached.eip = eip;
    cached.block = it != blocks.end() ? &it->second.entry : nullptr;
    return cached.block;
}

bool JitEngine::RestoreCachedBlock(uint32_t eip) {
    if (eip >= memorySize) return false;
    auto [first, last] = dormantIndex.equal_range(eip);
    for (auto it = first; it != last; ++it) {
        auto saved = it->second;
        const Block& b = saved->block;
        if (b.source.empty() || b.source.size() > memorySize - eip ||
            memcmp(guestMemory + eip, b.source.data(), b.source.size())) continue;
        Block restored = std::move(saved->block);
        dormant.erase(saved);
        dormantIndex.erase(it);
        StoreBlock(eip, restored.end, restored.entry, std::move(restored.exits));
        ++smcRestored;
        return true;
    }
    return false;
}

void JitEngine::StoreBlock(uint32_t eip, uint32_t end, const CachedBlock& entry,
                           std::vector<std::pair<uint32_t, Link>>&& exits) {
    if (blocks.count(eip)) DropBlock(eip);
    const bool inRam = eip < memorySize;   // the trap page lies outside guest RAM
    end = inRam ? std::max(std::min<uint32_t>(end, (uint32_t)memorySize), eip + 1) : eip;
    Block& b = blocks[eip];
    b.entry = entry;
    LookupEntry& cached = lookup[eip & (kLookupSize - 1)];
    cached.eip = eip;
    cached.block = &b.entry;
    b.start = eip;
    b.end = end;
    if (inRam) b.source.assign(guestMemory + eip, guestMemory + end);
    b.exits = std::move(exits);
    for (auto& [target, link] : b.exits) {
        auto t = blocks.find(target);
        *link.slot = (t != blocks.end() && t->second.entry.hotEntry) ? t->second.entry.hotEntry : link.slowPath;
        links[target].push_back(link);
        b.exitTargets.push_back(target);
    }
    // Slots elsewhere that were waiting for this block (or for its previous translation).
    if (entry.hotEntry) {
        auto in = links.find(eip);
        if (in != links.end())
            for (Link& l : in->second) *l.slot = entry.hotEntry;
    }
    if (!inRam) return;
    for (uint32_t p = eip >> hostPageShift; p <= (end - 1) >> hostPageShift; ++p) pageBlocks[p].push_back(eip);
    ProtectRange(eip, end);
}

void JitEngine::DropBlock(uint32_t eip, bool park) {
    auto it = blocks.find(eip);
    if (it == blocks.end()) return;
    LookupEntry& cached = lookup[eip & (kLookupSize - 1)];
    if (cached.block && cached.eip == eip) cached.block = nullptr;
    Block& b = it->second;
    // Slots aimed at this block fall back to their slow path (the run loop), which compiles a
    // fresh translation on the next visit; the slots stay registered so it relinks them.
    auto in = links.find(eip);
    if (in != links.end())
        for (Link& l : in->second) *l.slot = l.slowPath;
    // The slots this block owns die with its code.
    for (uint32_t target : b.exitTargets) {
        auto t = links.find(target);
        if (t == links.end()) continue;
        auto& v = t->second;
        v.erase(std::remove_if(v.begin(), v.end(), [&](const Link& l) { return l.owner == eip; }), v.end());
        if (v.empty()) links.erase(t);
    }
    for (uint32_t p = b.start >> hostPageShift; b.end > b.start && p <= (b.end - 1) >> hostPageShift; ++p) {
        auto& v = pageBlocks[p];
        v.erase(std::remove(v.begin(), v.end(), eip), v.end());
    }
    // Nothing is executing (we are in the run loop) and nothing links here any more.
    if (park && b.start < memorySize) {
        dormant.push_back({eip, std::move(b)});
        dormantIndex.emplace(eip, std::prev(dormant.end()));
        if (dormant.size() > kDormantLimit) {
            auto oldest = dormant.begin();
            auto [first, last] = dormantIndex.equal_range(oldest->eip);
            for (auto d = first; d != last; ++d)
                if (d->second == oldest) { dormantIndex.erase(d); break; }
            jitRuntime.release(oldest->block.entry.coldEntry);
            dormant.erase(oldest);
            ++smcEvicted;
        }
    } else {
        jitRuntime.release(b.entry.coldEntry);
    }
    blocks.erase(it);
    ++smcInvalidated;
}

void JitEngine::ClearCachedBlocks() {
    while (!blocks.empty()) DropBlock(blocks.begin()->first);
    for (auto& saved : dormant) jitRuntime.release(saved.block.entry.coldEntry);
    dormant.clear();
    dormantIndex.clear();
    links.clear();
    for (size_t p = 0; p < pageProtected.size(); ++p)
        if (pageProtected[p]) {
            mprotect(guestMemory + (p << hostPageShift), (size_t)1 << hostPageShift, PROT_READ | PROT_WRITE);
            pageProtected[p] = 0;
        }
}

void JitEngine::ProtectRange(uint32_t start, uint32_t end) {
    for (uint32_t p = start >> hostPageShift; p <= (end - 1) >> hostPageShift; ++p) {
        if (pageProtected[p] || pageDirty[p]) continue;   // a dirty page is protected again by SyncDirtyCode
        if (mprotect(guestMemory + ((size_t)p << hostPageShift), (size_t)1 << hostPageShift, PROT_READ) == 0)
            pageProtected[p] = 1;

    }
}

bool JitEngine::OnWriteFault(const void* hostAddr) {
    // Async-signal context: mprotect and plain stores only.
    const uintptr_t a = (uintptr_t)hostAddr, base = (uintptr_t)guestMemory;
    if (!guestMemory || a < base || a >= base + memorySize) return false;
    const size_t p = (a - base) >> hostPageShift;
    if (!pageProtected[p]) return false;
    if (mprotect(guestMemory + (p << hostPageShift), (size_t)1 << hostPageShift, PROT_READ | PROT_WRITE)) return false;
    pageProtected[p] = 0;
    MarkDirty(p);
    ++smcFaults;
    return true;
}

void JitEngine::Invalidate(uint32_t addr, uint32_t len) {
    if (!len || addr >= memorySize) return;
    const uint32_t last = (uint32_t)std::min<uint64_t>((uint64_t)addr + len - 1, memorySize - 1);
    for (uint32_t p = addr >> hostPageShift; p <= last >> hostPageShift; ++p) {
        if (!pageProtected[p]) {
            if (!pageBlocks[p].empty()) MarkDirty(p);
            continue;
        }
        mprotect(guestMemory + ((size_t)p << hostPageShift), (size_t)1 << hostPageShift, PROT_READ | PROT_WRITE);
        pageProtected[p] = 0;
        MarkDirty(p);
    }
}

void JitEngine::MarkDirty(size_t p) {
    if (!pageDirty[p]) {
        pageDirty[p] = 1;
        const uint32_t n = dirtyCount;
        if (n < kDirtyList) dirtyList[n] = (uint32_t)p;
        dirtyCount = n + 1;                       // past kDirtyList: SyncDirtyCode scans everything
    }
    smcPending = 1;
}

void JitEngine::SyncDirtyCode() {
    smcPending = 0;
    std::vector<uint32_t> pages;
    const uint32_t n = dirtyCount;
    if (n <= kDirtyList) {
        pages.assign(dirtyList, dirtyList + n);
    } else {
        for (size_t p = 0; p < pageBlocks.size(); ++p)
            if (pageDirty[p]) pages.push_back((uint32_t)p);
    }
    dirtyCount = 0;
    std::vector<uint32_t> stale;
    for (uint32_t p : pages) {
        if (!pageDirty[p]) continue;
        pageDirty[p] = 0;
        for (uint32_t eip : pageBlocks[p]) {
            const Block& b = blocks.at(eip);
            if (memcmp(guestMemory + b.start, b.source.data(), b.source.size())) stale.push_back(eip);
        }
        for (uint32_t eip : stale) DropBlock(eip, true);
        if (!stale.empty() && jitlog::g_level)
            fprintf(stderr, "[jit] smc: page %08x: %zu translations dropped\n", p << hostPageShift, stale.size());
        stale.clear();
        if (!pageBlocks[p].empty()) ProtectRange(p << hostPageShift, (p << hostPageShift) + 1);
    }
}

void JitEngine::ExecuteJit(void* hostCode) {
    context.chainBudget = kMaxChainBudget;
    ((JitFunction)hostCode)(&context, guestMemory, this);
}

// ---- selector helpers the compiler emits calls to -------------------------------------------

uint32_t JitEngine::GetLinearAddress(uint16_t selector, uint32_t offset) {
    if (selector == 0) return offset;
    if (isMZ) return ((uint32_t)selector << 4) + offset;
    // The kit builds real descriptors in guest memory (flat for DOS/4GW).
    const uint32_t at = gdtBase + (selector & ~7u);
    uint64_t d = 0;
    if (gdtBase && at + 8 <= memorySize) memcpy(&d, guestMemory + at, 8);
    const uint32_t base = (uint32_t)(((d >> 16) & 0xFFFFFF) | ((d >> 56) << 24));
    return base + offset;
}

bool JitEngine::VerifySelectorAccess(uint16_t selector, bool write) {
    if (isMZ || (selector & 0xFFFC) == 0) return false;
    const uint32_t at = gdtBase + (selector & ~7u);
    if (!gdtBase || at + 8 > memorySize) return false;
    uint64_t d = 0;
    memcpy(&d, guestMemory + at, 8);
    const uint8_t access = (uint8_t)((d >> 40) & 0xFF);
    if ((access & 0x90) != 0x90) return false;              // not present or a system segment
    if (access & 0x08) return !write && (access & 0x02);    // code: readable, never writable
    return !write || (access & 0x02);                       // data
}

void JitEngine::UpdateSegBase(int regId, uint16_t selector) {
    const uint32_t base = GetLinearAddress(selector, 0);
    switch (regId) {
        case ZYDIS_REGISTER_CS: context.cs = selector; context.csBase = base; break;
        case ZYDIS_REGISTER_DS: context.ds = selector; context.dsBase = base; break;
        case ZYDIS_REGISTER_ES: context.es = selector; context.esBase = base; break;
        case ZYDIS_REGISTER_SS: context.ss = selector; context.ssBase = base; break;
        case ZYDIS_REGISTER_FS: context.fs = selector; context.fsBase = base; break;
        case ZYDIS_REGISTER_GS: context.gs = selector; context.gsBase = base; break;
        default: break;
    }
}

void JitEngine::UpdateSegBaseStub(CpuContext*, uint8_t*, JitEngine* engine, int regId, uint16_t selector) {
    engine->UpdateSegBase(regId, selector);
}

void JitEngine::UpdateSegRegFromContextStub(CpuContext* ctx, uint8_t*, JitEngine* engine, int regId) {
    uint16_t selector = 0;
    switch (regId) {
        case ZYDIS_REGISTER_ES: selector = ctx->es; break;
        case ZYDIS_REGISTER_CS: selector = ctx->cs; break;
        case ZYDIS_REGISTER_SS: selector = ctx->ss; break;
        case ZYDIS_REGISTER_DS: selector = ctx->ds; break;
        case ZYDIS_REGISTER_FS: selector = ctx->fs; break;
        case ZYDIS_REGISTER_GS: selector = ctx->gs; break;
        default: break;
    }
    engine->UpdateSegBase(regId, selector);
}
