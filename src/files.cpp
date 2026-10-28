#include "hlekit/files.h"

#include "hlekit/machine.h"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace hlekit {

namespace fs = std::filesystem;

namespace {
std::string Lower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}
std::shared_ptr<FILE> Own(FILE* f) { return std::shared_ptr<FILE>(f, [](FILE* p) { fclose(p); }); }
}  // namespace

std::string HostFiles::Rel(const std::string& guest) const {
    std::string p = guest;
    std::replace(p.begin(), p.end(), '\\', '/');
    if (p.size() > 1 && p[1] == ':') p.erase(0, 2);
    while (!p.empty() && p[0] == '/') p.erase(0, 1);
    for (const std::string& entry : m_.dosDirAliases) {
        const std::string alias = Lower(entry), lower = Lower(p);
        if (lower == alias) { p.clear(); break; }
        if (lower.rfind(alias + "/", 0) == 0) { p.erase(0, alias.size() + 1); break; }
    }
    std::vector<std::string> parts;
    std::stringstream in(p);
    std::string part;
    while (std::getline(in, part, '/')) {
        if (part.empty() || part == ".") continue;
        if (part == "..") { if (!parts.empty()) parts.pop_back(); continue; }
        parts.push_back(part);
    }
    std::string rel;
    for (auto& s : parts) rel += (rel.empty() ? "" : "/") + s;
    return rel;
}

std::string HostFiles::GuestRel(uint32_t linear, size_t max) const { return Rel(m_.vm.CStr(linear, (uint32_t)max)); }

std::string HostFiles::OverlayPath(const std::string& rel) const { return (fs::path(m_.overlayDir) / Lower(rel)).string(); }

// A directory's entries by lower-case name, listed once. The game and fallback directories are never
// written (writes go to the overlay), so a listing stays valid; on slow media (an exFAT SD card)
// re-listing a directory for every missing file costs seconds.
const HostFiles::Listing& HostFiles::List(const fs::path& dir) {
    auto it = listings_.find(dir.string());
    if (it != listings_.end()) return it->second;
    Listing& names = listings_[dir.string()];
    std::error_code ec;
    for (auto& e : fs::directory_iterator(dir, ec)) names[Lower(e.path().filename().string())] = e.path();
    return names;
}

std::string HostFiles::FindCi(const std::string& root, const std::string& rel) {
    fs::path cur = root;
    size_t start = 0;
    while (start <= rel.size()) {
        const size_t end = rel.find('/', start);
        const std::string part = rel.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (!part.empty() && part != ".") {
            const Listing& names = List(cur);
            auto hit = names.find(Lower(part));
            if (hit == names.end()) return {};
            cur = hit->second;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return cur.string();
}

std::string HostFiles::Resolve(const std::string& rel, bool forWrite) {
    const fs::path ov = OverlayPath(rel);
    std::error_code ec;
    auto source = [&] {
        std::string src = FindCi(m_.gameDir, rel);
        if (src.empty() && !m_.fallbackGameDir.empty()) src = FindCi(m_.fallbackGameDir, rel);
        return src;
    };
    if (forWrite) {
        fs::create_directories(ov.parent_path(), ec);
        if (!fs::exists(ov, ec)) {
            const std::string src = source();
            if (!src.empty() && fs::is_regular_file(src, ec)) fs::copy_file(src, ov, ec);
        }
        return ov.string();
    }
    if (fs::exists(ov, ec)) return ov.string();
    return source();
}

bool HostFiles::MatchMask(const std::string& name, const std::string& pattern) {
    const std::string n = Lower(name), p = Lower(pattern);
    size_t i = 0, j = 0, star = std::string::npos, mark = 0;
    while (i < n.size()) {
        if (j < p.size() && (p[j] == '?' || p[j] == n[i])) { ++i; ++j; }
        else if (j < p.size() && p[j] == '*') { star = j++; mark = i; }
        else if (star != std::string::npos) { j = star + 1; i = ++mark; }
        else return false;
    }
    while (j < p.size() && (p[j] == '*' || p[j] == '.')) ++j;
    return j == p.size();
}

std::vector<HostFiles::Entry> HostFiles::List(const std::string& dir, const std::string& mask, bool withDirs) {
    std::map<std::string, Entry> byName;   // fallback (CD/source), then install, then overlay: later wins
    std::vector<std::string> roots;
    if (!m_.fallbackGameDir.empty()) roots.push_back(FindCi(m_.fallbackGameDir, dir));
    roots.push_back(FindCi(m_.gameDir, dir));
    roots.push_back(OverlayPath(dir));
    for (const std::string& root : roots) {
        std::error_code ec;
        if (root.empty() || !fs::is_directory(root, ec)) continue;
        for (auto& e : fs::directory_iterator(root, ec)) {
            const std::string n = e.path().filename().string();
            if (!MatchMask(n, mask)) continue;
            const bool isDir = e.is_directory(ec);
            if (isDir && !withDirs) continue;
            byName[Lower(n)] = {n, isDir ? 0u : (uint32_t)e.file_size(ec), isDir};
        }
    }
    std::vector<Entry> out;
    for (auto& [k, e] : byName) out.push_back(e);
    return out;
}

void HostFiles::WriteDta(uint32_t dta, const Entry& e) const {
    Vm& vm = m_.vm;
    vm.Wr8(dta + 0x15, e.dir ? 0x10 : 0x20);
    vm.Wr16(dta + 0x16, 0);
    vm.Wr16(dta + 0x18, (16 << 9) | (12 << 5) | 24);             // 1996-12-24, as the files
    vm.Wr32(dta + 0x1A, e.size);
    char name[13] = {};
    std::string up = e.name;
    for (auto& c : up) c = (char)toupper((unsigned char)c);
    memcpy(name, up.c_str(), std::min<size_t>(up.size(), 12));
    vm.Write(dta + 0x1E, name, 13);
}

uint16_t HostFiles::FreeHandle() const {
    // DOS hands out the lowest free entry of the process's handle table (20 by default; C run-times
    // size their own tables on that). 0-4 are the standard devices.
    for (uint16_t h = 5; h < 20; ++h)
        if (!streams_.count(h)) return h;
    return 0;
}

uint16_t HostFiles::Open(const std::string& rel, int accessMode) {
    const uint16_t h = FreeHandle();
    if (!h || rel.empty()) return kFail;
    const bool write = (accessMode & 3) != 0;
    const std::string host = Resolve(rel, write);
    FILE* f = host.empty() ? nullptr : fopen(host.c_str(), write ? "r+b" : "rb");
    if (m_.logServices) fprintf(stderr, "[file] open '%s' %s -> %s\n", rel.c_str(), write ? "rw" : "r", f ? "ok" : "not found");
    if (!f) return kFail;
    streams_[h] = Own(f);
    return h;
}

uint16_t HostFiles::Create(const std::string& rel) {
    const uint16_t h = FreeHandle();
    if (!h || rel.empty()) return kFail;
    FILE* f = fopen(Resolve(rel, true).c_str(), "w+b");
    if (m_.logServices) fprintf(stderr, "[file] create '%s' -> %s\n", rel.c_str(), f ? "ok" : "FAILED");
    if (!f) return kFail;
    streams_[h] = Own(f);
    return h;
}

size_t HostFiles::Read(uint16_t h, uint8_t* buf, size_t n) {
    auto it = streams_.find(h);
    return it == streams_.end() ? 0 : fread(buf, 1, n, it->second.get());
}

size_t HostFiles::Write(uint16_t h, const uint8_t* buf, size_t n) {
    auto it = streams_.find(h);
    return it == streams_.end() ? 0 : fwrite(buf, 1, n, it->second.get());
}

size_t HostFiles::ReadTo(uint16_t h, uint32_t at, size_t n) {
    std::vector<uint8_t> tmp(n);
    const size_t got = Read(h, tmp.data(), n);
    m_.vm.Write(at, tmp.data(), (uint32_t)got);
    if (m_.logServices) fprintf(stderr, "[file] read h%u %zu -> %zu\n", h, n, got);
    return got;
}

size_t HostFiles::WriteFrom(uint16_t h, uint32_t at, size_t n) {
    const uint8_t* p = m_.vm.Ptr(at, (uint32_t)n);
    return p ? Write(h, p, n) : 0;
}

bool HostFiles::Seek(uint16_t h, long off, int whence, uint32_t& newPos) {
    auto it = streams_.find(h);
    if (it == streams_.end()) return false;
    if (fseek(it->second.get(), off, whence == 1 ? SEEK_CUR : whence == 2 ? SEEK_END : SEEK_SET)) return false;
    newPos = (uint32_t)ftell(it->second.get());
    return true;
}

uint16_t HostFiles::Dup(uint16_t h) {
    auto it = streams_.find(h);
    const uint16_t nh = FreeHandle();
    if (it == streams_.end() || !nh) return kFail;
    streams_[nh] = it->second;
    return nh;
}

void HostFiles::Close(uint16_t h) { streams_.erase(h); }

void HostFiles::Remove(const std::string& rel) {
    std::error_code ec;
    fs::remove(OverlayPath(rel), ec);
}

}  // namespace hlekit
