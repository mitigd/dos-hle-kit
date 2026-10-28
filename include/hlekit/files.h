// The host side of a game's files: what every seam that replaces a game's file function needs, and
// what the extender's int 21h layer (dos.h) is built on. The guest never reaches the host: a seam
// (or the extender service) turns the game's path into a sandboxed relative path and asks here.
//
//   path     the drive letter is dropped, '\' becomes '/', ".." can not climb out, the game's own
//            directory aliases (GameInfo::dosDirAliases) fold to the root. Case is kept; every
//            lookup is case-insensitive, so a game that asks for "AGIDATA.OVL" finds "agidata.ovl".
//   reads    the overlay first, then the game directory (and GameInfo::fallbackGameDir)
//   writes   to the overlay only - the first write to a file in the game directory copies it up -
//            so the game directory is never changed and saved games land in the overlay
//   handles  small DOS-style numbers (5..19) over host streams; dup shares the stream and position
//
// Nothing here knows int 21h, error codes or register conventions. That is the caller's: a real-mode
// seam reads its arguments from the stack, calls these, and puts the answer where the game's own
// wrapper would have left it.
#pragma once
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace hlekit {

class Machine;

class HostFiles {
public:
    explicit HostFiles(Machine& m) : m_(m) {}

    static constexpr uint16_t kFail = 0xFFFF;

    // ---- paths
    std::string Rel(const std::string& guestPath) const;              // sandboxed, case kept
    std::string GuestRel(uint32_t linear, size_t max = 128) const;    // Rel() of the C string at `linear`
    // The existing host file for `rel` (overlay, then the game directories); "" when there is none.
    // With forWrite: the overlay path, created and copied up from the game directory if needed.
    std::string Resolve(const std::string& rel, bool forWrite);
    std::string OverlayPath(const std::string& rel) const;            // lower-cased, below the overlay
    // Case-insensitive lookup of `rel` below `root` ("" if a component is missing).
    std::string FindCi(const std::string& root, const std::string& rel);
    static bool MatchMask(const std::string& name, const std::string& dosMask);   // '*' and '?'

    struct Entry { std::string name; uint32_t size; bool dir; };
    // The entries of `relDir` matching `mask`, merged over the fallback, game and overlay directories
    // (the overlay wins), sorted by lower-case name. Directories only with `withDirs`.
    std::vector<Entry> List(const std::string& relDir, const std::string& mask, bool withDirs);
    // An entry in DOS DTA layout: +15h attribute, +16h time, +18h date, +1Ah size, +1Eh 8.3 name.
    void WriteDta(uint32_t dta, const Entry& e) const;

    // ---- handles
    uint16_t Open(const std::string& rel, int accessMode);     // 0 = read, else read/write in the overlay; kFail if none
    uint16_t Create(const std::string& rel);                   // truncating, in the overlay
    size_t Read(uint16_t h, uint8_t* buf, size_t n);
    size_t Write(uint16_t h, const uint8_t* buf, size_t n);
    size_t ReadTo(uint16_t h, uint32_t guestLinear, size_t n);        // Read into guest memory
    size_t WriteFrom(uint16_t h, uint32_t guestLinear, size_t n);     // Write from guest memory
    bool Seek(uint16_t h, long off, int whence /*0 set, 1 cur, 2 end*/, uint32_t& newPos);
    uint16_t Dup(uint16_t h);                                   // kFail if h is not open or the table is full
    void Close(uint16_t h);                                     // the stream closes with its last handle
    void Remove(const std::string& rel);                        // the overlay copy only

private:
    using Listing = std::map<std::string, std::filesystem::path>;
    const Listing& List(const std::filesystem::path& dir);
    uint16_t FreeHandle() const;

    Machine& m_;
    std::map<std::string, Listing> listings_;                   // listed once: game dirs may be on slow media
    std::map<uint16_t, std::shared_ptr<FILE>> streams_;
};

}  // namespace hlekit
