// NE executable / DLL loader (16-bit segmented protected mode: Phar Lap 286|DOS-Extender, OS/2
// 1.x, Windows 3.x). Parses the segment table and applies each segment's relocations; the
// runner chooses where segments live (their selectors) and resolves imports.
//
// Segment numbers are 1-based as in the NE header and in linker maps (seg:off).
#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace hlekit {

struct NeImage {
    struct Segment {
        std::vector<uint8_t> data;           // file bytes, zero-extended to `size`
        uint32_t size = 0;                   // allocation size (min alloc, 0 = 64 KB)
        uint16_t flags = 0;                  // 0001h data, 0010h movable, 0100h relocations, …
        bool IsData() const { return flags & 1; }
    };
    struct Import {                          // one imported function (module, ordinal or name)
        std::string module;
        uint16_t ordinal = 0;                // 0 when imported by name
        std::string name;
        std::string Key() const { return module + "." + (name.empty() ? std::to_string(ordinal) : name); }
    };
    std::string moduleName;                  // first resident name
    std::vector<Segment> segs;               // segs[0] = segment 1
    uint16_t autoData = 0;                   // DGROUP segment number
    uint16_t csSeg = 0, ip = 0, ssSeg = 0, sp = 0;
    uint16_t heapSize = 0, stackSize = 0;
    std::vector<Import> imports;             // every import some relocation names (unique)
    struct Export { uint16_t ordinal; std::string name; uint16_t seg, off; };
    std::vector<Export> exports;             // resident + non-resident names with their entries
    uint32_t relocations = 0, unsupported = 0;
    std::vector<uint8_t> file;               // the whole file (relocation records are read from it)
    uint32_t neOff = 0;
};

// Where things live, decided by the runner: a segment's selector, and the far address
// (selector:offset) an import resolves to (e.g. a native stub). `importValue` returns false for
// an import it cannot resolve (the fixup is then counted unsupported and left as is).
struct NeLayout {
    std::function<uint16_t(uint16_t seg)> selector;
    std::function<bool(const NeImage::Import&, uint16_t& sel, uint16_t& off)> importValue;
};

bool ParseNe(const std::string& path, NeImage& out, std::string& err);
// Applies every relocation of every segment in `img` (segment data is patched in place).
void RelocateNe(NeImage& img, const NeLayout& layout);

}  // namespace hlekit
