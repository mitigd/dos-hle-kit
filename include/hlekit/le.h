// LE executable loader (DOS/4GW, Watcom): objects at their linked bases where possible, internal
// fixups applied. Objects stay at their linked bases, so guest addresses stay decomp addresses.
//
// Exception, as DOS/4GW itself would load it: an object whose linked range covers the hole at
// A0000h-FFFFFh (VGA window, BIOS) is moved to 1 MB and up and the fixups are applied for that
// base. Its decomp addresses then differ from guest addresses by (base - linkBase); seams
// translate with Machine::Data(). Code objects normally stay where they were linked.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace hlekit {

struct LeImage {
    struct Region { uint32_t base; std::vector<uint8_t> data; uint32_t flags; uint32_t linkBase; };
    std::vector<Region> regions;
    uint32_t entry = 0, stack = 0;
    uint32_t fixups = 0, unsupported = 0;
};

// The address hole no object may occupy; moved objects go above it.
constexpr uint32_t kLeHoleStart = 0xA0000, kLeHoleEnd = 0x100000;

// Selector values for 16:16 / 16:32 fixups: the object's flat selector in the runner's GDT.
// `allHigh`: load every object at 1 MB and up, as DOS/4GW does, so the whole 640 KB stays free for
// conventional memory (int 31h/0100h). Decomp addresses of code then also differ from guest
// addresses: seams are translated with Machine::Data(), labels are remapped.
bool LoadLe(const std::string& path, uint16_t codeSel, uint16_t dataSel, LeImage& out, std::string& err,
            bool allHigh = false);

}  // namespace hlekit
