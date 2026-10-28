#include "hlekit/ne.h"

#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <set>

namespace hlekit {

namespace {

struct Reader {
    const std::vector<uint8_t>& d;
    bool ok(size_t o, size_t n) const { return o + n <= d.size(); }
    uint8_t u8(size_t o) const { return ok(o, 1) ? d[o] : 0; }
    uint16_t u16(size_t o) const { return ok(o, 2) ? (uint16_t)(d[o] | d[o + 1] << 8) : 0; }
    uint32_t u32(size_t o) const { return ok(o, 4) ? (uint32_t)(u16(o) | (uint32_t)u16(o + 2) << 16) : 0; }
    std::string pstr(size_t o) const {                     // length-prefixed
        const uint8_t n = u8(o);
        return ok(o + 1, n) ? std::string((const char*)&d[o + 1], n) : std::string();
    }
};

// Name tables: {len, name, u16 ordinal}..., 0. The first resident entry is the module name.
void Names(const Reader& r, size_t o, std::map<uint16_t, std::string>& out, std::string* first) {
    for (bool head = true; r.ok(o, 1) && r.u8(o); head = false) {
        const std::string n = r.pstr(o);
        const uint16_t ord = r.u16(o + 1 + n.size());
        if (head && first) *first = n;
        else out[ord] = n;
        o += 3 + n.size();
    }
}

}  // namespace

bool ParseNe(const std::string& path, NeImage& out, std::string& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return err = "cannot open " + path, false;
    out.file.assign(std::istreambuf_iterator<char>(in), {});
    const Reader r{out.file};
    if (r.u16(0) != 0x5A4D) return err = path + ": no MZ header", false;
    const uint32_t ne = r.u32(0x3C);
    if (r.u16(ne) != 0x454E) return err = path + ": no NE header", false;
    out.neOff = ne;
    out.autoData = r.u16(ne + 0x0E);
    out.heapSize = r.u16(ne + 0x10);
    out.stackSize = r.u16(ne + 0x12);
    out.ip = r.u16(ne + 0x14);
    out.csSeg = r.u16(ne + 0x16);
    out.sp = r.u16(ne + 0x18);
    out.ssSeg = r.u16(ne + 0x1A);
    const uint16_t nseg = r.u16(ne + 0x1C), align = r.u16(ne + 0x32) ? r.u16(ne + 0x32) : 9;
    const uint32_t segtab = ne + r.u16(ne + 0x22);
    for (uint16_t i = 0; i < nseg; ++i) {
        const size_t e = segtab + 8u * i;
        const uint32_t off = (uint32_t)r.u16(e) << align;
        const uint16_t flags = r.u16(e + 4);
        uint32_t len = r.u16(e + 2), size = r.u16(e + 6);
        if (!len && off) len = 0x10000;
        if (!size) size = 0x10000;
        NeImage::Segment s;
        s.flags = flags;
        s.size = std::max(size, len);
        s.data.assign(s.size, 0);
        if (off && r.ok(off, len)) memcpy(s.data.data(), &out.file[off], len);
        out.segs.push_back(std::move(s));
    }

    // exports: entry table (bundles) + resident / non-resident names
    std::map<uint16_t, std::pair<uint16_t, uint16_t>> entries;   // ordinal -> seg:off
    size_t o = ne + r.u16(ne + 0x04);
    const size_t end = o + r.u16(ne + 0x06);
    uint16_t ord = 1;
    while (o < end && r.u8(o)) {
        const uint8_t count = r.u8(o), type = r.u8(o + 1);
        o += 2;
        for (uint8_t k = 0; k < count; ++k, ++ord) {
            if (type == 0) continue;                                // unused ordinals
            if (type == 0xFF) { entries[ord] = {r.u8(o + 3), r.u16(o + 4)}; o += 6; }
            else { entries[ord] = {type, r.u16(o + 1)}; o += 3; }
        }
    }
    std::map<uint16_t, std::string> names;
    Names(r, ne + r.u16(ne + 0x26), names, &out.moduleName);
    if (const uint32_t nres = r.u32(ne + 0x2C)) Names(r, nres, names, nullptr);
    for (auto& [n, e] : entries) {
        auto it = names.find(n);
        out.exports.push_back({n, it == names.end() ? std::string() : it->second, e.first, e.second});
    }

    // every import a relocation names, once
    const size_t modtab = ne + r.u16(ne + 0x28), imptab = ne + r.u16(ne + 0x2A);
    auto modName = [&](uint16_t idx) { return idx ? r.pstr(imptab + r.u16(modtab + 2u * (idx - 1))) : std::string(); };
    std::set<std::string> seen;
    for (uint16_t i = 0; i < nseg; ++i) {
        const size_t e = segtab + 8u * i;
        if (!(r.u16(e + 4) & 0x100) || !r.u16(e)) continue;
        uint32_t len = r.u16(e + 2);
        if (!len) len = 0x10000;
        size_t p = ((size_t)r.u16(e) << align) + len;
        const uint16_t n = r.u16(p);
        p += 2;
        for (uint16_t k = 0; k < n; ++k, p += 8) {
            const uint8_t t = r.u8(p + 1) & 3;
            if (t != 1 && t != 2) continue;
            NeImage::Import im;
            im.module = modName(r.u16(p + 4));
            if (t == 1) im.ordinal = r.u16(p + 6);
            else im.name = r.pstr(imptab + r.u16(p + 6));
            if (seen.insert(im.Key()).second) out.imports.push_back(im);
        }
    }
    return true;
}

void RelocateNe(NeImage& img, const NeLayout& layout) {
    const Reader r{img.file};
    const uint32_t ne = img.neOff;
    const uint16_t align = r.u16(ne + 0x32) ? r.u16(ne + 0x32) : 9;
    const size_t segtab = ne + r.u16(ne + 0x22), modtab = ne + r.u16(ne + 0x28), imptab = ne + r.u16(ne + 0x2A);
    auto modName = [&](uint16_t idx) { return idx ? r.pstr(imptab + r.u16(modtab + 2u * (idx - 1))) : std::string(); };
    std::map<uint16_t, std::pair<uint16_t, uint16_t>> movable;      // for internal refs by ordinal
    for (auto& e : img.exports) movable[e.ordinal] = {e.seg, e.off};

    for (size_t i = 0; i < img.segs.size(); ++i) {
        const size_t e = segtab + 8 * i;
        if (!(r.u16(e + 4) & 0x100) || !r.u16(e)) continue;
        uint32_t len = r.u16(e + 2);
        if (!len) len = 0x10000;
        size_t p = ((size_t)r.u16(e) << align) + len;
        const uint16_t n = r.u16(p);
        p += 2;
        auto& buf = img.segs[i].data;
        auto rd16 = [&](uint32_t at) { return at + 2 <= buf.size() ? (uint16_t)(buf[at] | buf[at + 1] << 8) : (uint16_t)0xFFFF; };
        auto wr = [&](uint32_t at, uint32_t v, int bytes) {
            for (int b = 0; b < bytes; ++b) if (at + b < buf.size()) buf[at + b] = (uint8_t)(v >> (8 * b));
        };
        for (uint16_t k = 0; k < n; ++k, p += 8) {
            const uint8_t src = r.u8(p), fl = r.u8(p + 1);
            const uint16_t at0 = r.u16(p + 2), a = r.u16(p + 4), b = r.u16(p + 6);
            uint16_t sel = 0, off = 0;
            bool ok = true;
            switch (fl & 3) {
                case 0:                                             // internal
                    if ((a & 0xFF) == 0xFF) {
                        auto it = movable.find(b);
                        ok = it != movable.end();
                        if (ok) { sel = layout.selector(it->second.first); off = it->second.second; }
                    } else {
                        sel = layout.selector(a & 0xFF);
                        off = b;
                    }
                    break;
                case 1: case 2: {                                   // import by ordinal / name
                    NeImage::Import im;
                    im.module = modName(a);
                    if ((fl & 3) == 1) im.ordinal = b;
                    else im.name = r.pstr(imptab + b);
                    ok = layout.importValue(im, sel, off);
                    break;
                }
                default: ok = false; break;                        // OS fixups (FP emulation)
            }
            ++img.relocations;
            if (!ok) { ++img.unsupported; continue; }
            const bool additive = fl & 4;
            auto apply = [&](uint32_t at) {
                switch (src) {
                    case 0: wr(at, (additive ? buf[at] : 0) + off, 1); break;                 // low byte
                    case 2: wr(at, sel, 2); break;                                             // selector
                    case 3: wr(at, (additive ? rd16(at) : 0) + off, 2); wr(at + 2, sel, 2); break;   // far 16:16
                    case 5: wr(at, (additive ? rd16(at) : 0) + off, 2); break;                // offset 16
                    case 11: wr(at, off, 4); wr(at + 4, sel, 2); break;                       // far 16:32
                    case 13: wr(at, off, 4); break;                                           // offset 32
                    default: ++img.unsupported; break;
                }
            };
            if (additive || src == 0) { apply(at0); continue; }
            // not additive: the target location holds the next location of the same fixup
            for (uint32_t at = at0, guard = 0; at != 0xFFFF && at < buf.size() && guard < 0x10000; ++guard) {
                const uint16_t next = rd16(at);
                apply(at);
                at = next;
            }
        }
    }
}

}  // namespace hlekit
