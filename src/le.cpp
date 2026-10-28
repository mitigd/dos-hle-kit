#include "hlekit/le.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>
#include <set>

namespace hlekit {

namespace {

struct Reader {
    const std::vector<uint8_t>& d;
    bool ok(size_t o, size_t n) const { return o + n <= d.size(); }
    uint8_t u8(size_t o) const { return ok(o, 1) ? d[o] : 0; }
    uint16_t u16(size_t o) const { return ok(o, 2) ? (uint16_t)(d[o] | d[o + 1] << 8) : 0; }
    int16_t s16(size_t o) const { return (int16_t)u16(o); }
    uint32_t u32(size_t o) const { return ok(o, 4) ? (uint32_t)(u16(o) | (uint32_t)u16(o + 2) << 16) : 0; }
    bool isLe(size_t o) const {
        return ok(o, 8) && (d[o] == 'L' && (d[o + 1] == 'E' || d[o + 1] == 'X')) && !d[o + 2] && !d[o + 3] && !u32(o + 4);
    }
};

// FindLE: plain stub + LE, DOS/4G "BW"-bound chain, or a bare LE.
bool FindLe(const Reader& r, size_t& le, size_t& mzBase) {
    const auto& d = r.d;
    if (d.size() >= 0x40 && d[0] == 'M' && d[1] == 'Z') {
        uint32_t lfanew = r.u32(0x3C);
        if (r.u16(0x18) >= 0x40 && r.isLe(lfanew)) { le = lfanew; mzBase = 0; return true; }
        size_t o = r.u16(2) ? (size_t)(r.u16(4) - 1) * 512 + r.u16(2) : (size_t)r.u16(4) * 512;
        std::set<size_t> seen;
        while (r.ok(o, 2) && d[o] == 'B' && d[o + 1] == 'W' && !seen.count(o)) {
            seen.insert(o);
            size_t next = r.u32(o + 0x1C);
            if (next <= o) break;
            o = next;
        }
        if (r.ok(o, 0x40) && d[o] == 'M' && d[o + 1] == 'Z' && r.isLe(o + r.u32(o + 0x3C))) {
            le = o + r.u32(o + 0x3C);
            mzBase = o;
            return true;
        }
    } else if (r.isLe(0)) {
        le = mzBase = 0;
        return true;
    }
    for (size_t i = 0; i + 4 <= d.size(); ++i)
        if (r.isLe(i)) { le = i; mzBase = 0; return true; }
    return false;
}

}  // namespace

bool LoadLe(const std::string& path, uint16_t codeSel, uint16_t dataSel, LeImage& out, std::string& err, bool allHigh) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return err = "cannot open " + path, false;
    const std::vector<uint8_t> d((std::istreambuf_iterator<char>(in)), {});
    const Reader r{d};
    size_t le, mz;
    if (!FindLe(r, le, mz)) return err = path + ": no LE header", false;
    if (d[le + 1] != 'E') return err = path + ": LX is not supported (only LE)", false;

    const uint32_t nPages = r.u32(le + 0x14), pageSize = r.u32(le + 0x28), lastPage = r.u32(le + 0x2C);
    const size_t dataPages = mz + r.u32(le + 0x80);
    const uint32_t objTab = r.u32(le + 0x40), nObj = r.u32(le + 0x44), pageMap = r.u32(le + 0x48);
    struct Obj { uint32_t vsize, base, flags, first, count; };
    std::vector<Obj> objs;
    for (uint32_t i = 0; i < nObj; ++i) {
        size_t e = le + objTab + i * 24;
        Obj o{r.u32(e), r.u32(e + 4), r.u32(e + 8), r.u32(e + 12), r.u32(e + 16)};
        if (!o.base) o.base = (i + 1) * 0x100000;          // no base: place at n MB
        objs.push_back(o);
    }
    // Load bases: linked, unless the object covers the A0000h-FFFFFh hole (header comment).
    std::vector<uint32_t> link(nObj);
    uint32_t keptEnd = kLeHoleEnd;
    for (uint32_t i = 0; i < nObj; ++i) {
        link[i] = objs[i].base;
        const uint64_t end = (uint64_t)objs[i].base + objs[i].vsize;
        if (!allHigh && !(objs[i].base < kLeHoleEnd && end > kLeHoleStart)) keptEnd = std::max<uint32_t>(keptEnd, (uint32_t)end);
    }
    for (uint32_t i = 0; i < nObj; ++i) {
        if (!allHigh && !(objs[i].base < kLeHoleEnd && (uint64_t)objs[i].base + objs[i].vsize > kLeHoleStart)) continue;
        objs[i].base = (keptEnd + 0xFFFF) & ~0xFFFFu;
        keptEnd = objs[i].base + objs[i].vsize;
    }

    // object bytes from the page map (24-bit big-endian page numbers, LE)
    std::vector<std::vector<uint8_t>> mem(nObj);
    for (uint32_t i = 0; i < nObj; ++i) {
        const Obj& o = objs[i];
        mem[i].assign(std::max<size_t>(o.vsize, (size_t)o.count * pageSize), 0);
        for (uint32_t k = 0; k < o.count; ++k) {
            uint32_t idx = o.first + k;
            if (idx < 1 || idx > nPages) break;
            size_t e = le + pageMap + (idx - 1) * 4;
            uint32_t pnum = (uint32_t)r.u8(e) << 16 | r.u8(e + 1) << 8 | r.u8(e + 2);
            uint8_t type = r.u8(e + 3);
            if (type != 0) continue;                           // zero-filled / invalid: stays 0
            size_t foff = dataPages + (size_t)(pnum - 1) * pageSize;
            size_t size = pnum == nPages ? lastPage : pageSize;
            size = std::min<size_t>(size, pageSize);
            if (r.ok(foff, size)) memcpy(mem[i].data() + (size_t)k * pageSize, d.data() + foff, size);
        }
    }

    // fixups: page table at +68h, records at +6Ch
    const uint32_t fpt = r.u32(le + 0x68), frt = r.u32(le + 0x6C);
    for (uint32_t page = 1; fpt && frt && page <= nPages; ++page) {
        size_t o = le + frt + r.u32(le + fpt + (page - 1) * 4);
        const size_t end = le + frt + r.u32(le + fpt + page * 4);
        int owner = -1;
        for (uint32_t i = 0; i < nObj; ++i)
            if (objs[i].first <= page && page < objs[i].first + objs[i].count) owner = (int)i;
        while (o < end) {
            const uint8_t src = r.u8(o), fl = r.u8(o + 1);
            o += 2;
            std::vector<int16_t> offs;
            int count = 0;
            if (src & 0x20) count = r.u8(o++);
            else { offs.push_back(r.s16(o)); o += 2; }
            uint32_t obj;
            if (fl & 0x40) { obj = r.u16(o); o += 2; } else obj = r.u8(o++);
            const int target = fl & 3, stype = src & 0xF;
            uint32_t off = 0, add = 0;
            if ((target == 0 && stype != 2) || target == 2) {
                if (fl & 0x10) { off = r.u32(o); o += 4; } else { off = r.u16(o); o += 2; }
            } else if (target == 1) {
                if (fl & 0x80) off = r.u8(o++);
                else if (fl & 0x10) { off = r.u32(o); o += 4; }
                else { off = r.u16(o); o += 2; }
            }
            if (fl & 0x4) {
                if (fl & 0x20) { add = r.u32(o); o += 4; } else { add = r.u16(o); o += 2; }
            }
            for (int k = 0; k < count; ++k) offs.push_back(r.s16(o + 2 * k));
            o += 2 * count;
            if (owner < 0) continue;
            for (int16_t so : offs) {
                ++out.fixups;
                auto& buf = mem[owner];
                const int64_t at = (int64_t)(page - objs[owner].first) * pageSize + so;
                const uint32_t addr = objs[owner].base + (uint32_t)at;
                auto put = [&](uint64_t v, int n, int64_t pos) {
                    for (int b = 0; b < n; ++b)
                        if (pos + b >= 0 && pos + b < (int64_t)buf.size()) buf[pos + b] = (uint8_t)(v >> (8 * b));
                };
                if (target != 0) { ++out.unsupported; continue; }   // imports: none in DOS programs
                const uint32_t t = (obj >= 1 && obj <= nObj ? objs[obj - 1].base : 0) + off + add;
                const uint16_t sel = obj >= 1 && obj <= nObj && (objs[obj - 1].flags & 4) ? codeSel : dataSel;
                switch (stype) {
                    case 0: put(t & 0xFF, 1, at); break;
                    case 5: put(t & 0xFFFF, 2, at); break;
                    case 7: put(t, 4, at); break;
                    case 8: put(t - (addr + 4), 4, at); break;
                    case 2: put(sel, 2, at); break;
                    case 3: put((off & 0xFFFF) | (uint32_t)sel << 16, 4, at); break;
                    case 6: put(t, 4, at); put(sel, 2, at + 4); break;
                    default: ++out.unsupported; break;
                }
            }
        }
    }

    for (uint32_t i = 0; i < nObj; ++i) {
        mem[i].resize(objs[i].vsize);
        out.regions.push_back({objs[i].base, std::move(mem[i]), objs[i].flags, link[i]});
    }
    const uint32_t eipObj = r.u32(le + 0x18), espObj = r.u32(le + 0x20);
    if (eipObj < 1 || eipObj > nObj) return err = "entry object out of range", false;
    out.entry = objs[eipObj - 1].base + r.u32(le + 0x1C);
    out.stack = espObj >= 1 && espObj <= nObj ? objs[espObj - 1].base + r.u32(le + 0x24) : 0;
    return true;
}

}  // namespace hlekit
