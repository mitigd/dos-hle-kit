#!/usr/bin/env python3
"""Self-contained DOS executable loader for the analysis tools.

Supported inputs:

  COM   flat 16-bit image loaded at 0100h
  MZ    real-mode DOS executable (header + load image, 16-bit)
  NE    16-bit segmented protected-mode executable (Phar Lap 286, OS/2 1.x)
  LE    linear executable (DOS/4GW, DOS/4G, PMODE/W, CauseWay, ...)
  LX    linear executable, parsed with the LE reader (32-bit source fixups only)

The loader returns the executable's code/data regions at linked addresses, so disassembly
addresses match the addresses a decompiler shows. No external decompiler or workspace format is
required.
"""
import os
from dataclasses import dataclass, field


class ImageError(Exception):
    pass


def _u8(d, o):
    return d[o] if 0 <= o < len(d) else 0


def _u16(d, o):
    return _u8(d, o) | (_u8(d, o + 1) << 8)


def _s16(d, o):
    v = _u16(d, o)
    return v - 0x10000 if v & 0x8000 else v


def _u32(d, o):
    return _u16(d, o) | (_u16(d, o + 2) << 16)


@dataclass
class Region:
    """One loadable image region. `base` is its linked/linear address."""

    index: int
    base: int
    data: bytearray
    flags: int = 0            # LE/NE-style flags: 1 readable, 2 writable, 4 executable
    bits: int = 32
    segment_base: int = 0     # base used to resolve 16-bit near branches

    @property
    def size(self):
        return len(self.data)

    @property
    def executable(self):
        return bool(self.flags & 4)

    @property
    def end(self):
        return self.base + len(self.data)


@dataclass
class Fixup:
    source: int               # linked address of the fixup site
    target: int               # linked address of the referenced object/function
    source_is_code: bool = False
    kind: str = ""


@dataclass
class Image:
    path: str
    format: str
    bits: int
    regions: list = field(default_factory=list)
    entry: int = 0
    stack: int = 0
    fixups: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def region_at(self, addr):
        for r in self.regions:
            if r.base <= addr < r.end:
                return r
        return None

    def code_region_at(self, addr):
        r = self.region_at(addr)
        return r if r and r.executable else None

    def near_target(self, region, value):
        """Resolve a near branch operand for the region's bitness."""
        if region.bits == 16:
            return (region.segment_base + (value & 0xFFFF)) & 0xFFFFFFFF
        return value & 0xFFFFFFFF

    def far_target(self, seg, off):
        if self.format == "MZ":
            return ((seg << 4) + off) & 0xFFFFFFFF
        if self.format == "NE":
            return ((seg << 16) + off) & 0xFFFFFFFF
        return ((seg << 4) + off) & 0xFFFFFFFF


def _is_le(data, o):
    return (o + 8 <= len(data) and data[o:o + 2] in (b"LE", b"LX") and
            data[o + 2:o + 4] == b"\0\0" and _u32(data, o + 4) == 0)


def _find_le(data):
    """Return (le_offset, mz_offset) for a plain LE, MZ+LE, or DOS/4G BW chain."""
    if len(data) >= 0x40 and data[:2] == b"MZ":
        lfanew = _u32(data, 0x3C)
        if _u16(data, 0x18) >= 0x40 and _is_le(data, lfanew):
            return lfanew, 0
        if _u16(data, 2):
            o = (_u16(data, 4) - 1) * 512 + _u16(data, 2)
        else:
            o = _u16(data, 4) * 512
        seen = set()
        while o + 2 <= len(data) and data[o:o + 2] == b"BW" and o not in seen:
            seen.add(o)
            nxt = _u32(data, o + 0x1C)
            if nxt <= o:
                break
            o = nxt
        if o + 0x40 <= len(data) and data[o:o + 2] == b"MZ" and _is_le(data, o + _u32(data, o + 0x3C)):
            return o + _u32(data, o + 0x3C), o
    elif _is_le(data, 0):
        return 0, 0
    for i in range(0, max(0, len(data) - 8)):
        if _is_le(data, i):
            return i, 0
    return None, None


def _load_le(data, path):
    le, mz = _find_le(data)
    if le is None:
        raise ImageError("no LE/LX header")
    is_lx = data[le + 1:le + 2] == b"X"
    if not _u32(data, le + 0x14):
        raise ImageError("LE header has no pages")
    page_count = _u32(data, le + 0x14)
    page_size = _u32(data, le + 0x28)
    last_page = _u32(data, le + 0x2C)
    data_pages = mz + _u32(data, le + 0x80)
    obj_tab = _u32(data, le + 0x40)
    obj_count = _u32(data, le + 0x44)
    page_map = _u32(data, le + 0x48)
    if not page_size or not obj_count or obj_count > 0x4000:
        raise ImageError("bad LE object/page table")
    objects = []
    for i in range(obj_count):
        e = le + obj_tab + i * 24
        vsize = _u32(data, e)
        base = _u32(data, e + 4)
        flags = _u32(data, e + 8)
        first = _u32(data, e + 12)
        count = _u32(data, e + 16)
        if not base:
            base = (i + 1) * 0x100000
        objects.append({"vsize": vsize, "base": base, "flags": flags, "first": first, "count": count})

    # DOS/4GW moves an object out of the A0000h-FFFFFh hole (VGA/BIOS window). Match the C++
    # loader so analysis addresses are the addresses the game actually executes at.
    k_hole_start, k_hole_end = 0xA0000, 0x100000
    kept_end = k_hole_end
    for o in objects:
        end = o["base"] + o["vsize"]
        if not (o["base"] < k_hole_end and end > k_hole_start):
            kept_end = max(kept_end, end)
    for o in objects:
        end = o["base"] + o["vsize"]
        if o["base"] < k_hole_end and end > k_hole_start:
            o["base"] = (kept_end + 0xFFFF) & ~0xFFFF
            kept_end = o["base"] + o["vsize"]

    # Read the object bytes through the page map. A zero-filled/invalid page stays zero.
    mem = []
    for o in objects:
        buf = bytearray(max(o["vsize"], o["count"] * page_size))
        for k in range(o["count"]):
            idx = o["first"] + k
            if idx < 1 or idx > page_count:
                break
            e = le + page_map + (idx - 1) * 4
            pnum = (_u8(data, e) << 16) | (_u8(data, e + 1) << 8) | _u8(data, e + 2)
            ptype = _u8(data, e + 3)
            if ptype != 0 or not pnum:
                continue
            foff = data_pages + (pnum - 1) * page_size
            size = min(last_page if pnum == page_count else page_size, page_size)
            if 0 <= foff < len(data):
                n = min(size, len(data) - foff, len(buf) - k * page_size)
                if n > 0:
                    buf[k * page_size:k * page_size + n] = data[foff:foff + n]
        del buf[o["vsize"]:]
        mem.append(buf)

    # Internal fixups. Only source types the kit's loader also applies are rewritten; the rest
    # are counted as notes, not fatal, because the bytes are still useful for disassembly.
    fpt = _u32(data, le + 0x68)
    frt = _u32(data, le + 0x6C)
    fixes = []
    unsupported = 0
    if fpt and frt:
        for page in range(1, page_count + 1):
            owner = next((i for i, o in enumerate(objects)
                          if o["first"] <= page < o["first"] + o["count"]), None)
            start = le + frt + _u32(data, le + fpt + (page - 1) * 4)
            end = le + frt + _u32(data, le + fpt + page * 4)
            p = start
            while p + 2 <= end and p + 2 <= len(data):
                src = _u8(data, p)
                flags = _u8(data, p + 1)
                p += 2
                offsets = []
                if src & 0x20:
                    count = _u8(data, p)
                    p += 1
                else:
                    offsets.append(_s16(data, p))
                    p += 2
                    count = 0
                if flags & 0x40:
                    obj = _u16(data, p)
                    p += 2
                else:
                    obj = _u8(data, p)
                    p += 1
                target_kind = flags & 3
                stype = src & 0xF
                off = add = 0
                if (target_kind == 0 and stype != 2) or target_kind == 2:
                    if flags & 0x10:
                        off = _u32(data, p)
                        p += 4
                    else:
                        off = _u16(data, p)
                        p += 2
                elif target_kind == 1:
                    if flags & 0x80:
                        off = _u8(data, p)
                        p += 1
                    elif flags & 0x10:
                        off = _u32(data, p)
                        p += 4
                    else:
                        off = _u16(data, p)
                        p += 2
                if flags & 0x4:
                    if flags & 0x20:
                        add = _u32(data, p)
                        p += 4
                    else:
                        add = _u16(data, p)
                        p += 2
                for _ in range(count):
                    offsets.append(_s16(data, p))
                    p += 2
                if owner is None:
                    continue
                for so in offsets:
                    at = (page - objects[owner]["first"]) * page_size + so
                    addr = objects[owner]["base"] + at
                    if target_kind != 0:
                        fixes.append(Fixup(addr, 0, bool(objects[owner]["flags"] & 4), "import"))
                        unsupported += 1
                        continue
                    tidx = obj - 1
                    target = (objects[tidx]["base"] if 0 <= tidx < len(objects) else 0) + off + add
                    fixes.append(Fixup(addr, target, bool(objects[owner]["flags"] & 4), "internal"))
                    buf = mem[owner]
                    if 0 <= at < len(buf):
                        def put(value, n):
                            for b in range(n):
                                if 0 <= at + b < len(buf):
                                    buf[at + b] = (value >> (8 * b)) & 0xFF
                        if stype == 0:
                            put(target & 0xFF, 1)
                        elif stype == 5:
                            put(target & 0xFFFF, 2)
                        elif stype == 7:
                            put(target, 4)
                        elif stype == 8:
                            put(target - (addr + 4), 4)
                        elif stype == 3:
                            put(target & 0xFFFF, 4)
                        elif stype == 6:
                            put(target, 4)
                        else:
                            unsupported += 1
    regions = [Region(i, o["base"], buf, o["flags"], 32, o["base"])
               for i, (o, buf) in enumerate(zip(objects, mem))]
    entry_obj = _u32(data, le + 0x18)
    entry_off = _u32(data, le + 0x1C)
    stack_obj = _u32(data, le + 0x20)
    stack_off = _u32(data, le + 0x24)
    entry = regions[entry_obj - 1].base + entry_off if 1 <= entry_obj <= len(regions) else 0
    stack = regions[stack_obj - 1].base + stack_off if 1 <= stack_obj <= len(regions) else 0
    notes = []
    if is_lx:
        notes.append("LX header parsed with the LE reader; 32-bit fixup source types are not all applied")
    if unsupported:
        notes.append("%d fixups were not applied (unsupported source/target type)" % unsupported)
    return Image(path, "LX" if is_lx else "LE", 32,
                 regions, entry, stack, fixes, notes)


def _load_ne(data, path):
    if data[:2] != b"MZ":
        raise ImageError("NE without an MZ stub")
    ne = _u32(data, 0x3C)
    if data[ne:ne + 2] != b"NE":
        raise ImageError("no NE header")
    nseg = _u16(data, ne + 0x1C)
    align = _u16(data, ne + 0x32) or 9
    segtab = ne + _u16(data, ne + 0x22)
    cs_seg = _u16(data, ne + 0x16)
    ip = _u16(data, ne + 0x14)
    ss_seg = _u16(data, ne + 0x1A)
    sp = _u16(data, ne + 0x18)
    if nseg == 0 or nseg > 0x1000:
        raise ImageError("bad NE segment count")
    regions = []
    segs = []
    for i in range(nseg):
        e = segtab + 8 * i
        off = _u16(data, e) << align
        length = _u16(data, e + 2)
        flags = _u16(data, e + 4)
        min_alloc = _u16(data, e + 6)
        if not length and off:
            length = 0x10000
        size = length if not (flags & 1) else max(min_alloc or 0x10000, length)
        buf = bytearray(size)
        if off and off < len(data):
            n = min(length, len(data) - off, size)
            buf[:n] = data[off:off + n]
        # NE segment numbers are 1-based. A synthetic 64 KB slot per segment gives a stable
        # linear address space for disassembly and matches the 16-bit one-segment model.
        base = (i + 1) * 0x10000
        regions.append(Region(i, base, buf, 4 if not (flags & 1) else 0, 16, base))
        segs.append({"off": off, "length": length, "flags": flags, "base": base})
    # Internal relocation records are the NE equivalent of stored pointers. They are also
    # useful seeds for function discovery even when the target is reached indirectly.
    fixups = []
    for i, s in enumerate(segs):
        if not (s["flags"] & 0x100) or not s["off"]:
            continue
        p = s["off"] + s["length"]
        if p + 2 > len(data):
            continue
        count = _u16(data, p)
        p += 2
        for _ in range(count):
            if p + 8 > len(data):
                break
            src = _u8(data, p)
            flags = _u8(data, p + 1)
            off = _u16(data, p + 2)
            a = _u16(data, p + 4)
            b = _u16(data, p + 6)
            p += 8
            if (flags & 3) != 0 or (a & 0xFF) == 0xFF:
                continue
            tseg = a & 0xFF
            if not 1 <= tseg <= nseg:
                continue
            source = s["base"] + off
            target = tseg * 0x10000 + b
            fixups.append(Fixup(source, target, not (s["flags"] & 1), "NE relocation"))
    entry = (cs_seg * 0x10000 + ip) if 1 <= cs_seg <= nseg else 0
    stack = (ss_seg * 0x10000 + sp) if 1 <= ss_seg <= nseg else 0
    notes = ["segment addresses are synthetic (segment n -> n*10000h) because NE load addresses are chosen at run time"]
    return Image(path, "NE", 16, regions, entry, stack, fixups, notes)


def _load_mz(data, path):
    if data[:2] != b"MZ":
        raise ImageError("no MZ header")
    hdr_paras = _u16(data, 0x08)
    image = bytearray(data[hdr_paras * 16:])
    if not image:
        raise ImageError("empty MZ image")
    cs = _u16(data, 0x16)
    ip = _u16(data, 0x14)
    ss = _u16(data, 0x0E)
    sp = _u16(data, 0x10)
    # Model the PSP as 100h bytes; the load segment is 0, so a far pointer is seg*10h+off.
    region = Region(0, 0, bytearray(0x100) + image, 5, 16, 0x100 + cs * 16)
    entry = region.segment_base + ip
    stack = 0x100 + ss * 16 + sp
    relocs = _u16(data, 0x06)
    reloc_off = _u16(data, 0x18)
    stored = []
    for i in range(relocs):
        e = reloc_off + 4 * i
        if e + 4 > len(data):
            break
        off = _u16(data, e)
        seg = _u16(data, e + 2)
        source = 0x100 + seg * 16 + off
        target = 0
        if source + 4 <= len(region.data):
            lo = _u16(region.data, source)
            hi = _u16(region.data, source + 2)
            target = ((hi << 4) + lo) & 0xFFFFF
        stored.append(Fixup(source, target, False, "MZ relocation"))
    notes = ["real-mode image; code addresses use load segment 0 and a 100h PSP"]
    return Image(path, "MZ", 16, [region], entry, stack, stored, notes)


def _load_com(data, path):
    region = Region(0, 0, bytearray(0x100) + data, 5, 16, 0)
    return Image(path, "COM", 16, [region], 0x100, 0xFFFF, [],
                 ["flat 16-bit image loaded at 0100h"])


def load_image(path):
    try:
        data = open(path, "rb").read()
    except OSError as e:
        raise ImageError(str(e))
    if len(data) < 2:
        raise ImageError("file too short")
    path = os.path.abspath(path)
    if data[:2] == b"MZ":
        le, _ = _find_le(data)
        if le is not None:
            return _load_le(data, path)
        ne = _u32(data, 0x3C)
        if ne + 2 <= len(data) and data[ne:ne + 2] == b"NE":
            return _load_ne(data, path)
        return _load_mz(data, path)
    if data[:2] in (b"LE", b"LX"):
        return _load_le(data, path)
    if data[:4] == b"\x7fELF" or data[:2] == b"PE":
        raise ImageError("not a DOS executable (ELF/PE)")
    if path.lower().endswith(".com"):
        return _load_com(data, path)
    raise ImageError("unrecognized DOS executable format (expected COM, MZ, NE, LE or LX)")
