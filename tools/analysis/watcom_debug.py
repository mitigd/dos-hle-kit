#!/usr/bin/env python3
"""Watcom debug information left in a DOS executable: function and data symbols, source modules.

Many DOS/4GW games were linked with Watcom's `debug all` (or `debug` for globals) and shipped that
way. The debug block sits at the end of the file and ends with a master header (signature 8386h).
This reads it directly - no Watcom tools, no decompiler - and writes the CSV the kit and the
discovery tools take (`address,name,size`, linked addresses, i.e. the decompiler's addresses).

    python3 tools/analysis/watcom_debug.py GAME.EXE                      # summary
    python3 tools/analysis/watcom_debug.py GAME.EXE --functions F.csv    # code symbols (with sizes)
    python3 tools/analysis/watcom_debug.py GAME.EXE --data D.csv         # data symbols
    python3 tools/analysis/watcom_debug.py GAME.EXE --modules            # source files and their code ranges
    python3 tools/analysis/watcom_debug.py GAME.EXE --raw ...            # keep the mangled W?... names

Feed the functions CSV to the kit (`GameInfo::functionsCsv`, `--functions`) and to
`find_seams.py --backend csv --functions F.csv` / `rank_seams.py --functions F.csv`.

Format (Watcom debug info v3, the 10.x/11.x linker): at end of file the master header
  u16 signature 8386h, u8 exe major/minor, u8 obj major/minor, u16 language table size,
  u16 segment table size, u32 debug info size (everything, header included)
then from (file size - debug size): the language names (NUL-separated), the segment table (u16 each)
and one or more sections, each
  u32 module info offset, u32 global info offset, u32 address info offset, u32 section size,
  u16 section id
with offsets relative to the section. Global records: u32 offset, u16 segment, u16 module,
u8 kind (bit 0 static, bit 1 data, bit 2 code), u8 name length, name. Module records: u16 language,
three demand-info entries (u32 offset, u16 count), u8 name length, name. Address info: blocks of
u32 offset, u16 segment, u16 count, then count x (u32 size, u16 module).

Segments are the executable's objects (LE/LX) or segments (NE), numbered from 1.
"""
import argparse
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "lib"))
from dos_image import _find_le  # noqa: E402

SIGNATURE = 0x8386


class DebugInfoError(Exception):
    pass


def segment_bases(data):
    """Linked base of each segment number (1-based): LE/LX object bases. NE/MZ: None (seg:off)."""
    le, _ = _find_le(data)
    if le is None:
        return None
    table, count = struct.unpack_from("<II", data, le + 0x40)
    bases = {}
    for i in range(count):
        vsize, base, flags = struct.unpack_from("<III", data, le + table + i * 24)
        bases[i + 1] = (base or (i + 1) * 0x100000, vsize, flags)
    return bases


_OPERATORS = {"ct": None, "dt": None, "nw": "operator new", "na": "operator new[]", "dl": "operator delete",
              "da": "operator delete[]", "aa": "operator=", "eq": "operator==", "ne": "operator!=",
              "lt": "operator<", "gt": "operator>", "pl": "operator+", "mi": "operator-", "ml": "operator*",
              "dv": "operator/", "ix": "operator[]", "cl": "operator()", "rf": "operator->", "cv": "operator cast"}


def _split(name):
    """W?... -> (base name, [scopes innermost first], rest of the mangling after the scopes)."""
    body = name[2:]
    if body.startswith("$") and body[1:3] in _OPERATORS and body[3:4] in (":", "$"):
        base, rest = "$" + body[1:3], body[3:]
    else:
        base, _, rest = body.partition("$")
        rest = "$" + rest if rest.startswith(":") else rest
    rest = rest[1:] if rest.startswith("$") and rest[1:2] == ":" else rest
    scopes = []
    while rest.startswith(":"):
        scope, _, rest = rest[1:].partition("$")
        scopes.append(scope)
    if base.startswith("$") and base[1:] in _OPERATORS:
        op = base[1:]
        cls = scopes[0] if scopes else ""
        base = cls if op == "ct" else ("~" + cls if op == "dt" else _OPERATORS[op])
    return base, scopes, rest


def demangle(name):
    """Readable form of a Watcom C++ name: W?Name$:Class$n(args)ret -> Class::Name."""
    if not name.startswith("W?"):
        return name
    if name.startswith("W?$Wvt"):
        return "vftable:" + name[6:].split("$")[0]
    base, scopes, _ = _split(name)
    return "::".join(list(reversed(scopes)) + [base]) if scopes else base


_BASIC = {"a": "signed char", "c": "char", "s": "short", "i": "int", "l": "long", "f": "float",
          "d": "double", "t": "long double", "v": "void", "q": "bool", "w": "wchar_t", "e": "..."}


def _type(t, i):
    """One Watcom-mangled type at t[i:]: (C type text, slots of 4 bytes, next index)."""
    quals = ""
    while i < len(t) and t[i] in "xy":
        quals += "const " if t[i] == "x" else "volatile "
        i += 1
    if i >= len(t):
        return "?", 1, i
    ch = t[i]
    if ch in "pr":                                    # pointer / reference: p|r [n|f] pointee
        i += 1
        far = i < len(t) and t[i] == "f"
        if i < len(t) and t[i] in "nf":
            i += 1
        inner, _, i = _type(t, i)
        return quals + inner + (" far" if far else "") + ("*" if ch == "p" else "&"), 2 if far else 1, i
    if ch == "u" and i + 1 < len(t) and t[i + 1] in _BASIC:
        return quals + "unsigned " + _BASIC[t[i + 1]], 1, i + 2
    if ch == "$":                                     # class / enum: $Name$$ (scopes $:Outer)
        end = t.find("$$", i + 1)
        if end < 0:
            return quals + t[i:], 1, len(t)
        parts = t[i + 1:end].split("$:")
        return quals + "::".join(reversed(parts)), 1, end + 2
    if ch == "[":                                     # array: [N]type
        end = t.find("]", i)
        inner, slots, j = _type(t, end + 1)
        return quals + inner + t[i:end + 1], slots, j
    if ch in _BASIC:
        slots = 2 if ch in "dt" else 0 if ch in "ve" else 1
        return quals + _BASIC[ch], slots, i + 1
    return quals + t[i:], 1, len(t)                  # not understood: keep the rest verbatim


def signature(name):
    """What the name says about the symbol: qualified name, class, parameter and return types,
    calling convention (Watcom: C++ and NAME_ are register-based, _NAME is stack-based)."""
    out = {"name": demangle(name), "class": None, "params": None, "returns": None, "type": None,
           "convention": "unknown"}
    if name.startswith("W?"):
        out["convention"] = "watcom"
        body = name[2:]
        if body.startswith("$Wvt"):
            out["type"] = "vftable"
            return out
        base, scopes, rest = _split(name)
        out["class"] = "::".join(reversed(scopes)) or None
        if rest.startswith("n") or rest.startswith("f"):
            rest = rest[1:]
        if rest.startswith("("):
            close = rest.find(")")
            args, ret = rest[1:close], rest[close + 1:]
            params, i = [], 0
            while i < len(args):
                text, slots, i = _type(args, i)
                if text != "void":
                    params.append({"type": text, "slots": slots})
            out["params"] = params
            out["returns"] = _type(ret, 0)[0] if ret and ret != "_" else "void"   # "_": constructor/destructor
        else:
            out["type"] = _type(rest, 0)[0] if rest else None
    elif name.endswith("_") and not name.startswith("_"):
        out["convention"] = "watcom"                 # C, register calling: NAME_
        out["name"] = name[:-1]
    elif name.startswith("_") and not name.startswith("__"):
        out["convention"] = "cdecl"                  # C, stack calling: _NAME
    if not out["name"]:
        out["name"] = name                           # compiler-generated ($Wts type signatures, ...)
    return out


def parse(data):
    if len(data) < 14:
        raise DebugInfoError("file too short")
    sig, exe_major, exe_minor, obj_major, obj_minor, lang_size, seg_size, size = struct.unpack_from(
        "<HBBBBHHI", data, len(data) - 14)
    if sig != SIGNATURE:
        raise DebugInfoError("no Watcom debug info (no 8386h master header at end of file)")
    if size > len(data) or size < 14:
        raise DebugInfoError("bad debug info size %#x" % size)
    start = len(data) - size
    o = start
    languages = [s.decode("latin-1") for s in data[o:o + lang_size].split(b"\0") if s]
    o += lang_size
    segments = list(struct.unpack_from("<%dH" % (seg_size // 2), data, o))
    o += seg_size
    info = {"version": "%d.%d" % (exe_major, exe_minor), "languages": languages,
            "segments": segments, "modules": [], "globals": [], "addresses": []}
    end = len(data) - 14
    while o + 18 <= end:
        mod_off, gbl_off, addr_off, sec_size, sec_id = struct.unpack_from("<IIIIH", data, o)
        if sec_size == 0 or o + sec_size > end + 14:
            break
        # modules: from mod_off to gbl_off
        p, q = o + mod_off, o + gbl_off
        base_index = len(info["modules"])
        while p + 21 <= q:
            lang = struct.unpack_from("<H", data, p)[0]
            n = data[p + 20]
            name = data[p + 21:p + 21 + n].decode("latin-1")
            info["modules"].append({"name": name, "language": languages[lang] if lang < len(languages) else lang})
            p += 21 + n
        # globals: from gbl_off to addr_off
        p, q = o + gbl_off, o + addr_off
        while p + 10 <= q:
            off, seg, mod, kind, n = struct.unpack_from("<IHHBB", data, p)
            name = data[p + 10:p + 10 + n].decode("latin-1")
            info["globals"].append({"offset": off, "segment": seg, "module": base_index + mod,
                                    "kind": kind, "name": name})
            p += 10 + n
        # address info: from addr_off to the section end
        p, q = o + addr_off, o + sec_size
        while p + 8 <= q:
            off, seg, count = struct.unpack_from("<IHH", data, p)
            p += 8
            for _ in range(count):
                if p + 6 > q:
                    break
                sz, mod = struct.unpack_from("<IH", data, p)
                info["addresses"].append({"offset": off, "segment": seg, "size": sz, "module": base_index + mod})
                off += sz
                p += 6
        o += sec_size
    return info


def linear(bases, seg, off):
    if bases and seg in bases:
        return bases[seg][0] + off
    return None


def is_code(g):
    return bool(g["kind"] & 4) or not (g["kind"] & 2)


def function_rows(path, raw=False):
    """The code symbols of `path` as find_seams/rank_seams function rows, or None without debug info."""
    data = open(path, "rb").read()
    try:
        info = parse(data)
    except DebugInfoError:
        return None
    bases = segment_bases(data)
    if bases is None:
        return None
    code = sorted((g for g in info["globals"] if is_code(g) and g["segment"] in bases),
                  key=lambda g: linear(bases, g["segment"], g["offset"]))
    rows = []
    for i, g in enumerate(code):
        start = linear(bases, g["segment"], g["offset"])
        nxt = next((h for h in code[i + 1:] if h["segment"] == g["segment"]), None)
        end = linear(bases, nxt["segment"], nxt["offset"]) if nxt else bases[g["segment"]][0] + bases[g["segment"]][1]
        rows.append({"addr": start, "name": g["name"] if raw else demangle(g["name"]), "size": end - start,
                     "thunk": False})
    return rows


def export_json(path, exe, info, bases, code, dat, addr_of):
    """The whole symbol picture in one file: what gen_decomp.py needs to lay out a decompilation."""
    import json
    ranges = {}
    for r in info["addresses"]:
        lin = linear(bases, r["segment"], r["offset"])
        ranges.setdefault(r["module"], []).append({"start": lin, "size": r["size"], "segment": r["segment"]})
    code_sorted = sorted(code, key=addr_of)
    functions = []
    for i, g in enumerate(code_sorted):
        nxt = next((h for h in code_sorted[i + 1:] if h["segment"] == g["segment"]), None)
        end = addr_of(nxt) if nxt else (bases[g["segment"]][0] + bases[g["segment"]][1] if bases and g["segment"] in bases else addr_of(g))
        sig = signature(g["name"])
        sig.update({"address": addr_of(g), "size": end - addr_of(g), "mangled": g["name"],
                    "module": g["module"], "static": bool(g["kind"] & 1)})
        functions.append(sig)
    data = []
    for g in sorted(dat, key=addr_of):
        sig = signature(g["name"])
        data.append({"address": addr_of(g), "name": sig["name"], "class": sig["class"], "type": sig["type"],
                     "mangled": g["name"], "module": g["module"], "static": bool(g["kind"] & 1)})
    objects = [{"segment": k, "base": v[0], "size": v[1], "flags": v[2]} for k, v in sorted((bases or {}).items())]
    doc = {"executable": os.path.basename(exe), "debug_info": info["version"], "languages": info["languages"],
           "objects": objects,
           "modules": [{"index": i, "name": m["name"], "language": m["language"], "ranges": ranges.get(i, [])}
                       for i, m in enumerate(info["modules"])],
           "functions": functions, "data": data}
    with open(path, "w") as f:
        json.dump(doc, f, indent=1)
    print("wrote %s: %d modules, %d functions, %d data" % (path, len(doc["modules"]), len(functions), len(data)))


def main():
    ap = argparse.ArgumentParser(description="Watcom debug info: symbols and modules")
    ap.add_argument("exe")
    ap.add_argument("--functions", help="write code symbols as address,name,size")
    ap.add_argument("--data", help="write data symbols as address,name,size")
    ap.add_argument("--modules", action="store_true", help="print the source modules and their code ranges")
    ap.add_argument("--raw", action="store_true", help="keep mangled names")
    ap.add_argument("--json", help="write everything (modules, functions with signatures, data) as JSON "
                                   "for tools/decomp/gen_decomp.py")
    a = ap.parse_args()

    data = open(a.exe, "rb").read()
    try:
        info = parse(data)
    except DebugInfoError as e:
        sys.exit("%s: %s" % (a.exe, e))
    bases = segment_bases(data)
    name = (lambda g: g["name"]) if a.raw else (lambda g: demangle(g["name"]))
    module = lambda i: info["modules"][i]["name"] if 0 <= i < len(info["modules"]) else ""

    code = [g for g in info["globals"] if is_code(g)]
    dat = [g for g in info["globals"] if not is_code(g)]
    print("%s: Watcom debug info %s, languages %s, %d modules, %d code and %d data symbols" % (
        os.path.basename(a.exe), info["version"], "/".join(info["languages"]),
        len(info["modules"]), len(code), len(dat)))
    if bases is None:
        print("note: not an LE/LX image; addresses are written as segment:offset")

    def addr_of(g):
        lin = linear(bases, g["segment"], g["offset"])
        return lin if lin is not None else (g["segment"] << 16 | g["offset"])

    def write(path, syms, sized):
        syms = sorted(syms, key=addr_of)
        with open(path, "w") as f:
            f.write("# %s: Watcom debug symbols (tools/analysis/watcom_debug.py)\naddress,name,size,module\n"
                    % os.path.basename(a.exe))
            for i, g in enumerate(syms):
                size = 0
                if sized:
                    # up to the next symbol in the same segment, or the segment's end
                    nxt = next((h for h in syms[i + 1:] if h["segment"] == g["segment"]), None)
                    if nxt:
                        size = addr_of(nxt) - addr_of(g)
                    elif bases and g["segment"] in bases:
                        size = bases[g["segment"]][0] + bases[g["segment"]][1] - addr_of(g)
                f.write('%08x,"%s",%d,"%s"\n' % (addr_of(g), name(g).replace('"', "'"), size, module(g["module"])))
        print("wrote %d symbols to %s" % (len(syms), path))

    if a.json:
        export_json(a.json, a.exe, info, bases, code, dat, addr_of)
    if a.functions:
        write(a.functions, code, True)
    if a.data:
        write(a.data, dat, False)
    if a.modules:
        ranges = {}
        for r in info["addresses"]:
            lin = linear(bases, r["segment"], r["offset"])
            ranges.setdefault(r["module"], []).append((lin if lin is not None else r["offset"], r["size"], r["segment"]))
        for i, m in enumerate(info["modules"]):
            rs = ", ".join("%08x+%x" % (s, n) for s, n, seg in ranges.get(i, []) if bases and bases.get(seg, (0, 0, 0))[2] & 4)
            print("%3d %-4s %-40s %s" % (i, m["language"], m["name"], rs))


if __name__ == "__main__":
    main()
