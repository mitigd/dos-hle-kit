#!/usr/bin/env python3
"""Rank function-table entries as seam candidates for video, sound, timing and input.

    python3 tools/analysis/rank_seams.py GAME.EXE --functions docs/functions.csv --out docs/ranked-seams.md

The function table can come from Ghidra (`--backend ghidra`), any other decompiler, or the
built-in discovery when `--functions` is omitted. The executable is needed for disassembly and
for its LE/NE/MZ relocation table.

Signals, in rough order of weight:

  * direct `in`/`out`/`ins`/`outs` on a subsystem's ports (VGA, Sound Blaster/AdLib/MPU, PIT,
    keyboard controller, joystick, DMA, ...);
  * software-interrupt vectors (int 10h, 16h, 09h, 08h, 1Ah, 33h, ...);
  * writes/reads in the A0000h-BFFFFh VGA aperture;
  * `cli`/`sti` plus a port or an installed pointer: an interrupt handler;
  * the function's address stored in data (callbacks, driver tables, ISRs);
  * caller propagation: a small leaf helper such as `inp()`/`outp()` boosts its callers, because
    the caller is usually the real seam;
  * a few opcode hints (`rdtsc`);
  * replacement value, which combines the evidence with identification confidence and call-site
    hotness. A per-frame seam used from many places is worth more than a one-off init helper.

The score is evidence, not truth. Read the evidence column and the function body.

A ranking is a discovery aid, not an implementation plan. A port hit identifies a function whose
hardware behaviour has to be replaced; the seam body must implement the function's intent with
host services (audio queue, frame/palette, host clock, host input). It must not emulate the
chip, the keyboard controller, the PIC, or the VGA registers.
"""
import argparse
import collections
import math
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "lib"))

from dos_image import ImageError, load_image  # noqa: E402
from watcom_debug import function_rows  # noqa: E402
from find_seams import (  # noqa: E402
    KNOWN_PORTS, _direct_target, align_rows, augment_with_fixup_targets, capstone_decoders,
    discover_functions, functions_from_csv, read_functions,
)

CATEGORIES = ("video", "sound", "timing", "input")

# Port ranges that strongly identify a subsystem. A port can belong to more than one category
# (3DAh is both video status and a retrace wait, 61h both speaker and PIT gate).
PORT_RANGES = (
    ("video", 0x3B0, 0x3BF, 8, "MDA/VGA range"),
    ("video", 0x3C0, 0x3DF, 8, "VGA range"),
    ("sound", 0x220, 0x22F, 10, "Sound Blaster"),
    ("sound", 0x240, 0x24F, 8, "Sound Blaster alias"),
    ("sound", 0x260, 0x26F, 8, "Sound Blaster alias"),
    ("sound", 0x280, 0x28F, 8, "Sound Blaster alias"),
    ("sound", 0x330, 0x331, 9, "MPU-401"),
    ("sound", 0x388, 0x389, 9, "AdLib"),
    ("sound", 0x000, 0x00F, 5, "DMA controller"),
    ("sound", 0x081, 0x08F, 5, "DMA page"),
    ("timing", 0x040, 0x043, 10, "PIT"),
    ("timing", 0x070, 0x071, 4, "CMOS/RTC"),
    ("input", 0x060, 0x060, 10, "keyboard data"),
    ("input", 0x064, 0x064, 9, "keyboard controller"),
    ("input", 0x201, 0x201, 10, "joystick"),
)

INT_CATEGORY = {
    0x10: ("video", 12),
    0x16: ("input", 12),
    0x09: ("input", 12),
    0x33: ("input", 12),
    0x08: ("timing", 12),
    0x1A: ("timing", 10),
    0x1C: ("timing", 8),
    0x15: ("timing", 4),
    0x21: ("system", 2),
    0x31: ("system", 2),
    0x2F: ("system", 1),
}


def _port_categories(port):
    hits = []
    for cat, lo, hi, weight, label in PORT_RANGES:
        if lo <= port <= hi:
            hits.append((cat, weight + (4 if port in (0x3C8, 0x3C9, 0x3D4, 0x3D5,
                                                      0x3C4, 0x3C5, 0x3CE, 0x3CF,
                                                      0x3DA, 0x22F, 0x388, 0x330, 0x60, 0x64)
                                    else 0), label))
    # 61h is both the PC speaker gate and the keyboard-controller acknowledge. Pair it with
    # PIT channel 2 before calling it sound; otherwise it is not evidence for a category.
    if port in (0x020, 0x021, 0x0A0, 0x0A1):
        hits.append(("isr", 2, "PIC"))
    return hits


def _int_value(ins):
    m = re.search(r"(0x[0-9a-f]+|\b\d+\b)", ins.op_str, re.I)
    if not m:
        return None
    try:
        return int(m.group(1), 0)
    except ValueError:
        return None


def _features(img, decoder, f):
    region = img.code_region_at(f["start"])
    off = f["start"] - region.base
    code = bytes(region.data[off:off + f["size"]])
    ports = collections.Counter()
    ints = collections.Counter()
    calls = set()
    cli = sti = rdtsc = aperture = io = 0
    last_dx = None
    for ins in decoder[region.bits].disasm(code, f["start"]):
        mn = ins.mnemonic.lower()
        text = ins.op_str.lower()
        if mn in ("mov", "movzx", "movsx") and re.match(r"e?dx,\s*", text):
            m = re.search(r"(0x[0-9a-f]+|\d+)\s*$", text)
            if m:
                try:
                    last_dx = int(m.group(1), 0)
                except ValueError:
                    pass
        if mn in ("in", "out", "insb", "insw", "insd", "outsb", "outsw", "outsd"):
            io += 1
            port = None
            if "dx" in text:
                port = last_dx
            else:
                m = re.search(r"(0x[0-9a-f]+|\b\d+\b)", text)
                if m:
                    try:
                        port = int(m.group(1), 0)
                    except ValueError:
                        port = None
            if port is not None:
                ports[port] += 1
        elif mn == "int":
            v = _int_value(ins)
            if v is not None:
                ints[v] += 1
        elif mn in ("cli", "sti"):
            cli += mn == "cli"
            sti += mn == "sti"
        elif mn == "rdtsc":
            rdtsc += 1
        if mn.startswith("call"):
            target = _direct_target(ins, img)
            if target is not None and img.code_region_at(target):
                calls.add(target)
        for m in re.finditer(r"0x([0-9a-f]+)", text):
            try:
                value = int(m.group(1), 16)
            except ValueError:
                continue
            if 0xA0000 <= value < 0xC0000:
                aperture += 1
    return {"ports": ports, "ints": ints, "calls": calls, "cli": cli, "sti": sti,
            "rdtsc": rdtsc, "aperture": aperture, "io": io}


def analyze(img, decoder, functions):
    by_start = {f["start"]: f for f in functions}
    stored = {fx.target for fx in img.fixups if fx.target and img.code_region_at(fx.target)}
    feats = {f["start"]: _features(img, decoder, f) for f in functions}
    callers = collections.defaultdict(set)
    for start, ft in feats.items():
        for target in ft["calls"]:
            owner = next((g["start"] for g in functions if g["start"] <= target < g["end"]), None)
            if owner is not None:
                callers[owner].add(start)

    points = collections.defaultdict(lambda: collections.defaultdict(float))
    evidence = collections.defaultdict(lambda: collections.defaultdict(set))

    def add(start, cat, value, why):
        if value <= 0:
            return
        points[start][cat] += value
        evidence[start][cat].add(why)

    for f in functions:
        start = f["start"]
        ft = feats[start]
        for port, count in ft["ports"].items():
            label = KNOWN_PORTS.get(port, "")
            for cat, weight, what in _port_categories(port):
                if cat == "isr":
                    continue
                add(start, cat, weight + min(count, 8),
                    "port %Xh%s x%d (%s)" % (port, " " + label if label else "", count, what))
        if 0x61 in ft["ports"] and (0x42 in ft["ports"] or 0x43 in ft["ports"]):
            add(start, "sound", 5, "port 61h speaker gate + PIT channel 2")
        for vector, count in ft["ints"].items():
            cat, weight = INT_CATEGORY.get(vector, (None, 0))
            if cat in CATEGORIES:
                add(start, cat, weight + min(count, 4), "int %02Xh x%d" % (vector, count))
        if ft["aperture"]:
            add(start, "video", 10 + min(ft["aperture"], 10),
                "VGA aperture access x%d" % ft["aperture"])
        if ft["rdtsc"]:
            add(start, "timing", 8, "rdtsc")
        if ft["cli"] or ft["sti"]:
            for cat in list(points[start]):
                add(start, cat, 2, "cli/sti")
        is_stored = start in stored
        isr = is_stored and (ft["cli"] or ft["sti"] or 0x20 in ft["ports"] or 0x21 in ft["ports"]
                             or 0x60 in ft["ports"] or 0x64 in ft["ports"]
                             or 0x08 in ft["ints"] or 0x09 in ft["ints"])
        if is_stored:
            for cat in list(points[start]):
                add(start, cat, 4, "address stored in data")
        if isr:
            for cat in list(points[start]):
                add(start, cat, 8, "installed handler (stored + cli/ports)")

    # leaf inp()/outp()-style helpers do not own the seam; their direct callers do.
    base = {s: {c: v for c, v in cats.items()} for s, cats in points.items()}
    for f in functions:
        start = f["start"]
        ft = feats[start]
        if not ft["calls"] and ft["ports"] and f["size"] <= 64:
            for caller in callers.get(start, ()):
                for cat, value in base.get(start, {}).items():
                    add(caller, cat, min(8, max(2, value // 3)),
                        "calls leaf helper %s" % f["name"])
                    evidence[caller][cat].add("leaf helper caller")

    # One level of caller propagation: a seam often lives one function above the port wrapper.
    for f in functions:
        start = f["start"]
        for caller in callers.get(start, ()):
            for cat, value in base.get(start, {}).items():
                add(caller, cat, min(6, max(1, int(value // 4))),
                    "calls %s" % f["name"])

    out = []
    for f in functions:
        start = f["start"]
        cats = {c: points[start][c] for c in CATEGORIES if points[start][c] >= 5}
        if not cats:
            continue
        ft = feats[start]
        direct = base.get(start, {})
        caller_n = len(callers.get(start, ()))
        leaf = not ft["calls"] and bool(ft["ports"]) and f["size"] <= 64
        is_stored = start in stored
        isr = is_stored and (ft["cli"] or ft["sti"] or 0x20 in ft["ports"] or 0x21 in ft["ports"]
                             or 0x60 in ft["ports"] or 0x64 in ft["ports"]
                             or 0x08 in ft["ints"] or 0x09 in ft["ints"])
        values, confidence, priorities, why = {}, {}, {}, {}
        for cat, score in cats.items():
            d = direct.get(cat, 0.0)
            if d > 0:
                conf = 0.35 + min(0.45, d / 40.0)
                if isr: conf += 0.15
                if is_stored: conf += 0.05
                if ft["ints"] or ft["aperture"]: conf += 0.05
            else:
                conf = 0.25 + min(0.15, score / 80.0)   # propagated only
            conf = min(0.98, conf)

            hot = 1.0
            if caller_n:
                hot += min(1.5, math.log2(1 + caller_n) * 0.35)
            if isr: hot += 0.8
            if is_stored: hot += 0.25
            if leaf: hot *= 0.35                         # helper, not the seam
            if caller_n == 0 and not is_stored: hot *= 0.65   # usually one-off init
            if f["size"] > 12000: hot *= 0.75            # loop-like; scope depends

            bits = []
            bits.append("direct evidence" if d > 0 else "propagated from callers")
            if isr: bits.append("installed handler")
            if leaf: bits.append("leaf helper; inspect callers")
            if caller_n: bits.append("%d direct caller%s" % (caller_n, "" if caller_n == 1 else "s"))
            if f["size"] > 12000: bits.append("large/loop-like; scope depends")
            if caller_n == 0 and not is_stored: bits.append("no callers or stored pointer")
            why[cat] = "; ".join(bits)
            values[cat] = score * conf * hot
            confidence[cat] = conf
        out.append({
            "function": f,
            "cats": cats,
            "evidence": {c: sorted(evidence[start][c]) for c in cats},
            "values": values,
            "confidence": confidence,
            "priorities": priorities,
            "why": why,
            "leaf": leaf,
            "callers": caller_n,
            "isr": isr,
            "stored": is_stored,
        })
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("exe", help="COM, MZ, NE, LE or LX executable")
    ap.add_argument("--functions", help="functions CSV: address,name[,size]")
    ap.add_argument("--out", help="write markdown here; default stdout")
    ap.add_argument("--top", type=int, default=25, help="rows per category (default 25)")
    ap.add_argument("--shortlist", type=int, default=12,
                    help="cross-category replacement shortlist size (default 12)")
    ap.add_argument("--category", choices=CATEGORIES, help="show only this category")
    ap.add_argument("--include-data", action="store_true",
                    help="include Ghidra switchdata/case labels in the ranking")
    a = ap.parse_args()

    try:
        img = load_image(a.exe)
    except ImageError as e:
        sys.exit("%s: %s" % (a.exe, e))
    decoder = capstone_decoders()
    if a.functions:
        try:
            rows, meta = read_functions(a.functions)
        except OSError as e:
            sys.exit("cannot read functions CSV: %s" % e)
        rows = align_rows(img, rows, meta, [])
        functions = functions_from_csv(img, decoder, rows)
        source = "functions CSV `%s`" % a.functions
    elif function_rows(a.exe):
        functions = functions_from_csv(img, decoder, function_rows(a.exe))
        augment_with_fixup_targets(img, decoder, functions)
        source = "the executable's Watcom debug info"
    else:
        functions = discover_functions(img, decoder, 50000)
        augment_with_fixup_targets(img, decoder, functions)
        source = "built-in function discovery"

    ranked = analyze(img, decoder, functions)
    if not a.include_data:
        ranked = [r for r in ranked if not re.match(r"^(switchdata|caseD_|PTR_)", r["function"]["name"])]
    cats = (a.category,) if a.category else CATEGORIES

    # Priorities are relative within each category: value is evidence x confidence x hotness.
    for cat in CATEGORIES:
        pool = [r for r in ranked if cat in r["values"]]
        if not pool:
            continue
        top = max(r["values"][cat] for r in pool) or 1.0
        for r in pool:
            ratio = r["values"][cat] / top
            if r["leaf"]:
                r["priorities"][cat] = "Low (helper)"
            elif r["function"]["size"] > 12000:
                r["priorities"][cat] = "Depends"
            elif r["confidence"][cat] < 0.55:
                r["priorities"][cat] = "Medium" if ratio >= 0.25 else "Low"
            elif ratio >= 0.55:
                r["priorities"][cat] = "Very high"
            elif ratio >= 0.30:
                r["priorities"][cat] = "High"
            elif ratio >= 0.12:
                r["priorities"][cat] = "Medium"
            else:
                r["priorities"][cat] = "Low"

    # Round-robin shortlist: at least one from each area before filling by raw value.
    short = []
    used = set()
    level = 0
    ordered = {cat: sorted((r for r in ranked if cat in r["values"] and not r["leaf"]),
                           key=lambda r: r["values"][cat], reverse=True) for cat in cats}
    while len(short) < max(0, a.shortlist):
        added = False
        for cat in cats:
            if level < len(ordered[cat]):
                r = ordered[cat][level]
                key = (r["function"]["start"], cat)
                if key not in used:
                    used.add(key)
                    short.append((cat, r))
                    added = True
                    if len(short) >= a.shortlist:
                        break
        if not added:
            break
        level += 1
    short.sort(key=lambda x: x[1]["values"][x[0]], reverse=True)

    out = []
    w = out.append
    w("# Ranked seam candidates: %s\n" % os.path.basename(img.path))
    w("Format: **%s** (%d-bit). Functions: %d from %s.\n" % (img.format, img.bits,
                                                               len(functions), source))
    w("Evidence is combined with identification confidence and call-site hotness into a")
    w("**replacement value**. Five high-value seams can beat fifty arbitrary ones; the shortlist")
    w("below is cross-category, not just the top of one hardware table.\n")
    w("**The target is function replacement, not device emulation.** A port hit only locates the")
    w("seam. Implement its intent natively (host audio, frames/palette, host clock, host input);")
    w("do not build a Sound Blaster/AdLib/VGA/PIT/keyboard-controller model.\n")
    total = 0
    if short:
        w("\n## Replacement shortlist (best value across areas)\n")
        w("| # | priority | confidence | function | addr | area | value | why |")
        w("| --: | :-- | --: | :-- | :-- | :-- | --: | :-- |")
        for i, (cat, r) in enumerate(short[:max(1, a.shortlist)], 1):
            f = r["function"]
            w("| %d | %s | %.0f%% | %s | `%08x` | %s | %.1f | %s |" % (
                i, r["priorities"][cat], 100.0 * r["confidence"][cat], f["name"], f["start"],
                cat, r["values"][cat], r["why"][cat]))
        total += len(short)
    for cat in cats:
        rows = sorted((r for r in ranked if cat in r["values"]),
                      key=lambda r: r["values"][cat], reverse=True)[:max(1, a.top)]
        w("\n## %s (%d candidates, showing %d)\n" % (
            cat, sum(1 for r in ranked if cat in r["values"]), len(rows)))
        w("| rank | priority | confidence | function | addr | size | value | evidence |")
        w("| --: | :-- | --: | :-- | :-- | --: | --: | :-- |")
        for i, r in enumerate(rows, 1):
            f = r["function"]
            ev = "; ".join(r["evidence"][cat])
            w("| %d | %s | %.0f%% | %s | `%08x` | %d | %.1f | %s |" % (
                i, r["priorities"][cat], 100.0 * r["confidence"][cat], f["name"], f["start"],
                f["size"], r["values"][cat], ev))
        total += len(rows)
    text = "\n".join(out) + "\n"
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        open(a.out, "w").write(text)
        print("%s: %d ranked candidates" % (a.out, total))
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
