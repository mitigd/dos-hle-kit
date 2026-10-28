#!/usr/bin/env python3
"""Hardware-surface report for a DOS game: the seam candidates.

    python3 tools/analysis/find_seams.py GAME.EXE [--backend native|csv|ghidra] [--out REPORT.md]

Supports COM, MZ, NE, LE and LX images through tools/lib/dos_image.py. For each function the report
lists port I/O, interrupt toggles, software interrupts, callers and functions whose address is
stored in data (callbacks, interrupt handlers).

Function-discovery backends:
  native  recursive traversal from the entry point, code segment starts and internal fixups
  csv     a decompiler CSV: address,name[,size] (hex addresses)
  ghidra  headless Ghidra, exported by tools/ghidra/ExportFunctions.java
  watcom  the executable's own Watcom debug info (tools/analysis/watcom_debug.py): real function names
  auto    csv when --functions is given, else watcom when the EXE carries Watcom debug info,
          otherwise native

Capstone is required for disassembly:  pip install capstone
"""
import argparse
import collections
import csv
import os
import re
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "lib"))
from dos_image import ImageError, load_image  # noqa: E402
from watcom_debug import function_rows  # noqa: E402

KNOWN_PORTS = {
    0x20: "PIC1 cmd", 0x21: "PIC1 mask", 0xA0: "PIC2 cmd", 0xA1: "PIC2 mask",
    0x40: "PIT ch0", 0x42: "PIT ch2", 0x43: "PIT cmd", 0x60: "kbd data", 0x61: "kbd/speaker",
    0x64: "kbd status", 0x201: "joystick", 0x388: "AdLib", 0x389: "AdLib data",
    0x3C0: "VGA attr", 0x3C4: "VGA seq idx", 0x3C5: "VGA seq data", 0x3C7: "DAC read idx",
    0x3C8: "DAC write idx", 0x3C9: "DAC data", 0x3CE: "VGA gc idx", 0x3CF: "VGA gc data",
    0x3D4: "CRTC idx", 0x3D5: "CRTC data", 0x3DA: "VGA status", 0x70: "CMOS idx", 0x71: "CMOS data",
}
for base in (0x220, 0x240, 0x260, 0x280):
    for off, what in ((4, "SB mixer idx"), (5, "SB mixer data"), (6, "SB DSP reset"),
                      (0xA, "SB DSP read"), (0xC, "SB DSP write"), (0xE, "SB DSP status")):
        KNOWN_PORTS[base + off] = what
for p in range(0, 0x10):
    KNOWN_PORTS.setdefault(p, "DMA1")
for p in (0x81, 0x82, 0x83, 0x87):
    KNOWN_PORTS[p] = "DMA page"


def parse_int(s):
    s = str(s).strip()
    if not s:
        return 0
    return int(s, 0) if s.lower().startswith("0x") else int(s, 16)


def report_path(path):
    """A path for the report: relative when it is below the working directory, else its name.

    Reports are committed to game repositories, so they must not leak the local checkout layout
    (a user's game directory, home directory or mount point).
    """
    if not path:
        return ""
    full = os.path.abspath(path)
    try:
        rel = os.path.relpath(full)
    except ValueError:                      # Windows: a different drive has no relative path
        return os.path.basename(full)
    if rel == os.pardir or rel.startswith(os.pardir + os.sep):
        return os.path.basename(full)
    return rel


def read_functions(path):
    """Read address,name[,size] from any decompiler; returns (rows, metadata)."""
    rows, meta, header = [], {}, None
    with open(path, newline="") as f:
        for fields in csv.reader(f):
            if not fields or not fields[0].strip():
                continue
            first = fields[0].strip()
            if first.startswith("#"):
                line = first.lstrip("#").strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    meta[k.strip()] = v.strip()
                continue
            try:
                addr = parse_int(first)
            except ValueError:
                header = [x.strip().lower() for x in fields]
                continue                      # header row (addr,name,size,...)
            name = fields[1].strip() if len(fields) > 1 else ""
            try:
                size = int(fields[2], 0) if len(fields) > 2 and fields[2].strip() else 0
            except ValueError:
                size = 0
            thunk = False
            if header and "is_thunk" in header:
                idx = header.index("is_thunk")
                thunk = idx < len(fields) and fields[idx].strip().lower() in ("1", "true", "yes")
            rows.append({"addr": addr, "name": name or ("FUN_%08x" % addr), "size": size,
                         "thunk": thunk})
    return rows, meta


def ghidra_available(explicit=None):
    candidates = []
    if explicit:
        candidates.append(os.path.join(explicit, "support", "analyzeHeadless")
                          if os.path.isdir(explicit) else explicit)
    for var in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        root = os.environ.get(var)
        if root:
            candidates.append(os.path.join(root, "support", "analyzeHeadless"))
    candidates += ["/usr/libexec/ghidra/support/analyzeHeadless",
                   "/opt/ghidra/support/analyzeHeadless",
                   "/usr/share/ghidra/support/analyzeHeadless"]
    return any(os.path.isfile(c) and os.access(c, os.X_OK) for c in candidates)


def run_ghidra(exe, out, ghidra=None, keep_project=False, existing_project=None,
               project_name=None, program=None):
    tool = os.path.join(os.path.dirname(_HERE), "ghidra", "ghidra_export.py")
    cmd = [sys.executable, tool]
    if exe:
        cmd.append(exe)
    cmd += ["-o", out]
    if ghidra:
        cmd += ["--ghidra", ghidra]
    if keep_project:
        cmd += ["--keep-project"]
    if existing_project:
        cmd += ["--existing-project", existing_project]
        if project_name:
            cmd += ["--project-name", project_name]
        if program:
            cmd += ["--program", program]
    proc = subprocess.run(cmd)
    if proc.returncode != 0 or not os.path.exists(out):
        sys.exit("ghidra backend failed")


def align_rows(img, rows, meta, notes):
    """Align a decompiler's addresses with the kit loader's linked addresses.

    Different loaders anchor an image differently (Ghidra's MZ loader, for example, puts the PSP
    at 1000h while dos_image models it at 0). Try the exported entry point and image base, keep
    the shift that puts the most functions inside a code region, and report it.
    """
    candidates = []
    if meta.get("entry"):
        try:
            candidates.append(("entry", int(meta["entry"], 16), img.entry))
        except ValueError:
            pass
    if meta.get("image_base") and img.regions:
        try:
            candidates.append(("image_base", int(meta["image_base"], 16), img.regions[0].base))
        except ValueError:
            pass
    best = None
    for label, anchor, ours in candidates:
        if not anchor and not ours:
            continue
        delta = ours - anchor
        if abs(delta) > 0x10000000:
            continue
        score = sum(1 for r in rows if img.code_region_at((r["addr"] + delta) & 0xFFFFFFFF))
        if best is None or score > best[0]:
            best = (score, delta, label, anchor, ours)
    if not best or best[0] == 0 or best[1] == 0:
        return rows
    _, delta, label, anchor, ours = best
    notes.append("function addresses adjusted by %+d (0x%x) from the decompiler's %s (%08x -> %08x)"
                 % (delta, abs(delta), label, anchor, ours))
    return [dict(r, addr=(r["addr"] + delta) & 0xFFFFFFFF) for r in rows]


def capstone_decoders():
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_16, CS_MODE_32
    except ImportError:
        sys.exit("capstone is required for disassembly: pip install capstone")
    return {16: Cs(CS_ARCH_X86, CS_MODE_16), 32: Cs(CS_ARCH_X86, CS_MODE_32)}


def decode_one(decoder, img, addr):
    region = img.code_region_at(addr)
    if not region:
        return None
    off = addr - region.base
    if off < 0 or off >= len(region.data):
        return None
    blob = bytes(region.data[off:off + 16])
    if not blob:
        return None
    return next(iter(decoder[region.bits].disasm(blob, addr, 1)), None)


NUM_RE = re.compile(r"(?:^|[\s,])((?:0x)?[0-9a-fA-F]+)$")
FAR_RE = re.compile(r"(?:^|[\s,])((?:0x)?[0-9a-fA-F]+):((?:0x)?[0-9a-fA-F]+)$")


def _direct_target(ins, img):
    """Resolve a direct near/far branch operand; None for registers/memory."""
    op = ins.op_str.strip()
    m = FAR_RE.search(op)
    if m:
        try:
            return img.far_target(parse_int(m.group(1)), parse_int(m.group(2)))
        except ValueError:
            return None
    m = NUM_RE.search(op)
    if not m:
        return None
    try:
        value = parse_int(m.group(1))
    except ValueError:
        return None
    if img.code_region_at(value):
        return value
    region = img.code_region_at(ins.address)
    if region and region.bits == 16:
        wrapped = img.near_target(region, value)
        if img.code_region_at(wrapped):
            return wrapped
    return value


def walk_function(img, decoder, start, max_insns):
    """Follow a function's control flow; returns (end, calls, instruction_count)."""
    todo = [start]
    seen = set()
    calls = set()
    end = start
    while todo and len(seen) < max_insns:
        addr = todo.pop()
        if addr in seen:
            continue
        region = img.code_region_at(addr)
        if not region:
            continue
        ins = decode_one(decoder, img, addr)
        if not ins:
            seen.add(addr)
            continue
        seen.add(addr)
        end = max(end, addr + ins.size)
        mn = ins.mnemonic.lower()
        if mn.startswith("call"):
            target = _direct_target(ins, img)
            if target is not None and img.code_region_at(target):
                calls.add(target)
            todo.append(addr + ins.size)
        elif mn == "jmp":
            target = _direct_target(ins, img)
            if target is not None and img.code_region_at(target):
                todo.append(target)
        elif mn in ("jcc", "loop", "loope", "loopne", "loopz", "loopnz", "jcxz", "jecxz"):
            target = _direct_target(ins, img)
            if target is not None and img.code_region_at(target):
                todo.append(target)
            todo.append(addr + ins.size)
        elif mn.startswith("j"):
            target = _direct_target(ins, img)
            if target is not None and img.code_region_at(target):
                todo.append(target)
            todo.append(addr + ins.size)
        elif mn in ("ret", "retf", "iret", "iretd", "int3", "hlt", "ud2", "sysenter", "sysexit"):
            pass
        else:
            todo.append(addr + ins.size)
    return max(end, start + 1), calls, len(seen)


def discover_functions(img, decoder, max_functions):
    starts = set()
    if img.entry:
        starts.add(img.entry)
    for r in img.regions:
        if r.executable and img.format in ("NE", "LE", "LX"):
            starts.add(r.base)
    for fx in img.fixups:
        if fx.target and img.code_region_at(fx.target):
            starts.add(fx.target)
    pending = sorted(starts)
    functions = []
    by_start = {}
    while pending and len(functions) < max_functions:
        start = pending.pop(0)
        if start in by_start:
            continue
        if any(f["start"] < start < f["end"] for f in functions):
            continue
        if not img.code_region_at(start):
            continue
        end, calls, count = walk_function(img, decoder, start, 200000)
        if not count:
            continue
        f = {"start": start, "end": end, "size": end - start,
             "name": "FUN_%08x" % start, "calls": calls}
        functions.append(f)
        by_start[start] = f
        for target in sorted(calls):
            if target not in by_start and not any(g["start"] < target < g["end"] for g in functions):
                pending.append(target)
        pending.sort()
    return functions


def functions_from_csv(img, decoder, rows):
    funcs = []
    for row in rows:
        start = row["addr"]
        if row.get("thunk") or not img.code_region_at(start):
            continue
        size = row["size"]
        calls = set()
        if size <= 0:
            end, calls, _ = walk_function(img, decoder, start, 200000)
            size = max(1, end - start)
        else:
            region = img.code_region_at(start)
            size = min(size, max(1, region.end - start))
            # Read calls in the declared range for the caller table.
            off = start - region.base
            for ins in decoder[region.bits].disasm(bytes(region.data[off:off + size]), start):
                if ins.mnemonic.lower().startswith("call"):
                    target = _direct_target(ins, img)
                    if target is not None and img.code_region_at(target):
                        calls.add(target)
        funcs.append({"start": start, "end": start + size, "size": size,
                      "name": row["name"], "calls": calls})
    funcs.sort(key=lambda f: f["start"])
    return funcs


def augment_with_fixup_targets(img, decoder, functions):
    """Add code fixup targets that no backend reported as functions.

    LE/NE/MZ relocation tables are the authoritative list of "address taken" code. A target can
    sit inside a function body that a decompiler chose to merge; it is still where a callback or
    handler starts, so analyze it as a pointer target instead of losing it.
    """
    known = {f["start"] for f in functions}
    added = 0
    for target in sorted({fx.target for fx in img.fixups
                          if fx.target and img.code_region_at(fx.target)}):
        if target in known:
            continue
        # A target inside a backend function body is a label (switch case, local jump target).
        # Adding it again would duplicate the function's hardware accesses in the report.
        if any(f["start"] < target < f["end"] for f in functions):
            continue
        end, calls, count = walk_function(img, decoder, target, 200000)
        if not count or end <= target:
            continue
        functions.append({"start": target, "end": end, "size": end - target,
                          "name": "PTR_%08x" % target, "calls": calls, "pointer": True})
        known.add(target)
        added += 1
    functions.sort(key=lambda f: f["start"])
    return added


def analyze_function(img, decoder, f):
    region = img.code_region_at(f["start"])
    off = f["start"] - region.base
    code = bytes(region.data[off:off + f["size"]])
    ops = collections.Counter()
    ports = collections.Counter()
    ints = collections.Counter()
    calls = set()
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
            key = "ins" if mn.startswith("ins") else "outs" if mn.startswith("outs") else mn
            ops[key] += 1
            if "dx" in text:
                port = last_dx
            else:
                m = re.search(r"(0x[0-9a-f]+|\b\d+\b)", text)
                try:
                    port = int(m.group(1), 0) if m else None
                except ValueError:
                    port = None
            if port is not None:
                ports[port] += 1
        elif mn in ("cli", "sti"):
            ops[mn] += 1
        elif mn == "int":
            ints[ins.op_str.strip()] += 1
        if mn.startswith("call"):
            target = _direct_target(ins, img)
            if target is not None and img.code_region_at(target):
                calls.add(target)
    return ops, ports, ints, calls


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("exe", nargs="?", help="COM, MZ, NE, LE or LX executable")
    ap.add_argument("--backend", choices=("auto", "native", "csv", "ghidra", "watcom"), default="auto",
                    help="function-discovery backend (default: auto = csv if --functions, else watcom if the EXE has Watcom debug info, else native)")
    ap.add_argument("--functions", help="CSV from any decompiler: address,name[,size] (hex addresses)")
    ap.add_argument("--ghidra", help="Ghidra install directory or analyzeHeadless path")
    ap.add_argument("--ghidra-csv", help="where the ghidra backend writes its function CSV")
    ap.add_argument("--ghidra-project", help="reuse an existing Ghidra project directory")
    ap.add_argument("--ghidra-project-name", help="project name inside --ghidra-project")
    ap.add_argument("--ghidra-program", help="program name inside --ghidra-project (default: EXE basename)")
    ap.add_argument("--keep-ghidra-project", action="store_true")
    ap.add_argument("--refresh-ghidra", action="store_true",
                    help="re-run Ghidra even when --ghidra-csv already exists")
    ap.add_argument("--list-backends", action="store_true", help="show discovery backends and exit")
    ap.add_argument("--list-loaders", action="store_true", help="show executable loaders and exit")
    ap.add_argument("--out", help="write the report here (markdown); default stdout")
    ap.add_argument("--max-functions", type=int, default=50000,
                    help="cap for automatic discovery (default 50000)")
    a = ap.parse_args()

    if a.list_backends:
        print("native  built-in recursive traversal; no external tools")
        print("csv     any decompiler's address,name[,size] CSV")
        print("ghidra  headless Ghidra: %s" % ("available" if ghidra_available(a.ghidra) else "not found"))
        print("watcom  the EXE's Watcom debug info (function names), when present")
        return
    if a.list_loaders:
        print("COM  flat 16-bit image at 0100h")
        print("MZ   real-mode DOS executable")
        print("NE   16-bit segmented protected mode")
        print("LE   32-bit linear executable")
        print("LX   32-bit linear executable (partial fixup coverage)")
        return
    if not a.exe:
        ap.error("an executable is required")

    backend = a.backend
    watcom_rows = None
    if backend in ("auto", "watcom") and not a.functions:
        watcom_rows = function_rows(a.exe)
    if backend == "auto":
        backend = "csv" if a.functions else ("watcom" if watcom_rows else "native")
    if backend == "watcom" and not watcom_rows:
        sys.exit("%s: no Watcom debug info" % a.exe)
    if backend == "csv" and not a.functions:
        sys.exit("--backend csv needs --functions FILE")
    if backend == "native" and a.functions:
        sys.exit("--functions is for --backend csv/auto; use --backend native to ignore it")

    try:
        img = load_image(a.exe)
    except ImageError as e:
        sys.exit("%s: %s" % (a.exe, e))
    decoder = capstone_decoders()

    discovery_notes = list(img.notes)
    ghidra_csv = None
    if backend == "ghidra":
        if not a.ghidra and not ghidra_available():
            sys.exit("ghidra backend unavailable; set GHIDRA_INSTALL_DIR or pass --ghidra PATH")
        ghidra_csv = a.ghidra_csv or os.path.join(tempfile.mkdtemp(prefix="hlekit-ghidra-"),
                                                  "functions.csv")
        if os.path.exists(ghidra_csv) and os.path.getsize(ghidra_csv) and not a.refresh_ghidra:
            source = "cached Ghidra CSV `%s`" % report_path(ghidra_csv)
        elif a.ghidra_project:
            if not a.ghidra_project_name:
                sys.exit("--ghidra-project needs --ghidra-project-name")
            run_ghidra(a.exe, ghidra_csv, a.ghidra, a.keep_ghidra_project,
                       a.ghidra_project, a.ghidra_project_name, a.ghidra_program)
            source = "existing Ghidra project `%s`" % report_path(a.ghidra_project)
        else:
            run_ghidra(a.exe, ghidra_csv, a.ghidra, a.keep_ghidra_project)
            source = "headless Ghidra"
    elif backend == "csv":
        source = "functions CSV `%s`" % report_path(a.functions)
    elif backend == "watcom":
        source = "the executable's Watcom debug info (%d symbols)" % len(watcom_rows)

    if backend in ("ghidra", "csv"):
        csv_path = ghidra_csv or a.functions
        try:
            rows, meta = read_functions(csv_path)
        except OSError as e:
            sys.exit("cannot read functions CSV: %s" % e)
        rows = align_rows(img, rows, meta, discovery_notes)
        functions = functions_from_csv(img, decoder, rows)
    elif backend == "watcom":
        functions = functions_from_csv(img, decoder, watcom_rows)
    else:
        functions = discover_functions(img, decoder, a.max_functions)
        source = "built-in recursive traversal from the entry point, code segments and fixups"
    pointer_targets = augment_with_fixup_targets(img, decoder, functions)

    callers = collections.defaultdict(set)
    analyses = {}
    for f in functions:
        ops, ports, ints, calls = analyze_function(img, decoder, f)
        analyses[f["start"]] = (ops, ports, ints)
        for target in calls:
            owner = next((g for g in functions if g["start"] <= target < g["end"]), None)
            callers[target].add(f["name"] if owner else "FUN_%08x" % target)
    # Calls to a function start also populate the caller's name.
    stored = collections.defaultdict(list)
    for fx in img.fixups:
        if fx.target and img.code_region_at(fx.target):
            stored[fx.target].append(fx.source)

    rows = []
    for f in functions:
        ops, ports, ints = analyses[f["start"]]
        if ops or ints or f["start"] in stored:
            rows.append((f, ops, ports, ints))

    out = []
    w = out.append
    w("# Seam candidates: %s\n" % os.path.basename(img.path))
    w("Format: **%s** (%d-bit). Generated by `dos-hle-kit/tools/analysis/find_seams.py` from `%s`."
      % (img.format, img.bits, report_path(img.path)))
    w("Functions: %d from %s%s.\n" % (len(functions), source,
      (", plus %d fixup/pointer targets" % pointer_targets) if pointer_targets else ""))
    for note in discovery_notes:
        w("- %s" % note)
    if discovery_notes:
        w("")
    w("Functions that touch hardware are seams; leaf helpers (inp/outp-style) point at their")
    w("callers. Port numbers are where the code names them (`mov dx, imm` before the instruction);")
    w("a `dx` computed at run time shows as `?`. The ports identify the function to replace, not")
    w("a device to emulate: the seam body is native host behaviour.\n")

    hw = [r for r in rows if any(k in r[1] for k in ("in", "out", "ins", "outs"))]
    w("## Port I/O (%d functions)\n" % len(hw))
    w("| function | addr | size | in/out | ports | callers |")
    w("| :-- | :-- | --: | :-- | :-- | :-- |")
    for f, ops, ports, ints in hw:
        pl = ", ".join("%Xh%s" % (p, " " + KNOWN_PORTS[p] if p in KNOWN_PORTS else "")
                       for p, _ in ports.most_common(6)) or "?"
        cs = sorted(callers.get(f["start"], ()))
        w("| %s | `%08x` | %d | %s | %s | %d: %s |" % (
            f["name"], f["start"], f["size"],
            " ".join("%s×%d" % kv for kv in ops.items() if kv[0] in ("in", "out", "ins", "outs")),
            pl, len(cs), ", ".join(cs[:8]) + (" …" if len(cs) > 8 else "")))

    st = [r for r in rows if r[0]["start"] in stored]
    w("\n## Stored as pointers (%d functions: callbacks, handler candidates)\n" % len(st))
    w("A function whose address is written into data is entered indirectly — interrupt handlers")
    w("(`_dos_setvect`, int 21h/25h, int 31h/0205h), driver tables, C++ vtables, qsort callbacks.\n")
    w("| function | addr | stored by | port I/O | cli/sti |")
    w("| :-- | :-- | :-- | :-- | :-- |")
    for f, ops, ports, ints in st:
        w("| %s | `%08x` | %s | %s | %s |" % (
            f["name"], f["start"], ", ".join("%08x" % x for x in sorted(set(stored[f["start"]]))[:4]),
            "yes" if any(k in ops for k in ("in", "out")) else "",
            "yes" if ("cli" in ops or "sti" in ops) else ""))

    si = [r for r in rows if r[3]]
    w("\n## Software interrupts (%d functions)\n" % len(si))
    w("int 21h/31h/10h are the extender's services the kit answers; anything else needs a look.\n")
    w("| function | addr | ints | callers |")
    w("| :-- | :-- | :-- | --: |")
    for f, ops, ports, ints in si:
        w("| %s | `%08x` | %s | %d |" % (
            f["name"], f["start"], " ".join("%s×%d" % kv for kv in ints.items()),
            len(callers.get(f["start"], ()))))

    text = "\n".join(out) + "\n"
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        open(a.out, "w").write(text)
        print("%s: %d functions, %d port-I/O functions, %d stored pointers, %d with software ints"
              % (a.out, len(functions), len(hw), len(st), len(si)))
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
