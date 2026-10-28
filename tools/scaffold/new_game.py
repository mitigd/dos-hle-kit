#!/usr/bin/env python3
"""Create a game project on dos-hle-kit.

    python3 tools/scaffold/new_game.py NAME GAME.EXE [--backend native|csv|ghidra] [--functions CSV]
                              [--ghidra PATH] [--title T] [--dest DIR]

NAME       short name (cdogs -> project cdogs-hle, binary cdogs-hle)
GAME.EXE   the game's DOS executable (COM, MZ, NE, LE or LX; never written)
--backend    function discovery: native (built-in), csv, or ghidra (default: auto)
--functions  optional CSV from your decompiler: address,name[,size] (hex addresses)
--ghidra     Ghidra install directory or analyzeHeadless path (for --backend ghidra)

Copies template/ (seam modules under src/seams/, room for decompiled code under
src/decompiled/), links subprojects/dos-hle-kit to this kit, and writes
docs/seam-candidates.md with tools/analysis/find_seams.py and docs/ranked-seams.md with
tools/analysis/rank_seams.py. No external decompiler workspace is required.
"""
import argparse
import datetime
import os
import subprocess
import sys

KIT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("name")
    ap.add_argument("exe")
    ap.add_argument("--backend", choices=("auto", "native", "csv", "ghidra"), default="auto")
    ap.add_argument("--functions", help="CSV from any decompiler: address,name[,size]")
    ap.add_argument("--ghidra", help="Ghidra install dir or analyzeHeadless path")
    ap.add_argument("--keep-ghidra-project", action="store_true")
    ap.add_argument("--title")
    ap.add_argument("--dest", help="default: next to the kit, NAME-hle")
    a = ap.parse_args()
    exe = os.path.abspath(a.exe)
    dest = os.path.abspath(a.dest or os.path.join(os.path.dirname(KIT), a.name + "-hle"))
    if os.path.exists(dest):
        sys.exit("%s exists" % dest)
    backend = a.backend
    if backend == "auto":
        backend = "csv" if a.functions else "native"
    if backend == "csv" and not a.functions:
        sys.exit("--backend csv needs --functions FILE")
    if backend == "ghidra" and a.functions:
        sys.exit("--backend ghidra writes its own CSV; use --backend csv to import one")
    functions = os.path.abspath(a.functions) if a.functions else ""
    if backend == "csv" and not os.path.isfile(functions):
        sys.exit("functions CSV not found: %s" % functions)
    functions_for_code = functions
    if backend == "ghidra":
        functions = os.path.join(dest, "docs", "functions.csv")
        functions_for_code = "docs/functions.csv"
    subst = {"@NAME@": a.name, "@TITLE@": a.title or a.name, "@EXE@": os.path.basename(exe),
             "@EXENAME@": os.path.basename(exe).lower(), "@GAMEDIR@": os.path.dirname(exe),
             "@FUNCTIONSCSV@": functions_for_code, "@FUNCTIONSCSV_DOC@": functions_for_code or "(none)",
             "@DATE@": datetime.date.today().isoformat()}
    for root, _, files in os.walk(os.path.join(KIT, "template")):
        for f in files:
            src = os.path.join(root, f)
            rel = os.path.relpath(src, os.path.join(KIT, "template"))
            out = os.path.join(dest, ".gitignore" if rel == "gitignore" else rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            text = open(src).read()
            for k, v in subst.items():
                text = text.replace(k, v)
            open(out, "w").write(text)
    os.makedirs(os.path.join(dest, "subprojects"), exist_ok=True)
    os.symlink(KIT, os.path.join(dest, "subprojects", "dos-hle-kit"))
    cmd = [sys.executable, "-I", os.path.join(KIT, "tools", "analysis", "find_seams.py"), exe,
           "--backend", backend,
           "--out", os.path.join(dest, "docs", "seam-candidates.md")]
    if backend == "ghidra":
        cmd += ["--ghidra-csv", functions]
        if a.ghidra:
            cmd += ["--ghidra", a.ghidra]
        if a.keep_ghidra_project:
            cmd += ["--keep-ghidra-project"]
    elif backend == "csv":
        cmd += ["--functions", functions]
    subprocess.run(cmd, check=False)

    rank_cmd = [sys.executable, "-I", os.path.join(KIT, "tools", "analysis", "rank_seams.py"), exe,
                "--out", os.path.join(dest, "docs", "ranked-seams.md")]
    if backend in ("ghidra", "csv"):
        rank_cmd += ["--functions", functions]
    subprocess.run(rank_cmd, check=False)

    print("created %s\n  cd %s && meson setup build && ninja -C build && build/%s-hle --headless --seconds 10"
          % (dest, dest, a.name))


if __name__ == "__main__":
    main()
