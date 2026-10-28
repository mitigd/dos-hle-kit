#!/usr/bin/env python3
"""Run Ghidra headless and export a function CSV for find_seams.py.

    python3 tools/ghidra/ghidra_export.py GAME.EXE -o functions.csv
    python3 tools/ghidra/ghidra_export.py --existing-project DIR --project-name NAME --program EXE -o functions.csv

Ghidra is optional. The script looks for analyzeHeadless in $GHIDRA_INSTALL_DIR,
$GHIDRA_HOME, /usr/libexec/ghidra, /opt/ghidra, then /usr/share/ghidra. Override with
--ghidra PATH (the installation directory or the analyzeHeadless executable).

The exported CSV is plain `address,name,size,is_thunk` with comment lines for the image base and
entry point. Any decompiler that emits `address,name[,size]` can be used instead; see
find_seams.py --backend csv.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile


def find_analyze_headless(explicit=None):
    candidates = []
    if explicit:
        if os.path.isdir(explicit):
            candidates.append(os.path.join(explicit, "support", "analyzeHeadless"))
        else:
            candidates.append(explicit)
    for var in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        root = os.environ.get(var)
        if root:
            candidates.append(os.path.join(root, "support", "analyzeHeadless"))
    candidates += [
        "/usr/libexec/ghidra/support/analyzeHeadless",
        "/opt/ghidra/support/analyzeHeadless",
        "/usr/share/ghidra/support/analyzeHeadless",
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)
    discovered = shutil.which("analyzeHeadless")
    return discovered


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("exe", nargs="?")
    ap.add_argument("-o", "--out", help="output CSV (default: GAME.functions.csv)")
    ap.add_argument("--ghidra", help="Ghidra install directory or analyzeHeadless path")
    ap.add_argument("--project-dir", help="temporary Ghidra project directory")
    ap.add_argument("--existing-project", help="open this existing Ghidra project instead of importing")
    ap.add_argument("--program", help="program name in an existing project (default: /GAME.EXE)")
    ap.add_argument("--project-name", help="Ghidra project name")
    ap.add_argument("--keep-project", action="store_true", help="do not delete the project")
    ap.add_argument("--no-fixup-functions", action="store_true",
                    help="skip CreateFunctionsFromFixups.java (LE/LX targets)")
    ap.add_argument("--timeout", type=int, default=1800, help="headless timeout in seconds")
    ap.add_argument("--verbose", action="store_true", help="stream Ghidra output")
    a = ap.parse_args()

    headless = find_analyze_headless(a.ghidra)
    if not headless:
        sys.exit("analyzeHeadless not found; set GHIDRA_INSTALL_DIR or pass --ghidra PATH")

    exe = os.path.abspath(a.exe) if a.exe else None
    if not exe and not a.out:
        sys.exit("give GAME.EXE or --out when using --existing-project")
    out = os.path.abspath(a.out or (os.path.splitext(exe)[0] + ".functions.csv"))
    script_path = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)

    if a.existing_project:
        project_dir = os.path.abspath(a.existing_project)
        if not os.path.isdir(project_dir):
            sys.exit("existing Ghidra project not found: %s" % project_dir)
        project_name = a.project_name
        if not project_name:
            sys.exit("--existing-project needs --project-name")
        program = a.program or (os.path.basename(exe) if exe else "")
        if not program:
            sys.exit("--existing-project needs --program")
        cmd = [headless, project_dir, project_name, "-process", program, "-noanalysis",
               "-scriptPath", script_path, "-postScript", "ExportFunctions.java", out]
    else:
        if not exe:
            sys.exit("GAME.EXE is required when importing")
        auto_project = not a.project_dir
        project_dir = os.path.abspath(a.project_dir) if a.project_dir else tempfile.mkdtemp(prefix="hlekit-ghidra-")
        project_name = a.project_name or ("hlekit-" + os.path.basename(exe).replace(".", "_"))
        cmd = [headless, project_dir, project_name, "-import", exe,
               "-scriptPath", script_path]
        if not a.no_fixup_functions:
            cmd += ["-preScript", "CreateFunctionsFromFixups.java"]
        cmd += ["-postScript", "ExportFunctions.java", out,
                "-analysisTimeoutPerFile", str(a.timeout)]
        if not a.keep_project:
            cmd.append("-deleteProject")

    print("ghidra: %s" % headless)
    print("ghidra: %s %s" % ("opening project" if a.existing_project else "importing",
                              a.existing_project if a.existing_project else exe))
    try:
        proc = subprocess.run(cmd, timeout=a.timeout, text=True,
                              stdout=None if a.verbose else subprocess.PIPE,
                              stderr=None if a.verbose else subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        if not a.existing_project and auto_project and not a.keep_project:
            shutil.rmtree(project_dir, ignore_errors=True)
        sys.exit("ghidra: timed out after %d seconds" % a.timeout)
    finally:
        if not a.existing_project and auto_project and not a.keep_project:
            shutil.rmtree(project_dir, ignore_errors=True)
    if proc.returncode != 0:
        if proc.stdout:
            sys.stderr.write(proc.stdout)
        sys.exit("ghidra: analyzeHeadless failed with status %d" % proc.returncode)
    if not os.path.exists(out) or os.path.getsize(out) == 0:
        if proc.stdout:
            sys.stderr.write(proc.stdout)
        sys.exit("ghidra: no functions were exported (does Ghidra have a loader for this format?)")
    print("ghidra: wrote %s" % out)


if __name__ == "__main__":
    main()
