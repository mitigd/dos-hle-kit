# tools

Analysis, scaffolding, decompilation and debugging tools for dos-hle-kit. Everything is plain
Python 3 and runs from the kit root, so paths such as `GAME.EXE` and `docs/report.md` are relative
to where you invoke it.

No tool is required to build or run the kit. A game project can be written and built without
them; they shorten the work of finding and replacing hardware seams.

## What is where

```text
tools/
  analysis/
    find_seams.py        hardware-surface report: every function that touches hardware
    rank_seams.py        the same functions ranked by replacement value, by area
    watcom_debug.py      the executable's own Watcom debug symbols and source modules
    borland_debug.py     16-bit Borland TDINFO symbols to function CSV and decomp JSON
    find_debug_exes.py   scan a directory for executables that still carry debug info
  scaffold/
    new_game.py          create a game project from template/ and generate the first reports
  decomp/
    gen_decomp.py        lay out and update a decompilation tree from debug-symbol JSON
  ghidra/
    ghidra_export.py     headless Ghidra -> functions CSV
    ExportFunctions.java, CreateFunctionsFromFixups.java   Ghidra scripts
  debug/
    gdb_run.py           run a game under gdb, print a backtrace on a stop
  lib/
    dos_image.py         internal COM/MZ/NE/LE/LX loader used by the analysis tools
```

## Requirements

- Python 3.9 or newer.
- `capstone` for `find_seams.py` and `rank_seams.py` (disassembly): `pip install capstone`.
- Ghidra for `--backend ghidra` and `ghidra_export.py`. It is optional; the other backends need
  no external tools.
- `gdb` for `gdb_run.py`.

## analysis/find_seams.py

Builds the hardware-surface report for one DOS executable: the list of functions that must become
native seams. Supports COM, MZ, NE, LE and LX images through `lib/dos_image.py`, and reports port
I/O, interrupt toggles (`cli`/`sti`), software interrupts, callers, and functions whose address
is stored in data (callbacks and interrupt handlers).

```bash
python3 tools/analysis/find_seams.py GAME.EXE --out docs/seam-candidates.md
python3 tools/analysis/find_seams.py GAME.EXE --backend csv --functions functions.csv
python3 tools/analysis/find_seams.py --list-backends
python3 tools/analysis/find_seams.py --list-loaders
```

| Option | Meaning |
| :-- | :-- |
| `--backend native\|csv\|ghidra\|watcom\|auto` | function discovery; `auto` = `csv` if `--functions`, else `watcom` if the EXE has Watcom debug info, else `native` |
| `--functions CSV` | function table from any decompiler: `address,name[,size]`, hex addresses |
| `--ghidra PATH` | Ghidra install directory or `analyzeHeadless` |
| `--ghidra-csv FILE` | where the Ghidra backend writes its function CSV |
| `--ghidra-project DIR`, `--ghidra-project-name NAME`, `--ghidra-program EXE` | reuse an existing Ghidra project instead of re-importing |
| `--keep-ghidra-project`, `--refresh-ghidra` | keep the temporary project / re-run Ghidra even when the CSV exists |
| `--out FILE` | write markdown to FILE (default: stdout) |
| `--max-functions N` | cap for automatic discovery (default 50000) |

The report is a starting point, not an emulation plan: a port hit names the function to replace,
and the seam body implements its intent with host services.

## analysis/rank_seams.py

Ranks the same function table by replacement value. It combines direct hardware evidence, software
interrupts, VGA-aperture accesses, handler hints, caller propagation, identification confidence
and call-site hotness, and prints a cross-category shortlist plus per-area tables.

```bash
python3 tools/analysis/rank_seams.py GAME.EXE --functions functions.csv --out docs/ranked-seams.md
python3 tools/analysis/rank_seams.py GAME.EXE --category video --top 15
```

| Option | Meaning |
| :-- | :-- |
| `--functions CSV` | functions CSV; without it the tool uses Watcom debug info or built-in discovery |
| `--out FILE` | write markdown to FILE (default: stdout) |
| `--top N` | rows per category (default 25) |
| `--shortlist N` | cross-category shortlist size (default 12) |
| `--category NAME` | show only one category |
| `--include-data` | include Ghidra switch/case labels in the ranking |

## analysis/watcom_debug.py

Many DOS/4GW games were linked with Watcom `debug` information and shipped that way. The block sits
at the end of the executable (master header signature `8386h`); this reads it directly, without
Watcom tools or a decompiler, and emits the symbol CSVs the rest of the kit accepts.

```bash
python3 tools/analysis/watcom_debug.py GAME.EXE                       # summary
python3 tools/analysis/watcom_debug.py GAME.EXE --functions F.csv     # code symbols
python3 tools/analysis/watcom_debug.py GAME.EXE --data D.csv          # data symbols
python3 tools/analysis/watcom_debug.py GAME.EXE --modules             # source files and code ranges
python3 tools/analysis/watcom_debug.py GAME.EXE --json F.json         # everything (for gen_decomp.py)
```

| Option | Meaning |
| :-- | :-- |
| `--functions FILE` | write code symbols as `address,name,size` |
| `--data FILE` | write data symbols as `address,name,size` |
| `--modules` | print the original source modules and their code ranges |
| `--raw` | keep mangled `W?...` names instead of demangling them |
| `--json FILE` | write modules, functions with signatures, and data as JSON |

Symbol addresses are linked addresses, so they match what a decompiler shows. Use the CSVs as
`GameInfo::functionsCsv` and as `--functions` input. Use the JSON as input to `gen_decomp.py`.

## analysis/borland_debug.py

Extracts names, module code ranges, and function addresses from the packed 48-byte Borland
TDINFO header (`FB 52`, versions 1.x–3.x) appended to a real-mode MZ executable. Uses only
Python's standard library. It does not parse TD32 or NE/LE/LX debug information.

```bash
python3 tools/analysis/borland_debug.py GAME.EXE --functions F.csv --json debug.json
python3 tools/analysis/borland_debug.py GAME.EXE --data D.csv --symbols all-symbols.csv --modules
python3 tools/analysis/find_seams.py GAME.EXE --backend csv --functions F.csv
python3 tools/decomp/gen_decomp.py --build original=debug.json --out src/decompiled
```

Function classification uses function types within module code ranges and scope entries. Locals, constants, register
variables, and typedefs are excluded. `--symbols` also preserves unclassified public names;
these may include data and linker labels, so this file is **not** a function table. Some shipped
executables have only public names and yield no confidently identified functions. Detection
alone does not imply that a usable function table can be recovered.

Addresses use the kit's MZ convention: `0x100 + segment * 16 + offset`, including its PSP prefix.
Other tools may load MZ images at a different base. Function sizes use matching scope lengths;
otherwise they extend to the next function in the same segment or the containing module range's
end. JSON records `size_source` as `scope`, `inferred`, or `unknown`; an unknown size is zero.
Function candidates outside the MZ load image and function-typed names outside known code ranges
are omitted from the function table with warnings and retained in `--symbols`. Overlay addresses
are not resolved.

The JSON also includes raw type slots and `signature_evidence` for each function: return type,
function flags, scoped parameter names/types/locations, and locals. Repeated stack/register
locations of a parameter are grouped together. This evidence is not a complete call signature:
register locations can describe optimized copies rather than register argument passing, and
missing parameter records do not prove that a function takes no arguments. By default,
`params` remains null and `convention` remains unknown, so no wrappers are generated.

After checking a function's argument layout, return instructions, and call sites, supply a
complete signature with `--signatures signatures.json`. Keys are exact symbol names, or linked
addresses such as `0x00006724` when names are ambiguous. For example:

```json
{
  "_example": {
    "convention": "cdecl16_far",
    "params": [{"type": "int far*", "words": 2}, {"type": "int", "words": 1}],
    "returns": "long",
    "return_words": 2
  }
}
```

```bash
python3 tools/analysis/borland_debug.py GAME.EXE --signatures signatures.json --json debug.json
python3 tools/decomp/gen_decomp.py --build original=debug.json --out src/decompiled
```

Supported declarations are `cdecl16_near` and `cdecl16_far`, with an explicit parameter list
(`[]` for zero parameters). Each parameter occupies one or two 16-bit stack words; two-word
values, including far pointers, become separate `aN_lo`, `aN_hi` arguments in generated C++.
These are guest words, not host pointers. `return_words` selects void (0), AX (1), or DX:AX (2).
Only integer/pointer/void return ABIs are supported; floating-point and structure returns,
variadic functions, Pascal argument order, and register calling conventions need manual work.
Static visibility remains unknown.

The generated `guest::` wrappers call `Machine::CallGuestNear16` or `CallGuestFar16`. Far wrappers
preserve the original code segment and relocate it for the selected build. Near wrappers require
the caller to be in the function's original code segment. The optional final `dataSeg` argument
sets DS and ES for the call; zero preserves them. Supply a valid relocated data segment when
calling from a task that has no meaningful DS. CPU registers and segments are restored afterward;
guest memory changes persist.

For declared 16-bit signatures, hand-written `native` bodies register with the correct near/far
return, word argument offsets, and AX/DX:AX result. An empty native block produces an explicit
compile error: 16-bit `guest::orig::`/`CallOriginal` fallback is not implemented. Write the body
before enabling that translation. Existing Watcom generation is unchanged.

## analysis/find_debug_exes.py

Scans a directory tree (or one file) for DOS executables carrying recognizable debug information:
Watcom, Microsoft CodeView, Borland Turbo Debugger, DJGPP COFF symbol tables, and LE/LX header
debug sections. Useful when deciding which build of a game is worth porting. This is format
detection; use `watcom_debug.py` or `borland_debug.py` to extract supported symbols.

```bash
python3 tools/analysis/find_debug_exes.py /path/to/games
python3 tools/analysis/find_debug_exes.py /path/to/games --csv debug_exes.csv
python3 tools/analysis/find_debug_exes.py GAME.EXE --all-files
```

| Option | Meaning |
| :-- | :-- |
| `root` | file or directory to scan (default: current directory) |
| `--all-files` | inspect every file, not just `.exe`/`.com`/`.dll`/`.ovl` |
| `--max-files N` | stop after N candidates |
| `--csv FILE` | also write matches as CSV (`path,format,version,modules,symbols,debug_bytes`) |

## scaffold/new_game.py

Creates a game project next to the kit: copies `template/`, links the kit as a Meson subproject,
and generates `docs/seam-candidates.md` and `docs/ranked-seams.md` from the executable.

```bash
python3 tools/scaffold/new_game.py mygame /path/to/GAME.EXE
python3 tools/scaffold/new_game.py mygame /path/to/GAME.EXE --functions functions.csv
python3 tools/scaffold/new_game.py mygame /path/to/GAME.EXE --backend ghidra
```

| Option | Meaning |
| :-- | :-- |
| `NAME` | short name: project `NAME-hle`, binary `NAME-hle` |
| `GAME.EXE` | COM, MZ, NE, LE or LX executable (never written) |
| `--backend native\|csv\|ghidra\|auto` | function discovery for the first reports (default: `auto`) |
| `--functions CSV` | function table from your decompiler |
| `--ghidra PATH` | Ghidra install directory or `analyzeHeadless` |
| `--keep-ghidra-project` | keep the temporary Ghidra project |
| `--title T` | project title in the generated files |
| `--dest DIR` | output directory (default: next to the kit, `NAME-hle`) |

## decomp/gen_decomp.py

Lays out (and keeps up to date) a project's `src/decompiled/` tree from Watcom symbols. Input is
one JSON file per build, written by `watcom_debug.py --json`. Several builds of one program (for
example a lo-res and a hi-res EXE) share one tree: functions are paired by mangled name, and the
build is chosen at run time.

```bash
python3 tools/analysis/watcom_debug.py LO.EXE --json lo.json
python3 tools/analysis/watcom_debug.py HI.EXE --json hi.json
python3 tools/decomp/gen_decomp.py --build lo=lo.json --build hi=hi.json \
    --out src/decompiled --namespace mygame
```

| Option | Meaning |
| :-- | :-- |
| `--build NAME=JSON` | one build; repeat for each executable (first one orders the files) |
| `--out DIR` | the tree to create or update, e.g. `src/decompiled` |
| `--namespace NAME` | C++ namespace for the generated symbols (default: `game`) |

Module `.cpp` files are merged, not overwritten: existing function blocks keep their bodies and
status (`original`/`native`), so the generator can be re-run after every change. Files under
`gen/`, `decomp.h` and `meson.build` are regenerated each run.

## ghidra/ghidra_export.py

Runs Ghidra headless and exports a function CSV for `find_seams.py` or `new_game.py`. Java scripts
live in the same directory. The CSV is `address,name,size,is_thunk`, with comment lines for the
image base and entry point; any decompiler that writes `address,name[,size]` can be used instead.

```bash
python3 tools/ghidra/ghidra_export.py GAME.EXE -o functions.csv
python3 tools/ghidra/ghidra_export.py --existing-project DIR --project-name NAME \
    --program GAME.EXE -o functions.csv
```

| Option | Meaning |
| :-- | :-- |
| `-o, --out FILE` | output CSV (default: `GAME.functions.csv`) |
| `--ghidra PATH` | Ghidra installation directory or `analyzeHeadless` |
| `--project-dir DIR`, `--project-name NAME` | temporary or named Ghidra project |
| `--existing-project DIR`, `--program EXE` | reuse an existing project instead of importing |
| `--keep-project` | keep the temporary project |
| `--no-fixup-functions` | skip `CreateFunctionsFromFixups.java` (LE/LX relocation targets) |
| `--timeout SECONDS` | headless timeout (default 1800) |
| `--verbose` | stream Ghidra output |

Ghidra is found through `GHIDRA_INSTALL_DIR`, `GHIDRA_HOME`, a common install location, or
`--ghidra`. A fresh import runs `CreateFunctionsFromFixups.java` before analysis; an existing
project that was already prepared by other scripts usually has better function boundaries.

## debug/gdb_run.py

Runs a game under gdb in batch mode and prints the stop reason, registers and
`thread apply all bt full` when it stops. KVM's kick signal (SIGUSR1) is ignored, and the game
window stays interactive so the crash can be reproduced normally.

```bash
python3 tools/debug/gdb_run.py --exe build/mygame-hle -- --overlay /tmp/mygame-gdb
python3 tools/debug/gdb_run.py --exe build/mygame-hle -- --game /path/to/game
```

| Option | Meaning |
| :-- | :-- |
| `--exe PATH` | game executable (default: `build/carpet-hle`) |
| `--gdb PATH` | gdb executable (default: `gdb`) |
| `-- ARGS...` | everything after `--` is passed to the game |

## lib/dos_image.py

Shared loader for COM, MZ, NE, LE and LX executables. It is a library, not a command-line tool; it
returns the image's code and data regions at linked addresses so disassembly matches a
decompiler's addresses. `find_seams.py`, `rank_seams.py` and `watcom_debug.py` import it, adding
`tools/lib/` to `sys.path` themselves. External Python code can do the same:

```python
import sys
sys.path.insert(0, "tools/lib")
from dos_image import load_image

img = load_image("GAME.EXE")
print(img.format, img.bits, len(img.code_regions))
```

## Typical flow

```bash
# 1. which executable to work on, and does it carry symbols?
python3 tools/analysis/find_debug_exes.py /path/to/games
python3 tools/analysis/watcom_debug.py GAME.EXE --functions functions.csv

# 2. what touches hardware, and what is worth replacing first?
python3 tools/analysis/find_seams.py GAME.EXE --functions functions.csv --out docs/seam-candidates.md
python3 tools/analysis/rank_seams.py GAME.EXE --functions functions.csv --out docs/ranked-seams.md

# 3. create the project and start replacing seams
python3 tools/scaffold/new_game.py mygame GAME.EXE --functions functions.csv

# 4. when a run disagrees with the original, get a backtrace
python3 tools/debug/gdb_run.py --exe build/mygame-hle -- --headless --seconds 10
```
