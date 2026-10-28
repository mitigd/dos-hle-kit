# dos-hle-kit

**A framework for function-level HLE (high-level emulation) of 32-bit DOS games.**

Run the original executable and replace only the functions that touch hardware — video, sound,
input, timing, and the DOS extender — with native code. Game logic, renderers, mixers and data
stay in the original binary. The CPU still executes the original instructions; the kit provides
the OS services, the memory map, the hardware seams and the host frontend around it.

The central rule is simple: **hardware is never emulated**. A function that programs a VGA
register, the PIT, the joystick or a sound card becomes a native *seam*. Any port access that
still reaches the CPU is reported as an unseamed function instead of being silently faked.

## What the kit gives you

| Area | Provided |
| :-- | :-- |
| CPU | KVM on Linux; portable AsmJit JIT; one `Vcpu` interface for both |
| Loaders | runtime: LE (DOS/4GW), NE (Phar Lap 286), AHLEIMG; analysis: COM, MZ, NE, LE, LX |
| DOS services | `int 21h`, `int 31h` (DPMI), `int 10h`, PSP, environment, overlay files, real-mode calls |
| Guest control | registers, guest memory, segment/descriptor helpers, guest function calls |
| Hardware seams | native replacement functions with the original call/return convention |
| Interrupts | native ISR bodies as posted tasks, host timers with PIC-like coalescing |
| Host I/O | SDL2 window and input, audio queue, General MIDI via FluidSynth, WAV/PNG capture |
| Diagnostics | unseamed-hardware reports, tracing, watchpoints, memory dumps, headless runs |

The kit is a static library. A game project supplies one `GameInfo` with its seam table and
native handlers; it does not fork the CPU, loader or frontend.

## Requirements

- Linux for the KVM backend (`/dev/kvm` must be available) — the current default
- A C++20 compiler and C11 compiler
- Meson and Ninja
- SDL2 and zlib
- Optional: FluidSynth for music seams
- Optional: Python 3 and Capstone for the seam-discovery tooling
- Optional: Ghidra for the `ghidra` discovery backend
- Optional: a functions CSV from any decompiler (`address,name[,size]`) for labels

The x86 decoder (Zydis) and code emitter (AsmJit) used by the JIT are vendored under
`third_party/`; they are built automatically.

On Debian/Ubuntu, the usual packages are:

```bash
sudo apt install build-essential meson ninja-build libsdl2-dev zlib1g-dev libfluidsynth-dev
```

## Build the kit

```bash
meson setup build
ninja -C build
```

This builds `build/libhlekit.a` and the vendored CPU dependencies. The kit has no executable of
its own: a game project links against it.

## Start a game project

The scaffold copies `template/`, links the kit as a Meson subproject, and generates a
seam-candidate report directly from the executable:

```bash
python3 tools/scaffold/new_game.py mygame /path/to/GAME.EXE
cd ../mygame-hle
meson setup build
ninja -C build

build/mygame-hle --headless --overlay /tmp/ov --seconds 10
```

If you already have a function list from your decompiler, pass it in:

```bash
python3 tools/scaffold/new_game.py mygame /path/to/GAME.EXE --functions my_functions.csv
```

Read the `[hw] unseamed hardware access` lines from the run, then turn each reported function
into a seam in `src/game.cpp`. Repeat until the report is empty on the paths you care about.

### Analysis backends

The analysis tools carry their own loaders for the DOS executable formats (`tools/lib/dos_image.py`)
and use Capstone for disassembly. Function discovery is pluggable:

| Backend | What it does |
| :-- | :-- |
| `native` | recursive traversal from the entry point, code segment starts and internal fixups; no external tools |
| `csv` | reads `address,name[,size]` from any decompiler |
| `ghidra` | runs Ghidra headless and exports its function list, then analyzes the hardware surface |
| `watcom` | the executable's own Watcom debug info: the developers' function names |
| `auto` | `csv` when `--functions` is given, else `watcom` when the EXE carries Watcom debug info, otherwise `native` |

### Watcom debug info

Many DOS/4GW games were linked with Watcom debug info and shipped that way: the block sits at the
end of the EXE (master header signature `8386h`). It names every global function and variable and
lists the source modules with their code ranges. Check for it first; it is worth more than any
decompiler's guesses:

```bash
python3 tools/analysis/watcom_debug.py GAME.EXE                          # present? how many symbols
python3 tools/analysis/watcom_debug.py GAME.EXE --functions docs/symbols.csv --data docs/data_symbols.csv
python3 tools/analysis/watcom_debug.py GAME.EXE --modules                # source files and code ranges
```

The CSVs are linked (decompiler) addresses and work as `GameInfo::functionsCsv` labels and as
`--functions` input everywhere; `find_seams.py` and `rank_seams.py` use the debug info by
themselves when no CSV is given.

```bash
pip install capstone
python3 tools/analysis/find_seams.py --list-backends
python3 tools/analysis/find_seams.py --list-loaders
python3 tools/analysis/find_seams.py /path/to/GAME.EXE --out docs/seam-candidates.md
python3 tools/analysis/find_seams.py /path/to/GAME.EXE --backend ghidra --ghidra-csv docs/functions.csv
python3 tools/analysis/find_seams.py /path/to/GAME.EXE --backend csv --functions my_functions.csv
python3 tools/analysis/rank_seams.py /path/to/GAME.EXE --functions docs/functions.csv --out docs/ranked-seams.md
```

`rank_seams.py` ranks the same function table by **replacement value**: direct hardware
evidence combined with identification confidence and call-site hotness. A hot, well-identified
seam is worth more than a one-off init helper; large loop-like functions are marked `Depends`.
The report has priority (`Very high`/`High`/`Medium`/`Low`/`Depends`), confidence, value, and a
cross-category shortlist (`--shortlist N`) so five strategic replacements are not buried under
fifty arbitrary ones.

It is still a discovery aid: the port evidence finds the function to replace, not a device to
emulate. The native body uses host services (audio queue, frames/palette, host clock, host
input). The scaffold writes:

```text
docs/seam-candidates.md   every hardware-touching function
docs/ranked-seams.md      replacement shortlist + per-area ranked tables
```

For an existing analysis, reuse its Ghidra project instead of re-importing:

```bash
python3 tools/analysis/find_seams.py /path/to/GAME.EXE --backend ghidra \
  --ghidra-project ~/RE/game/ghidra_project --ghidra-project-name Game \
  --ghidra-program GAME.EXE --ghidra-csv docs/functions.csv
```

A fresh import runs `CreateFunctionsFromFixups.java` before analysis, which creates functions at
LE/LX relocation targets. An existing project that was already prepared by other Ghidra scripts
(such as a decompiler pipeline) will usually have better function boundaries; the CSV backend
accepts that project's exported `functions.csv` just as well.

The Ghidra backend uses `GHIDRA_INSTALL_DIR`/`GHIDRA_HOME`, a common install location, or
`--ghidra PATH`. The scaffold can run it for you:

```bash
python3 tools/scaffold/new_game.py mygame /path/to/GAME.EXE --backend ghidra
```

That writes `docs/functions.csv` into the new project and points `GameInfo::functionsCsv` at it.
The Ghidra export is optional: without it, the native backend still finds hardware seams, and
the project can be given a CSV from any other decompiler later.

| Format | Loader | Typical use |
| :-- | :-- | :-- |
| `COM` | flat 16-bit image at 0100h | small real-mode utilities |
| `MZ` | DOS real-mode executable | setup programs, extenders, older games |
| `NE` | 16-bit segmented protected mode | Phar Lap 286, OS/2 1.x programs |
| `LE` | 32-bit linear executable | DOS/4GW, DOS/4G, PMODE/W, CauseWay games |
| `LX` | 32-bit linear executable | parsed with the LE reader; 32-bit fixup coverage is partial |

The report lists every function with port I/O, `cli`/`sti`, software interrupts, callers, and
functions whose address is stored in data (callbacks and interrupt handlers). The tool only
reads the executable; Ghidra projects are temporary unless `--keep-ghidra-project` is used.

Runtime loader support is a separate question: `Machine::Load` runs **LE**, **NE**, real-mode **MZ**
and **COM** images (plus the kit's AHLEIMG dump format). Real-mode programs get no DOS and no BIOS:
every interrupt a game would make is a function you replace with a seam (see `gr-hle`), and native
code can call game functions back with `Machine::CallGuestNear16`. They run on `kvm` and on the
portable `jit` (`--cpu jit`); `tools/test/vcpu_diff` checks the JIT against KVM.

## Using the kit directly

A minimal game project is a `main()` that describes the game and hands control to the runner:

```cpp
#include "hlekit/machine.h"
#include "hlekit/seam.h"

using namespace hlekit;

int main(int argc, char** argv) {
    GameInfo g;
    g.title = "My Game";
    g.exeName = "GAME.EXE";
    g.gameDir = "/path/to/game";      // read-only; writes go to the overlay
    g.functionsCsv = "/path/to/functions.csv";  // optional: address,name,size
    g.seams = {
        // {addr, "name", "video", "decomp evidence", [](Machine& m) { ... }},
    };
    g.onKey = [](Machine& m, uint8_t scan, bool down, bool extended) { /* native ISR body */ };
    return Main(argc, argv, g);
}
```

`meson.build` for such a project (the template lists every module explicitly):

```meson
project('mygame-hle', 'cpp', default_options : ['cpp_std=c++20'])
hlekit = subproject('dos-hle-kit').get_variable('hlekit_dep')
project_inc = include_directories('src')

game_src = files(
  'src/game.cpp',
  'src/seams/seams.cpp',
  'src/seams/video.cpp',
  'src/seams/input.cpp',
  'src/seams/sound.cpp',
  'src/seams/timing.cpp',
)
executable('mygame-hle', game_src,
  include_directories : project_inc, dependencies : [hlekit])
```

Place the kit at `subprojects/dos-hle-kit` (a symlink is fine). The template under `template/`
is the recommended starting point.

## From HLE to a full decomp

The kit is not HLE-only. A seam table is just a `std::vector<Seam>`, so it can be split across
as many files and directories as the port needs. The template starts that way:

```text
src/game.cpp                 GameInfo and module wiring only
src/seams/seams.cpp          All(): concatenates the area modules
src/seams/video.cpp          palette, modes, planar/VESA helpers, frame composition
src/seams/input.cpp          keyboard/mouse/pad handler bodies
src/seams/sound.cpp          start/stop, mixer, music driver entry points
src/seams/timing.cpp         PIT, retrace waits, timer ISR bodies
src/decompiled/              translated game code, by subsystem (grows over time)
```

The progression is:

1. HLE seams for every hardware-touching function.
2. Split them by area under `src/seams/`.
3. Translate game code under `src/decompiled/`; call the original through
   `Machine::CallGuest`/`CallGuestFar` while a module is incomplete.
4. Replace guest functions one at a time; expose guest-callable replacements with
   `Machine::NativeFunction`.
5. A full decomp keeps the seam boundary and the original executable as the reference/fallback.

Nothing in the build or runtime assumes one seam file: add modules to `meson.build` and
concatenate them in `seams::All()`. See
[template/docs/project.md](template/docs/project.md) for the layout and rules.

## The seam API

`src/game.cpp` only needs `hlekit/machine.h` and `hlekit/seam.h`. The most used entry points:

| API | Purpose |
| :-- | :-- |
| `vm.Get/Set(Reg)`, `vm.Rd*/Wr*` | guest registers and memory; guest address == linked/decomp address |
| `CallGuest(fn, {args})` | run a guest function from a seam and return its EAX |
| `CallGuestCdecl(fn, {args})` | the same for cdecl / Watcom `-3s` stack arguments |
| `CallGuestFar(sel, off, iretFrame)` | far call, optionally with an interrupt frame |
| `CallGuestFar16(...)` | NE far function with word arguments |
| `Post(task)` | run a native ISR body where the guest has `IF=1` |
| `SetTimer(hz, task)` | periodic IRQ 0 replacement with coalescing |
| `WaitUntil(t)` | replace a busy-wait without blocking interrupt tasks |
| `StartSound(...)`, `QueueAudio(...)` | host audio; queue level acts as the DMA clock |
| `NativeFunction(seam)` | make a native function callable from the guest |
| `PresentFrame(...)`, `ClearFrame()` | show a seam-composed frame instead of the A0000h window |
| `TakeSnapshot/RestoreSnapshot` | rollback guest memory around speculative work |
| `palette`, `videoMode`, `frames` | palette, display mode and frame counter |
| `HookedVector(v)` | the protected-mode handler the game installed |

A seam is `{address, name, area, doc, function, pop, ret}`. It replaces the function entry with
a trap byte; the runner executes the native body and performs the original return (`ret` or
`ret N`). Put the decomp and disassembly evidence in `doc` — it is the reason the seam is
faithful, and it is printed by `--seams`.

## Runner options

```text
build/mygame-hle [EXE|IMAGE] [options]

--game DIR              game data directory
--overlay DIR           writable overlay (default: ./overlay)
--functions CSV         function labels: address,name[,size] (hex addresses)
--decomp CSV            alias for --functions
--seams                 print the seam table and exit
--no-seam NAME|AREA     disable one seam or an entire area
--headless              no window or audio device
--seconds N             run for N seconds (headless)
--png FILE              write the last displayed frame
--wav FILE              write mixed audio
--keys SPEC             scripted input, e.g. "1.5:enter,3:down+2.5"
--mute                  run without audio output
--cpu NAME              kvm, jit, whpx (if built) — or set HLEKIT_CPU
--list-cpus             list the backends this build can create
--args "..."            guest command line
--soundfont FILE        General MIDI SoundFont for music seams
--log-services          log DOS/DPMI service calls
--dump-image FILE       dump the loaded guest image and exit
```

## Music and SoundFonts

**No SoundFont is bundled, embedded or hardcoded by the kit.** Music output is optional and is
resolved at runtime, in this order:

1. the path passed to `--soundfont FILE`;
2. `GameInfo::soundFont`, if a game project deliberately sets one;
3. the `HLEKIT_SOUNDFONT` environment variable;
4. the `SOUNDFONT` environment variable.

If none is set, or if the build has no FluidSynth, the runner prints a note and runs without
MIDI music. The rest of the game is unaffected.

`GameInfo::soundFont` is empty by default. Game projects should normally leave it empty and let
the player supply a SoundFont, rather than committing a machine-specific path. SoundFonts have
their own licenses: do not redistribute a `.sf2` file unless its license allows it.

## CPU backends

The CPU is a backend behind `include/hlekit/vcpu.h`; seams, loaders and services never see
which engine is running.

| Backend | Host | State |
| :-- | :-- | :-- |
| `kvm` | Linux | default; hardware-virtualised; recommended |
| `jit` | Linux, any x86-64 host | experimental portable engine; no debugger support yet; runs 32-bit and real-mode (MZ/COM) guests |
| `whpx` | Windows 10+ | planned |

```bash
build/mygame-hle --list-cpus
build/mygame-hle --cpu jit --headless --seconds 10
```

See the CPU backend notes in `include/hlekit/vcpu.h` for the register/exit contract.

## Diagnostics

| Variable | Effect |
| :-- | :-- |
| `HLEKIT_CPU` | default backend name |
| `HLEKIT_TRACE=addr[,steps]` | execute breakpoint; keep a ring of subsequent steps |
| `HLEKIT_WATCH=addr[,limit]` | stop on a write to a guest dword (optionally above a limit) |
| `HLEKIT_WATCH_AFTER=seconds` | ignore watchpoint hits before this time |
| `HLEKIT_DUMP_ON_FAULT=file` | dump guest memory at a fault stop |
| `HLEKIT_LOG_READS=1` | log service reads |
| `HLEKIT_PROFILE=1` | profile counters |
| `HLEKIT_JIT_LOG=1|2` | JIT compiler chatter |
| `HLEKIT_JIT_EIPLOG=1` | ring of recently executed block entries |
| `HLEKIT_JIT_MAXBLOCK=N` | cap JIT block size |
| `HLEKIT_JIT_NOCHAIN=1` | disable JIT block chaining |
| `HLEKIT_JIT_EAGER_FLAGS=1` | re-seed host flags at every instruction |

## Repository layout

```text
include/hlekit/   public API: seam.h, machine.h, vm.h, vcpu.h, dos.h, le.h, ne.h,
                  phar286.h, audio.h, midi.h
src/              machine, Vm, DOS/DPMI services, LE/NE loaders, audio/MIDI, frontend
src/jit/          portable x86-64 JIT compiler and translation cache
third_party/      vendored Zydis and AsmJit (with their licenses)
tools/            analysis/ (seam discovery and ranking, Watcom debug info), scaffold/
                  (new_game.py), decomp/ (gen_decomp.py), ghidra/ (export + Java scripts),
                  debug/ (gdb_run.py), lib/ (DOS image loader); see tools/README.md
template/         game-project skeleton copied by new_game.py (src/seams/, src/decompiled/)
```

## Documentation

- [tools/README.md](tools/README.md) — every tool in `tools/`, with usage and options
- [template/docs/project.md](template/docs/project.md) — what a generated game project looks like

## Licensing

dos-hle-kit is released under the MIT License; see [LICENSE](LICENSE).

The vendored components keep their upstream licenses:

- Zydis / Zycore — MIT (see `third_party/zydis/LICENSE`)
- AsmJit — zlib (see `third_party/asmjit/LICENSE.md`)
