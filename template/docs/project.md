# @TITLE@ — function-level HLE

The original `@EXE@` runs on dos-hle-kit; only the functions at the hardware seams are replaced
by native code. Use any decompiler you like for names and function boundaries; the kit does not
require a particular workspace format.

The seam table is split by area under `src/seams/` (video, input, sound, timing). `src/game.cpp`
only wires the modules together.

| | |
| :-- | :-- |
| Game directory | Not compiled in: found at startup by `--game DIR` (or an EXE path), `$HLEKIT_GAME_DIR`, the remembered directory, or next to the program (never written: writes go to the overlay) |
| Function labels | `@FUNCTIONSCSV_DOC@` (optional CSV: address,name,size) |
| Seam candidates | [seam-candidates.md](seam-candidates.md) (generated from the executable) |
| Ranked candidates | [ranked-seams.md](ranked-seams.md) (heuristic video/sound/timing/input ranking) |
| Seam modules | `src/seams/` (by area) |
| Decompiled code | `src/decompiled/` (grows over time) |

## Layout

```text
src/
  game.cpp        GameInfo and module wiring only
  seams/          seam modules by area + All(), which concatenates them
  decompiled/     translated game code, by subsystem (grows over time)
```

The seam table is a plain `std::vector<Seam>`: add new source files to `meson.build` and
concatenate their vectors in `seams::All()`. Start with HLE seams, split them by area, then
translate game code under `src/decompiled/`, calling the original through
`Machine::CallGuest`/`CallGuestFar` while a module is incomplete. A full decomp keeps the seam
boundary and the original executable as the reference/fallback.

## Run

```bash
meson setup build && ninja -C build
build/@NAME@-hle                                   # window + sound
build/@NAME@-hle --seams                           # the seam table, all modules
build/@NAME@-hle --headless --overlay /tmp/ov --seconds 10 --png shot.png   # scripted, hermetic
```
