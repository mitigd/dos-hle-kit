# Decompiled code

This directory is for native replacements that are **game logic**, not hardware seams. A port
can grow here without changing the seam boundary:

- `video/`, `sound/`, `input/` — decompiled subsystems
- `game/` — simulation, rendering, menus
- `lib/` — recovered helper libraries (allocators, file formats, math)

Each module is ordinary C++. Call back into the original binary with
`Machine::CallGuest`, `CallGuestCdecl` or `CallGuestFar` while the transition is incomplete.
A function that the guest must call is exposed with `Machine::NativeFunction`.
