// What a game project provides to the kit: its seam table and a few defaults.
//
// A seam replaces one guest function. Its entry byte becomes `hlt`; when the guest calls it, the
// host runs `fn` instead of the original body and then performs the function's own return
// (`ret`, or `ret pop` for stack arguments). __watcall: arguments in EAX, EDX, EBX, ECX, the rest
// on the stack, result in EAX.
//
// The rule: hardware is never emulated. Every function that touches hardware
// is a seam; a port access that still happens is reported as an unseamed function and reads 0.
#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace hlekit {

class Machine;

struct Seam {
    uint32_t addr;
    const char* name;
    const char* area;          // video | sound | input | timing | diagnostics | ...
    const char* doc;           // the decomp evidence: what the original does, why this is faithful
    std::function<void(Machine&)> fn;
    uint32_t pop = 0;          // bytes of stack arguments the original `ret N` pops
                               // (Ret::Resume: the length of the replaced instruction)
    // Segmented (NE) programs: `seg` = segment number as in the linker map (1-based) and `addr`
    // the offset in it; the original returns with `retf N` (Far16) or `ret N` (Near16).
    // Resume: an *instruction* seam. `addr` is a software interrupt (or other instruction) inside a
    // function, e.g. an inline `int 33h`; the body is its native result and the guest continues at
    // addr + pop.
    enum class Ret : uint8_t { Near32, Far16, Near16, Resume };
    uint16_t seg = 0;
    Ret ret = Ret::Near32;
};

// A seam table is a plain list: compose it from any number of modules/files.
using SeamList = std::vector<Seam>;

// A game controller (SDL's standard layout): sticks -1..1 (y down positive), triggers 0..1,
// `buttons` bit n = SDL_GameControllerButton n (A, B, X, Y, Back, Guide, Start, LS, RS, LB, RB,
// D-pad up, down, left, right, ...).
struct PadState {
    float lx = 0, ly = 0, rx = 0, ry = 0, lt = 0, rt = 0;
    uint32_t buttons = 0;
    bool connected = false;
};

struct GameInfo {
    std::string title;                         // window title
    std::string exeName;                       // e.g. "across.exe": default EXE, argv[0] (C:\NAME)
    std::string gameDir;                       // default data directory (the EXE's)
    std::string fallbackGameDir;               // optional read-only CD/source asset directory
    std::vector<std::string> dosDirAliases;   // guest directory prefixes mapped to gameDir
    std::string commandLine;                   // default guest arguments (--args replaces them)
    std::string functionsCsv;                  // optional CSV (addr,name,size) for function labels
    std::string mapFile;                       // NE: a Borland/Microsoft linker map (seg:off publics), for labels
    // The seam table. A plain vector: compose it from as many modules/directories as the
    // project needs. The kit does not require one table, file or translation unit.
    SeamList seams;
    // A host key event, XT set-1 make code; `extended` = the key sends an E0h prefix (grey
    // arrows, Insert/Delete/Home/End/PgUp/PgDn, right Ctrl/Alt, keypad Enter and /). Runs at an
    // interruptible point (guest IF=1), where the game's keyboard IRQ could have arrived: the
    // native body of its keyboard ISR goes here.
    std::function<void(Machine&, uint8_t xtScan, bool down, bool extended)> onKey;
    // A host mouse event: position in the shown picture's pixels (clamped to it), buttons bit 0
    // left, bit 1 right, bit 2 middle. Delivered like onKey; the native body of the game's mouse
    // input functions goes here. With onMouse set, the window hides the host cursor.
    std::function<void(Machine&, int x, int y, uint8_t buttons)> onMouse;
    // Relative mouse motion in shown-picture pixels: dx/dy since the previous event. This is the
    // one to use for a mouse-look game: the window enters relative mode while captured, so the
    // pointer keeps turning instead of stopping at the window edge. Click to capture; Ctrl+G or
    // losing focus releases. If both are set, onMouseDelta wins.
    std::function<void(Machine&, int dx, int dy, uint8_t buttons)> onMouseDelta;
    // The first connected game controller, whenever its state changes. Delivered like onKey.
    std::function<void(Machine&, const PadState&)> onPad;
    // Called before the executable is loaded: register native bodies for imported functions
    // (Machine::importImpls, e.g. a game-specific driver DLL) the kit does not provide.
    std::function<void(Machine&)> onImports;
    // General MIDI SoundFont for music. Empty by default: set it only if the game should carry a
    // path, otherwise the runner uses --soundfont, HLEKIT_SOUNDFONT or SOUNDFONT. The kit never
    // bundles or hardcodes a SoundFont.
    std::string soundFont;
    // Files the runner provides in place of the game's (guest-relative path -> bytes), e.g. the
    // identity of a driver that is native here. Written into the overlay at every start.
    std::map<std::string, std::vector<uint8_t>> generatedFiles;
    // Called once after loading and installing the seams, before the guest runs.
    std::function<void(Machine&)> onStart;
    // Game-specific command-line options: return true if `arg` was the game's.
    std::function<bool(const std::string& arg)> onArg;
    std::string argHelp;                       // one line per option, for --help
    // LE games: load every object at 1 MB and up (as DOS/4GW does) instead of at its linked base,
    // for games that allocate several hundred KB of conventional memory (int 31h/0100h) and need it
    // free. Seam addresses and function labels stay decompiler addresses; the kit translates them.
    bool loadHigh = false;
    int windowWidth = 960;                     // initial window width (height 720); the picture keeps its aspect
};

// The whole runner: arguments, load, seams, the vCPU thread, window/audio or headless mode.
int Main(int argc, char** argv, const GameInfo& game);

}  // namespace hlekit
