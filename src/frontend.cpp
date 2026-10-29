// The kit's frontend: arguments, load, seams, the vCPU thread, an SDL2 window with audio, or a
// headless run with scripted keys, PNG and WAV capture.
//
//   GAME [EXE|IMAGE] [--game DIR] [--overlay DIR] [--functions CSV] [--no-seam NAME|AREA]...
//        [--headless --seconds N] [--png FILE] [--keys T:KEY[+HELD],...] [--wav FILE] [--mute]
//        [--log-services] [--dump-image FILE] [--seams]
#include "hlekit/decomp.h"
#include "hlekit/machine.h"
#include "hlekit/paths.h"
#include "hlekit/phar286.h"
#include "hlekit/seam.h"
#include "host_audio.h"

#include <SDL2/SDL.h>
#include <zlib.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <sstream>
#include <thread>
#include <vector>

namespace hlekit {

namespace {

// SDL scancode -> XT set-1 make code.
uint8_t XtScan(SDL_Scancode s) {
    switch (s) {
    case SDL_SCANCODE_ESCAPE: return 0x01;
    case SDL_SCANCODE_1: case SDL_SCANCODE_2: case SDL_SCANCODE_3: case SDL_SCANCODE_4:
    case SDL_SCANCODE_5: case SDL_SCANCODE_6: case SDL_SCANCODE_7: case SDL_SCANCODE_8:
    case SDL_SCANCODE_9: return (uint8_t)(0x02 + (s - SDL_SCANCODE_1));
    case SDL_SCANCODE_0: return 0x0B;
    case SDL_SCANCODE_MINUS: return 0x0C;
    case SDL_SCANCODE_EQUALS: return 0x0D;
    case SDL_SCANCODE_BACKSPACE: return 0x0E;
    case SDL_SCANCODE_TAB: return 0x0F;
    case SDL_SCANCODE_Q: return 0x10; case SDL_SCANCODE_W: return 0x11; case SDL_SCANCODE_E: return 0x12;
    case SDL_SCANCODE_R: return 0x13; case SDL_SCANCODE_T: return 0x14; case SDL_SCANCODE_Y: return 0x15;
    case SDL_SCANCODE_U: return 0x16; case SDL_SCANCODE_I: return 0x17; case SDL_SCANCODE_O: return 0x18;
    case SDL_SCANCODE_P: return 0x19;
    case SDL_SCANCODE_LEFTBRACKET: return 0x1A; case SDL_SCANCODE_RIGHTBRACKET: return 0x1B;
    case SDL_SCANCODE_RETURN: case SDL_SCANCODE_KP_ENTER: return 0x1C;
    case SDL_SCANCODE_LCTRL: case SDL_SCANCODE_RCTRL: return 0x1D;
    case SDL_SCANCODE_A: return 0x1E; case SDL_SCANCODE_S: return 0x1F; case SDL_SCANCODE_D: return 0x20;
    case SDL_SCANCODE_F: return 0x21; case SDL_SCANCODE_G: return 0x22; case SDL_SCANCODE_H: return 0x23;
    case SDL_SCANCODE_J: return 0x24; case SDL_SCANCODE_K: return 0x25; case SDL_SCANCODE_L: return 0x26;
    case SDL_SCANCODE_SEMICOLON: return 0x27; case SDL_SCANCODE_APOSTROPHE: return 0x28;
    case SDL_SCANCODE_GRAVE: return 0x29;
    case SDL_SCANCODE_LSHIFT: return 0x2A;
    case SDL_SCANCODE_BACKSLASH: return 0x2B;
    case SDL_SCANCODE_Z: return 0x2C; case SDL_SCANCODE_X: return 0x2D; case SDL_SCANCODE_C: return 0x2E;
    case SDL_SCANCODE_V: return 0x2F; case SDL_SCANCODE_B: return 0x30; case SDL_SCANCODE_N: return 0x31;
    case SDL_SCANCODE_M: return 0x32;
    case SDL_SCANCODE_COMMA: return 0x33; case SDL_SCANCODE_PERIOD: return 0x34; case SDL_SCANCODE_SLASH: return 0x35;
    case SDL_SCANCODE_RSHIFT: return 0x36;
    case SDL_SCANCODE_KP_MULTIPLY: return 0x37;
    case SDL_SCANCODE_LALT: case SDL_SCANCODE_RALT: return 0x38;
    case SDL_SCANCODE_SPACE: return 0x39;
    case SDL_SCANCODE_CAPSLOCK: return 0x3A;
    case SDL_SCANCODE_F1: case SDL_SCANCODE_F2: case SDL_SCANCODE_F3: case SDL_SCANCODE_F4:
    case SDL_SCANCODE_F5: case SDL_SCANCODE_F6: case SDL_SCANCODE_F7: case SDL_SCANCODE_F8:
    case SDL_SCANCODE_F9: case SDL_SCANCODE_F10: return (uint8_t)(0x3B + (s - SDL_SCANCODE_F1));
    case SDL_SCANCODE_HOME: case SDL_SCANCODE_KP_7: return 0x47;
    case SDL_SCANCODE_UP: case SDL_SCANCODE_KP_8: return 0x48;
    case SDL_SCANCODE_PAGEUP: case SDL_SCANCODE_KP_9: return 0x49;
    case SDL_SCANCODE_KP_MINUS: return 0x4A;
    case SDL_SCANCODE_LEFT: case SDL_SCANCODE_KP_4: return 0x4B;
    case SDL_SCANCODE_KP_5: return 0x4C;
    case SDL_SCANCODE_RIGHT: case SDL_SCANCODE_KP_6: return 0x4D;
    case SDL_SCANCODE_KP_PLUS: return 0x4E;
    case SDL_SCANCODE_END: case SDL_SCANCODE_KP_1: return 0x4F;
    case SDL_SCANCODE_DOWN: case SDL_SCANCODE_KP_2: return 0x50;
    case SDL_SCANCODE_PAGEDOWN: case SDL_SCANCODE_KP_3: return 0x51;
    case SDL_SCANCODE_INSERT: case SDL_SCANCODE_KP_0: return 0x52;
    case SDL_SCANCODE_DELETE: case SDL_SCANCODE_KP_PERIOD: return 0x53;
    case SDL_SCANCODE_F11: return 0x57;
    case SDL_SCANCODE_F12: return 0x58;
    default: return 0;
    }
}

// Keys whose XT make code comes with an E0h prefix on a real keyboard.
bool XtExtended(SDL_Scancode s) {
    switch (s) {
    case SDL_SCANCODE_UP: case SDL_SCANCODE_DOWN: case SDL_SCANCODE_LEFT: case SDL_SCANCODE_RIGHT:
    case SDL_SCANCODE_INSERT: case SDL_SCANCODE_DELETE: case SDL_SCANCODE_HOME: case SDL_SCANCODE_END:
    case SDL_SCANCODE_PAGEUP: case SDL_SCANCODE_PAGEDOWN: case SDL_SCANCODE_RCTRL: case SDL_SCANCODE_RALT:
    case SDL_SCANCODE_KP_ENTER: case SDL_SCANCODE_KP_DIVIDE: return true;
    default: return false;
    }
}

// --keys names -> XT make codes, by way of the SDL table
SDL_Scancode ScancodeByName(const std::string& name) {
    SDL_Scancode s = SDL_GetScancodeFromName(name.c_str());
    if (s == SDL_SCANCODE_UNKNOWN && name == "enter") s = SDL_SCANCODE_RETURN;
    if (s == SDL_SCANCODE_UNKNOWN && name == "esc") s = SDL_SCANCODE_ESCAPE;
    return s;
}

// The picture to show: a frame a seam composed (any width), else the mode-13h window at A0000h.
// Returns false when `rgba` still holds exactly the picture it held last call (same seam frame,
// same palette), so the caller can skip the texture upload.
bool Frame(Machine& m, std::vector<uint32_t>& rgba, int& w, int& h, double& aspect) {
    uint8_t pal[768];
    {
        std::lock_guard<std::mutex> lock(m.paletteMutex);
        memcpy(pal, m.palette, sizeof pal);
    }
    static uint64_t lastSerial = 0;
    static uint8_t lastPal[768];
    static int lastW, lastH;
    static double lastAspect;
    const uint64_t serial = m.PresentedSerial();
    if (serial && serial == lastSerial && !memcmp(pal, lastPal, sizeof pal) && !rgba.empty()) {
        w = lastW;
        h = lastH;
        aspect = lastAspect;
        return false;
    }
    uint32_t lut[256];
    for (int i = 0; i < 256; ++i) {
        auto c = [&](int k) { uint32_t v = pal[i * 3 + k]; return (v << 2) | (v >> 4); };
        lut[i] = 0xFF000000u | c(0) << 16 | c(1) << 8 | c(2);
    }
    static Machine::HostFrame hf;
    if (m.LatestFrame(hf)) {
        w = hf.width;
        h = hf.height;
        aspect = hf.aspect;
        rgba.resize((size_t)w * h);
        for (size_t i = 0; i < rgba.size(); ++i) rgba[i] = lut[hf.pixels[i]];
        lastSerial = hf.serial;
        memcpy(lastPal, pal, sizeof pal);
        lastW = w;
        lastH = h;
        lastAspect = aspect;
        return true;
    }
    lastSerial = 0;
    w = 320;
    h = 200;
    aspect = 0;
    rgba.resize(320 * 200);
    if (m.videoMode != 0x13) { std::fill(rgba.begin(), rgba.end(), 0xFF000000u); return true; }
    const uint8_t* fb = m.vm.mem + 0xA0000;
    for (int i = 0; i < 320 * 200; ++i) rgba[i] = lut[fb[i]];
    return true;
}

// VGA 320x200 fills a 4:3 screen: pixels are 5:6 (wider than tall would be 1:1). Keep that shape
// at any frame width and letterbox into the window - unless the seam gave the frame's display
// aspect (`aspect` > 0, e.g. 4:3 for a 320x400 mode).
SDL_Rect Fit(int winW, int winH, int w, int h, double aspect) {
    if (aspect <= 0) aspect = (double)w / h * (200.0 / 320.0) * (4.0 / 3.0);
    int dw = winW, dh = (int)(winW / aspect + 0.5);
    if (dh > winH) { dh = winH; dw = (int)(winH * aspect + 0.5); }
    return SDL_Rect{(winW - dw) / 2, (winH - dh) / 2, dw, dh};
}

bool WritePng(const std::string& path, const std::vector<uint32_t>& px, int w, int h) {
    std::vector<uint8_t> raw;
    for (int y = 0; y < h; ++y) {
        raw.push_back(0);
        for (int x = 0; x < w; ++x) {
            uint32_t p = px[y * w + x];
            raw.push_back((uint8_t)(p >> 16)); raw.push_back((uint8_t)(p >> 8)); raw.push_back((uint8_t)p);
        }
    }
    uLongf zlen = compressBound(raw.size());
    std::vector<uint8_t> z(zlen);
    if (compress2(z.data(), &zlen, raw.data(), raw.size(), 6) != Z_OK) return false;
    z.resize(zlen);
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    auto be32 = [](uint32_t v) { uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v}; return std::vector<uint8_t>(b, b + 4); };
    auto chunk = [&](const char* tag, const std::vector<uint8_t>& data) {
        std::vector<uint8_t> c(tag, tag + 4);
        c.insert(c.end(), data.begin(), data.end());
        auto len = be32((uint32_t)data.size());
        auto crc = be32((uint32_t)crc32(0, c.data(), (uInt)c.size()));
        fwrite(len.data(), 1, 4, f); fwrite(c.data(), 1, c.size(), f); fwrite(crc.data(), 1, 4, f);
    };
    fwrite("\x89PNG\r\n\x1a\n", 1, 8, f);
    std::vector<uint8_t> ihdr = be32(w);
    auto hh = be32(h);
    ihdr.insert(ihdr.end(), hh.begin(), hh.end());
    ihdr.insert(ihdr.end(), {8, 2, 0, 0, 0});
    chunk("IHDR", ihdr);
    chunk("IDAT", z);
    chunk("IEND", {});
    fclose(f);
    return true;
}

// A key, or with `mouse` a pointer event at x,y (picture pixels) with `buttons`.
struct ScriptKey { double at; uint8_t scan; bool down, extended; bool mouse = false; int x = 0, y = 0; uint8_t buttons = 0; };


}  // namespace

int Main(int argc, char** argv, const GameInfo& game) {
    std::string image, png, keys, wav, dumpImage, functions = game.functionsCsv, cpuName, soundFont = game.soundFont;
    std::string configFile;
    std::map<std::string, std::string> setOptions;
    bool soundFontGiven = false;
    bool gameGiven = false, overlayGiven = false, mute = false, headless = false;
    std::vector<std::string> noSeams;
    double seconds = 0;
    Machine m;
    m.gameDir = game.gameDir;
    m.fallbackGameDir = game.fallbackGameDir;
    m.dosDirAliases = game.dosDirAliases;
    m.commandLine = game.commandLine;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
        if (a == "--game") { m.gameDir = next(); gameGiven = true; }
        else if (a == "--dump-image") dumpImage = next();
        else if (a == "--overlay") { m.overlayDir = next(); overlayGiven = true; }
        else if (a == "--config") configFile = next();
        else if (a == "--set") {
            const std::string kv = next();
            const auto eq = kv.find('=');
            if (eq == std::string::npos) { std::cerr << "--set wants key=value\n"; return 2; }
            setOptions[kv.substr(0, eq)] = kv.substr(eq + 1);
        }
        else if (a == "--functions" || a == "--decomp") functions = next();
        else if (a == "--no-seam") noSeams.push_back(next());
        else if (a == "--headless") headless = true;
        else if (a == "--seconds") seconds = std::stod(next());
        else if (a == "--png") png = next();
        else if (a == "--keys") keys = next();
        else if (a == "--log-services") m.logServices = true;
        else if (a == "--mute") mute = true;
        else if (a == "--wav") wav = next();
        else if (a == "--cpu") cpuName = next();
        else if (a == "--args") m.commandLine = next();
        else if (a == "--soundfont") { soundFont = next(); soundFontGiven = true; }
        else if (a == "--list-cpus") {
            for (const std::string& n : Vcpu::Available()) printf("%s%s\n", n.c_str(), n == Vcpu::Default() ? "  (default)" : "");
            return 0;
        }
        else if (game.onArg && game.onArg(a)) {}
        else if (a == "--help") {
            printf("%s [EXE|IMAGE] [--game DIR] [--overlay DIR] [--functions CSV] [--no-seam NAME|AREA]\n"
                   "  [--headless --seconds N] [--keys T:KEY[+HELD]|T:lmb@X/Y,...] [--png F] [--wav F] [--mute]\n"
                   "  [--cpu kvm|whpx|jit] [--list-cpus] [--log-services] [--dump-image F] [--seams]\n"
                   "  [--args \"GUEST ARGUMENTS\"] [--soundfont SF2] [--config FILE] [--set KEY=VALUE]\n%s",
                   argv[0], game.argHelp.c_str());
            return 0;
        }
        else if (a == "--seams") {
            for (const Seam& s : game.seams) printf("%08x  %-11s %-18s %s\n", s.addr, s.area, s.name, s.doc);
            for (const Seam& s : Decompiled()) printf("%08x  %-11s %-18s %s\n", s.addr, s.area, s.name, s.doc);
            return 0;
        } else if (a[0] != '-' && image.empty()) image = a;
        else { std::cerr << "unknown argument " << a << "\n"; return 2; }
    }
    if (!overlayGiven) m.overlayDir = DefaultOverlayDir(game);
    if (configFile.empty()) configFile = DefaultConfigFile(game);
    {
        // Options every kit game has, ahead of the port's own.
        std::vector<ConfigOption> options = {
            {"soundfont", "", "General MIDI SoundFont (.sf2) for music. Empty: GameInfo default, then $HLEKIT_SOUNDFONT / $SOUNDFONT.", {}},
        };
        options.insert(options.end(), game.options.begin(), game.options.end());
        m.config.Load(options, configFile, setOptions);
        if (!soundFontGiven && !m.config.Get("soundfont").empty()) soundFont = m.config.Get("soundfont");
    }
    std::string foundHow;
    if (image.empty() && !gameGiven) {
        m.gameDir = FindGameDir(game, foundHow);
        if (m.gameDir.empty()) {
            const std::string msg = "Cannot find the game files (" + game.exeName + ").\n\n"
                "Run once with   --game /path/to/the/game/folder   and it is remembered, or set\n"
                "HLEKIT_GAME_DIR, or put the game folder next to this program.\n"
                "The original game is not included.";
            std::cerr << game.title << ": " << msg << "\n";
            if (!headless) SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_ERROR, game.title.c_str(), msg.c_str(), nullptr);
            return 1;
        }
    }
    if (image.empty()) image = m.gameDir + "/" + game.exeName;
    if (!gameGiven && image.size() > 4) {
        std::string ext = image.substr(image.size() - 4);
        for (auto& c : ext) c = (char)tolower((unsigned char)c);
        if (ext == ".exe") {
            auto slash = image.find_last_of('/');
            m.gameDir = slash == std::string::npos ? "." : image.substr(0, slash);
        }
    }
    if (!functions.empty() && !m.labels.Load(functions)) std::cerr << "note: no function labels (" << functions << ")\n";

    // "1.5:enter,3:down,5:up+2.5" (+ = held seconds); mouse "4:move@160/100", "5:lmb@160/100",
    // "6:rmb@10/20+0.5" (picture pixels).
    std::vector<ScriptKey> script;
    {
        std::stringstream ss(keys);
        std::string item;
        while (std::getline(ss, item, ',')) {
            auto c = item.find(':');
            if (c == std::string::npos) continue;
            double t = std::stod(item.substr(0, c)), held = 0.1;
            std::string name = item.substr(c + 1);
            const auto plus = name.rfind('+');
            if (plus != std::string::npos && plus > 0) { held = std::stod(name.substr(plus + 1)); name.resize(plus); }
            const auto at = name.find('@'), slash = name.find('/');
            if (at != std::string::npos && slash != std::string::npos && slash > at) {
                const std::string what = name.substr(0, at);
                const int x = std::stoi(name.substr(at + 1, slash - at - 1)), y = std::stoi(name.substr(slash + 1));
                const uint8_t b = what == "lmb" ? 1 : what == "rmb" ? 2 : what == "mmb" ? 4 : 0;
                if (!b && what != "move") { std::cerr << "unknown mouse event " << item << "\n"; return 2; }
                script.push_back({t, 0, true, false, true, x, y, b});
                if (b) script.push_back({t + held, 0, false, false, true, x, y, 0});
                continue;
            }
            const SDL_Scancode s = ScancodeByName(name);
            const uint8_t sc = XtScan(s);
            if (!sc) { std::cerr << "unknown key " << item << "\n"; return 2; }
            script.push_back({t, sc, true, XtExtended(s)});
            script.push_back({t + held, sc, false, XtExtended(s)});
        }
        std::stable_sort(script.begin(), script.end(), [](auto& x, auto& y) { return x.at < y.at; });
    }

    std::string err;
    RegisterPharLap286(m);                                  // NE programs' imports (before Load: value imports)
    if (game.onImports) game.onImports(m);
    m.loadHigh = game.loadHigh;
    if (!m.vm.Create(cpuName, err) || !m.Load(image, err)) { std::cerr << err << "\n"; return 1; }
    if (m.loadHigh) m.labels.Remap([&m](uint32_t a) { return m.Data(a); });
    if (foundHow != "remembered" && IsGameDir(m.gameDir, game.exeName)) RememberGameDir(game, m.gameDir);
    fprintf(stderr, "[cpu] %s\n", m.vm.Backend().c_str());
    if (!game.mapFile.empty() && !m.LoadMap(game.mapFile)) std::cerr << "note: no labels from " << game.mapFile << "\n";
    else if (m.segmented) m.labels.Sort();
    if (!dumpImage.empty()) {
        bool ok = m.DumpImage(dumpImage);
        printf("%s: entry %08x stack %08x, %zu objects, %u fixups -> %s\n", image.c_str(), m.entry, m.stack,
               m.regions.size(), m.fixups, ok ? dumpImage.c_str() : "write failed");
        return ok ? 0 : 1;
    }
    if (!m.Start(game.exeName, err)) { std::cerr << err << "\n"; return 1; }
    m.InstallSeams(game.seams, noSeams);
    m.InstallSeams(Decompiled(), noSeams);                  // translated functions (hlekit/decomp.h)
    for (const auto& [rel, bytes] : game.generatedFiles) {
        std::string lower = rel;
        for (auto& c : lower) c = (char)tolower((unsigned char)c);
        const std::filesystem::path out = std::filesystem::path(m.overlayDir) / lower;
        std::error_code ec;
        std::filesystem::create_directories(out.parent_path(), ec);
        FILE* f = fopen(out.string().c_str(), "wb");
        if (!f || fwrite(bytes.data(), 1, bytes.size(), f) != bytes.size()) std::cerr << "cannot write " << out << "\n";
        if (f) fclose(f);
    }
    // Sound: without a sink, sound seams take the game's own "no sound" path.
    if (!mute) {
        if (headless) m.audio = MakeClockSink();
        else {
            auto hostAudio = MakeHostAudio(soundFont);
            m.audio = std::move(hostAudio.samples);
            m.midi = std::move(hostAudio.midi);
        }
    }
    if (!wav.empty()) m.audio = MakeWavTee(m.audio ? std::move(m.audio) : MakeClockSink(), wav);
    auto pushKey = [&](uint8_t scan, bool down, bool extended) {
        if (!game.onKey) return;
        m.Post([&game, scan, down, extended](Machine& mm) { mm.Count("key"); game.onKey(mm, scan, down, extended); });
    };
    auto pushPad = [&](const PadState& pad) {
        if (!game.onPad) return;
        m.Post([&game, pad](Machine& mm) { game.onPad(mm, pad); });
    };
    auto pushMouse = [&](int x, int y, uint8_t buttons) {
        if (!game.onMouse) return;
        m.Post([&game, x, y, buttons](Machine& mm) { mm.Count("mouse"); game.onMouse(mm, x, y, buttons); });
    };
    auto pushMouseDelta = [&](int dx, int dy, uint8_t buttons) {
        if (!game.onMouseDelta) return;
        m.Post([&game, dx, dy, buttons](Machine& mm) { mm.Count("mouse"); game.onMouseDelta(mm, dx, dy, buttons); });
    };
    if (game.onStart) game.onStart(m);
    m.t0 = std::chrono::steady_clock::now();
    std::thread vcpu([&] { m.Run(); });

    std::vector<uint32_t> rgba;
    size_t nextKey = 0;
    auto feedScript = [&] {
        while (nextKey < script.size() && m.Seconds() >= script[nextKey].at) {
            const ScriptKey& k = script[nextKey];
            if (k.mouse) pushMouse(k.x, k.y, k.buttons);
            else pushKey(k.scan, k.down, k.extended);
            ++nextKey;
        }
    };
    if (headless) {
        while (!m.stopping && (seconds <= 0 || m.Seconds() < seconds)) {
            feedScript();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    } else {
        if (SDL_Init(SDL_INIT_VIDEO) != 0) { std::cerr << SDL_GetError() << "\n"; m.Stop("no video"); }
        if (game.onPad) SDL_InitSubSystem(SDL_INIT_GAMECONTROLLER);
        SDL_GameController* controller = nullptr;
        PadState pad;
        auto axis = [](Sint16 v) { return v < 0 ? v / 32768.0f : v / 32767.0f; };
        SDL_Window* win = SDL_CreateWindow(game.title.c_str(), SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                           game.windowWidth, 720, SDL_WINDOW_RESIZABLE);
        SDL_Renderer* ren = SDL_CreateRenderer(win, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
        SDL_Texture* tex = nullptr;
        int texW = 0, texH = 0;
        SDL_Rect shown{0, 0, 1, 1};                         // last picture rectangle, output pixels
        uint8_t mouseButtons = 0;
        const bool relativeMouse = static_cast<bool>(game.onMouseDelta);
        const bool mouseInput = game.onMouse || game.onMouseDelta;
        // With either mouse callback the game owns the pointer: a click grabs it (the game draws
        // its own cursor), Ctrl+G or losing focus releases it. Relative mode is for mouse-look:
        // the cursor cannot hit a window edge and stop the turn.
        bool grabbed = false;
        int lastX = 0, lastY = 0;                           // last pointer, picture pixels
        auto grab = [&](bool on) {
            if (!mouseInput || on == grabbed) return;
            grabbed = on;
            SDL_SetWindowGrab(win, on ? SDL_TRUE : SDL_FALSE);
            if (relativeMouse) SDL_SetRelativeMouseMode(on ? SDL_TRUE : SDL_FALSE);
            SDL_ShowCursor(on ? SDL_DISABLE : SDL_ENABLE);
            SDL_SetWindowTitle(win, on ? (game.title + " - Ctrl+G releases the mouse").c_str() : game.title.c_str());
            if (!on && mouseButtons) {
                mouseButtons = 0;
                if (relativeMouse) pushMouseDelta(0, 0, 0);
                else pushMouse(lastX, lastY, 0);
            }
        };
        bool swallowG = false;                              // the G of Ctrl+G, until its release
        bool swallowEnter = false;                          // the Enter of Alt+Enter (fullscreen toggle)
        // Window coordinates -> picture pixels (the output can be HiDPI-scaled).
        auto mouseAt = [&](int wx, int wy, uint8_t buttons) {
            int ww, wh, ow, oh;
            SDL_GetWindowSize(win, &ww, &wh);
            SDL_GetRendererOutputSize(ren, &ow, &oh);
            const double ox = (double)wx * ow / std::max(ww, 1), oy = (double)wy * oh / std::max(wh, 1);
            const int x = std::clamp((int)((ox - shown.x) * texW / std::max(shown.w, 1)), 0, std::max(texW - 1, 0));
            const int y = std::clamp((int)((oy - shown.y) * texH / std::max(shown.h, 1)), 0, std::max(texH - 1, 0));
            lastX = x;
            lastY = y;
            pushMouse(x, y, buttons);
        };
        auto buttonBit = [](uint8_t b) -> uint8_t {
            return b == SDL_BUTTON_LEFT ? 1 : b == SDL_BUTTON_RIGHT ? 2 : b == SDL_BUTTON_MIDDLE ? 4 : 0;
        };
        while (!m.stopping && (seconds <= 0 || m.Seconds() < seconds)) {
            SDL_Event e;
            while (SDL_PollEvent(&e)) {
                if (e.type == SDL_QUIT) m.Stop("window closed");
                if (e.type == SDL_WINDOWEVENT && e.window.event == SDL_WINDOWEVENT_FOCUS_LOST) grab(false);
                if ((e.type == SDL_KEYDOWN || e.type == SDL_KEYUP)) {
                    const SDL_Scancode sc0 = e.key.keysym.scancode;
                    if (sc0 == SDL_SCANCODE_RETURN || sc0 == SDL_SCANCODE_KP_ENTER) {
                        if (e.type == SDL_KEYDOWN && (e.key.keysym.mod & KMOD_ALT)) {
                            if (!e.key.repeat) {
                                const bool full = SDL_GetWindowFlags(win) & SDL_WINDOW_FULLSCREEN_DESKTOP;
                                SDL_SetWindowFullscreen(win, full ? 0 : SDL_WINDOW_FULLSCREEN_DESKTOP);
                            }
                            swallowEnter = true;
                            continue;
                        }
                        if (e.type == SDL_KEYUP && swallowEnter) { swallowEnter = false; continue; }
                    }
                    if (mouseInput && e.key.keysym.scancode == SDL_SCANCODE_G) {
                        if (e.type == SDL_KEYDOWN && (e.key.keysym.mod & KMOD_CTRL)) {
                            if (!e.key.repeat) grab(!grabbed);
                            swallowG = true;
                            continue;
                        }
                        if (e.type == SDL_KEYUP && swallowG) { swallowG = false; continue; }
                    }
                    if (uint8_t sc = XtScan(e.key.keysym.scancode))
                        pushKey(sc, e.type == SDL_KEYDOWN, XtExtended(e.key.keysym.scancode));
                }
                if (e.type == SDL_CONTROLLERDEVICEADDED && !controller) {
                    controller = SDL_GameControllerOpen(e.cdevice.which);
                    pad = PadState{};
                    pad.connected = controller != nullptr;
                    pushPad(pad);
                }
                if (e.type == SDL_CONTROLLERDEVICEREMOVED && controller &&
                    e.cdevice.which == SDL_JoystickInstanceID(SDL_GameControllerGetJoystick(controller))) {
                    SDL_GameControllerClose(controller);
                    controller = nullptr;
                    pad = PadState{};
                    pushPad(pad);
                }
                if (controller && (e.type == SDL_CONTROLLERAXISMOTION || e.type == SDL_CONTROLLERBUTTONDOWN ||
                                   e.type == SDL_CONTROLLERBUTTONUP)) {
                    PadState next = pad;
                    if (e.type == SDL_CONTROLLERAXISMOTION) {
                        const float v = axis(e.caxis.value);
                        switch (e.caxis.axis) {
                        case SDL_CONTROLLER_AXIS_LEFTX: next.lx = v; break;
                        case SDL_CONTROLLER_AXIS_LEFTY: next.ly = v; break;
                        case SDL_CONTROLLER_AXIS_RIGHTX: next.rx = v; break;
                        case SDL_CONTROLLER_AXIS_RIGHTY: next.ry = v; break;
                        case SDL_CONTROLLER_AXIS_TRIGGERLEFT: next.lt = v; break;
                        case SDL_CONTROLLER_AXIS_TRIGGERRIGHT: next.rt = v; break;
                        }
                    } else if (e.cbutton.button < 32) {
                        const uint32_t bit = 1u << e.cbutton.button;
                        next.buttons = e.type == SDL_CONTROLLERBUTTONDOWN ? next.buttons | bit : next.buttons & ~bit;
                    }
                    // Axis noise: report a change of at least 2% (buttons always).
                    auto moved = [](float a, float b) { return std::fabs(a - b) >= 0.02f; };
                    if (next.buttons != pad.buttons || moved(next.lx, pad.lx) || moved(next.ly, pad.ly) ||
                        moved(next.rx, pad.rx) || moved(next.ry, pad.ry) || moved(next.lt, pad.lt) || moved(next.rt, pad.rt)) {
                        pad = next;
                        pushPad(pad);
                    }
                }
                if (e.type == SDL_MOUSEMOTION && grabbed) {
                    if (relativeMouse) {
                        int ww, wh, ow, oh;
                        SDL_GetWindowSize(win, &ww, &wh);
                        SDL_GetRendererOutputSize(ren, &ow, &oh);
                        const double sx = (double)texW / std::max(shown.w, 1) * ow / std::max(ww, 1);
                        const double sy = (double)texH / std::max(shown.h, 1) * oh / std::max(wh, 1);
                        const int dx = (int)std::lround(e.motion.xrel * sx);
                        const int dy = (int)std::lround(e.motion.yrel * sy);
                        if (dx || dy) pushMouseDelta(dx, dy, mouseButtons);
                    } else {
                        mouseAt(e.motion.x, e.motion.y, mouseButtons);
                    }
                }
                if (e.type == SDL_MOUSEBUTTONDOWN && mouseInput && !grabbed) {
                    grab(true);                             // this click only takes the mouse
                    if (!relativeMouse) mouseAt(e.button.x, e.button.y, mouseButtons);
                    continue;
                }
                if ((e.type == SDL_MOUSEBUTTONDOWN || e.type == SDL_MOUSEBUTTONUP) && grabbed) {
                    const uint8_t bit = buttonBit(e.button.button);
                    mouseButtons = e.type == SDL_MOUSEBUTTONDOWN ? mouseButtons | bit : mouseButtons & ~bit;
                    if (bit) {
                        if (relativeMouse) pushMouseDelta(0, 0, mouseButtons);
                        else mouseAt(e.button.x, e.button.y, mouseButtons);
                    }
                }
            }
            feedScript();
            int w, h;
            double aspect;
            bool changed = Frame(m, rgba, w, h, aspect);
            if (!tex || w != texW || h != texH) {
                if (tex) SDL_DestroyTexture(tex);
                tex = SDL_CreateTexture(ren, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING, w, h);
                texW = w;
                texH = h;
                changed = true;
            }
            if (changed) SDL_UpdateTexture(tex, nullptr, rgba.data(), w * 4);
            int winW, winH;
            SDL_GetRendererOutputSize(ren, &winW, &winH);
            const SDL_Rect dst = Fit(winW, winH, w, h, aspect);
            shown = dst;
            SDL_SetRenderDrawColor(ren, 0, 0, 0, 255);
            SDL_RenderClear(ren);
            SDL_RenderCopy(ren, tex, nullptr, &dst);
            SDL_RenderPresent(ren);
        }
        if (tex) SDL_DestroyTexture(tex);
        if (controller) SDL_GameControllerClose(controller);
        SDL_DestroyRenderer(ren);
        SDL_DestroyWindow(win);
        SDL_Quit();
    }
    m.Stop(m.stopping ? "" : "time limit");
    vcpu.join();

    if (!png.empty()) {
        int w, h;
        double aspect;
        Frame(m, rgba, w, h, aspect);
        if (WritePng(png, rgba, w, h)) std::cerr << "framebuffer " << w << "x" << h << " -> " << png << "\n";
    }
    printf("stopped: %s after %.2f s, %llu frames (vsync seam)\n", m.stopReason.c_str(), m.Seconds(),
           (unsigned long long)m.frames.load());
    std::vector<std::pair<std::string, uint64_t>> counts(m.counts.begin(), m.counts.end());
    std::sort(counts.begin(), counts.end(), [](auto& a, auto& b) { return a.second > b.second; });
    for (auto& [k, n] : counts) printf("  %-48s %10llu\n", k.c_str(), (unsigned long long)n);
    return 0;
}

}  // namespace hlekit
