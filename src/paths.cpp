#include "hlekit/paths.h"

#include <SDL2/SDL.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <vector>

namespace hlekit {

namespace fs = std::filesystem;

namespace {
std::string Lower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

std::string Env(const char* name) {
    const char* v = getenv(name);
    return v ? v : "";
}

// The per-user writable directory SDL picks for this platform (XDG data home on Linux, %APPDATA% on
// Windows, ~/Library/Application Support on macOS), created on first use; "" if it has none.
fs::path UserDir(const GameInfo& game) {
    char* p = SDL_GetPrefPath("hlekit", GameSlug(game).c_str());
    if (!p) return {};
    fs::path d = p;
    SDL_free(p);
    return d;
}

fs::path ConfigFile(const GameInfo& game) { return UserDir(game) / "game_dir"; }
}  // namespace

std::string GameSlug(const GameInfo& game) {
    std::string s;
    for (char c : game.title.empty() ? game.exeName : game.title) {
        if (isalnum((unsigned char)c)) s += (char)tolower((unsigned char)c);
        else if (!s.empty() && s.back() != '-') s += '-';
    }
    while (!s.empty() && s.back() == '-') s.pop_back();
    return s.empty() ? "game" : s;
}

bool IsGameDir(const std::string& dir, const std::string& exeName) {
    if (dir.empty() || exeName.empty()) return false;
    std::error_code ec;
    const std::string want = Lower(exeName);
    for (auto& e : fs::directory_iterator(dir, ec))
        if (Lower(e.path().filename().string()) == want) return true;
    return false;
}

std::string FindGameDir(const GameInfo& game, std::string& how) {
    auto good = [&](const std::string& d, const char* why) {
        if (!IsGameDir(d, game.exeName)) return false;
        how = why;
        return true;
    };
    if (std::string d = Env("HLEKIT_GAME_DIR"); good(d, "HLEKIT_GAME_DIR")) return d;
    {
        std::ifstream f(ConfigFile(game));
        std::string d;
        if (std::getline(f, d) && good(d, "remembered")) return d;
    }
    if (good(game.gameDir, "built-in default")) return game.gameDir;

    std::vector<fs::path> roots;
    if (std::string d = Env("OWD"); !d.empty()) roots.push_back(d);                // AppImage: where it was started
    std::error_code ec;
    roots.push_back(fs::current_path(ec));
    if (std::string a = Env("APPIMAGE"); !a.empty()) roots.push_back(fs::path(a).parent_path());
    if (char* base = SDL_GetBasePath()) {                                           // the program's own directory
        roots.push_back(base);
        SDL_free(base);
    }
    for (const fs::path& r : roots)
        for (const char* sub : {"", "game"}) {
            const std::string d = (sub[0] ? r / sub : r).string();
            if (good(d, "found next to the program")) return d;
        }
    how.clear();
    return {};
}

void RememberGameDir(const GameInfo& game, const std::string& dir) {
    std::error_code ec;
    const fs::path abs = fs::absolute(dir, ec);
    const fs::path f = ConfigFile(game);
    if (!f.has_parent_path()) return;
    std::ofstream(f) << abs.string() << "\n";
}

std::string DefaultOverlayDir(const GameInfo& game) {
    const fs::path user = UserDir(game);
    return user.empty() ? "overlay" : (user / "overlay").string();   // "overlay" only if SDL has no user dir
}

std::string DefaultConfigFile(const GameInfo& game) {
    const fs::path user = UserDir(game);
    return user.empty() ? "config.ini" : (user / "config.ini").string();
}

}  // namespace hlekit
