// Where a game's files are, and where the kit may write: the part of start-up that must not be
// baked into a build. A program that ships (an AppImage, a release zip) cannot know where its user
// keeps the original game, and may itself sit on a read-only mount.
//
// Game directory, first match wins (see FindGameDir):
//   1. --game DIR, or an EXE/IMAGE path on the command line       (explicit; handled by the runner)
//   2. $HLEKIT_GAME_DIR
//   3. the directory remembered from the last successful start     ("game_dir" in the per-user directory)
//   4. GameInfo::gameDir, a compiled-in hint - leave it empty in anything you distribute
//   5. next to the program: the directory an AppImage was started from ($OWD), the current
//      directory, the AppImage's or the executable's own directory, and a "game" folder in each
// A directory counts only if it contains the game's executable (GameInfo::exeName, any case).
//
// Overlay (the writable side; saved games land here): --overlay DIR, else "overlay" in the per-user
// directory, SDL_GetPrefPath("hlekit", <slug>) - the platform's own place: XDG data home on Linux,
// %APPDATA% on Windows, Application Support on macOS. The remembered game directory lives there
// too. Nothing here names a platform, and nothing depends on the current directory.
#pragma once
#include "hlekit/seam.h"

#include <string>

namespace hlekit {

std::string GameSlug(const GameInfo& game);                       // "gold-rush" from the title
bool IsGameDir(const std::string& dir, const std::string& exeName);
// The game directory by rules 2-5; `how` says which one matched. "" when none did.
std::string FindGameDir(const GameInfo& game, std::string& how);
void RememberGameDir(const GameInfo& game, const std::string& dir);
std::string DefaultOverlayDir(const GameInfo& game);

}  // namespace hlekit
