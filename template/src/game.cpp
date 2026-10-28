// @TITLE@ (@EXE@) on dos-hle-kit: the GameInfo and the module wiring.
//
// The seam table is composed from src/seams/ (video, input, sound, timing). Start from
// docs/seam-candidates.md: every function there that touches hardware becomes a seam, with the
// decomp evidence in its `doc`. Run the game, read the `[hw] unseamed hardware access` lines,
// repeat until there are none. See docs/project.md.
#include "hlekit/machine.h"
#include "hlekit/seam.h"
#include "seams/seams.h"

using namespace hlekit;

int main(int argc, char** argv) {
    GameInfo g;
    g.title = "@NAME@-hle";
    g.exeName = "@EXENAME@";
    g.functionsCsv = "@FUNCTIONSCSV@";   // optional: address,name,size labels from any decompiler
    g.seams = game::seams::All();

    // Input callbacks are implemented in src/seams/input.cpp. Uncomment each one as the game's
    // handler is translated; setting onMouse also hides the host cursor.
    g.onKey = game::seams::OnKey;
    // g.onMouse = game::seams::OnMouse;
    // g.onPad = game::seams::OnPad;

    return Main(argc, argv, g);
}
