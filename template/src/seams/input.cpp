// Input seams: the native bodies of the game's keyboard, mouse and controller handlers.
#include "seams/seams.h"

namespace game::seams {

SeamList Input() {
    return {
        // Example: the keyboard ISR itself (vector 9 / the handler in the game's table).
        // {0x00000000, "keyboard_isr", "input",
        //  "FUN_xxxxxxxx: reads port 60h and appends to the game's key queue. Native: OnKey below.",
        //  [](hlekit::Machine& m) { /* translate the ISR body, then call m.OnKey logic */ }},
    };
}

void OnKey(hlekit::Machine& m, uint8_t xtScan, bool down, bool extended) {
    // The original keyboard IRQ body goes here: write the guest's key table/queue exactly as
    // the game's ISR does. `extended` is true for keys that send an E0h prefix.
    (void)m;
    (void)xtScan;
    (void)down;
    (void)extended;
}

void OnMouse(hlekit::Machine& m, int x, int y, uint8_t buttons) {
    // Native body of the game's mouse handler. Coordinates are in displayed picture pixels;
    // buttons bit 0 = left, bit 1 = right, bit 2 = middle.
    (void)m;
    (void)x;
    (void)y;
    (void)buttons;
}

void OnPad(hlekit::Machine& m, const hlekit::PadState& pad) {
    // The game's controller state update. `pad` uses SDL's standard controller layout.
    (void)m;
    (void)pad;
}

}  // namespace game::seams
