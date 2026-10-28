// Native seam modules for @TITLE@.
//
// A seam module is just a function returning std::vector<Seam>. Keep the hardware boundary
// split by area, not in one growing GameSeams() function: video/, input/, sound/, timing/ can
// each grow independently, and later decompiled modules can live beside them.
#pragma once

#include "hlekit/machine.h"
#include "hlekit/seam.h"

#include <cstdint>
#include <vector>

namespace game::seams {

using SeamList = hlekit::SeamList;

SeamList Video();
SeamList Input();
SeamList Sound();
SeamList Timing();
SeamList All();

// Input entry points: the native bodies of the game's keyboard/mouse/pad handlers. They run at
// an interruptible point, where the original IRQ could have arrived.
void OnKey(hlekit::Machine& m, uint8_t xtScan, bool down, bool extended);
void OnMouse(hlekit::Machine& m, int x, int y, uint8_t buttons);
void OnPad(hlekit::Machine& m, const hlekit::PadState& pad);

}  // namespace game::seams
