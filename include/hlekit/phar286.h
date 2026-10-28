// Phar Lap 286|DOS-Extender's system interface for NE programs, answered natively: the OS/2 1.x
// subset it exports as DOSCALLS (segments, huge blocks, aliases, vectors, exit list) and its own
// PHAPI (real-mode and linear memory, vectors, real-mode interrupts). These are the extender's
// OS services - no hardware - so they live in the kit. Registered as Machine::importImpls.
#pragma once

namespace hlekit {

class Machine;
void RegisterPharLap286(Machine& m);

}  // namespace hlekit
