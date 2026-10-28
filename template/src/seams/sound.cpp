// Sound seams: start/stop, the mixer ISR, volume, and music driver entry points.
#include "seams/seams.h"

namespace game::seams {

SeamList Sound() {
    return {
        // Example (remove or adapt): start digital sound.
        // {0x00000000, "sound_start", "sound",
        //  "FUN_xxxxxxxx: programs the DMA/SB and installs its mixer ISR. Native: StartSound.",
        //  [](hlekit::Machine& m) {
        //      const int rate = (int)m.vm.Get(hlekit::Reg::Eax);
        //      m.StartSound(rate, 2, 16, 4096, [](hlekit::Machine& mm) {
        //          // Queue the next guest-mixed buffer here.
        //          (void)mm;
        //      });
        //  }},
    };
}

}  // namespace game::seams
