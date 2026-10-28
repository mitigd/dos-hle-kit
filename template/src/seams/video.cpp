// Video seams: palette uploads, mode changes, planar/VESA helpers, frame composition.
#include "seams/seams.h"

namespace game::seams {

SeamList Video() {
    return {
        // Example (remove or adapt): a palette upload, read from the guest's 6-bit DAC array.
        // {0x00000000, "set_palette", "video",
        //  "FUN_xxxxxxxx: writes the VGA DAC from a 768-byte guest buffer. Native: copy to m.palette.",
        //  [](hlekit::Machine& m) {
        //      const uint32_t src = m.vm.Get(hlekit::Reg::Eax);
        //      for (int i = 0; i < 768; ++i) m.palette[i] = m.vm.Rd8(src + i);
        //  }},
    };
}

}  // namespace game::seams
