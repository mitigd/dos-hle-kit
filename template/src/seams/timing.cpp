// Timing seams: PIT reads, retrace waits, and timer ISR bodies.
#include "seams/seams.h"

#include <chrono>

namespace game::seams {

SeamList Timing() {
    using namespace std::chrono;
    return {
        // Example (remove or adapt): a retrace wait, replaced by 70 Hz pacing on the host clock.
        // {0x00000000, "vsync_wait", "timing",
        //  "FUN_xxxxxxxx: waits for retrace on 3DAh bit 3. Native: pace to 70 Hz.",
        //  [](hlekit::Machine& m) {
        //      constexpr auto period = microseconds(14286);
        //      auto n = (steady_clock::now() - m.t0) / period + 1;
        //      m.WaitUntil(m.t0 + n * period);
        //      ++m.frames;
        //  }},
    };
}

}  // namespace game::seams
