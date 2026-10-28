// The seam table as a composition of the area modules. There is no central registry: adding a
// module means adding one function here and one source file in meson.build.
#include "seams/seams.h"

#include <iterator>

namespace game::seams {

SeamList All() {
    SeamList seams;
    auto append = [&](SeamList part) {
        seams.insert(seams.end(), std::make_move_iterator(part.begin()),
                     std::make_move_iterator(part.end()));
    };
    append(Video());
    append(Input());
    append(Sound());
    append(Timing());
    return seams;
}

}  // namespace game::seams
