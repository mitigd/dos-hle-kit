// Translated game functions: the decompilation growing on top of the seams.
//
// A project's src/decompiled/ (laid out from the executable's symbols by tools/decomp/gen_decomp.py)
// holds one native function per original function that has been translated. Each registers
// itself here at static-initialisation time; the runner installs them after the game's seam table,
// as seams in area "decomp/<module>". The original stays in the image: `--no-seam NAME`,
// `--no-seam decomp/<module>` or `--no-seam decomp` puts it back, for A/B against the guest code,
// and Machine::CallOriginal runs it from inside a translation that is still partial.
#pragma once

#include "hlekit/seam.h"

namespace hlekit {

SeamList& Decompiled();

struct DecompRegistration {
    explicit DecompRegistration(Seam s) { Decompiled().push_back(std::move(s)); }
};

}  // namespace hlekit
