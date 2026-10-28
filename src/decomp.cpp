#include "hlekit/decomp.h"

namespace hlekit {

SeamList& Decompiled() {
    static SeamList list;                       // a function-local static: safe from any TU's initialiser
    return list;
}

}  // namespace hlekit
