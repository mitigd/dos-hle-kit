// The compiler's diagnostics buffer.
#pragma once

#include <sstream>
#include <string>

#include "Common/Log.h"

struct BlockLogHelper {
    std::ostringstream buffer;
    bool isError = false;
    ~BlockLogHelper() {
        std::string s = buffer.str();
        if (!s.empty()) (isError ? LOG_ERROR : LOG_INFO) << s;
    }
};
