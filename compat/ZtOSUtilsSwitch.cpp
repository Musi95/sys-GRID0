#include "ZtOSUtilsSwitch.hpp"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

namespace ZeroTier {

    unsigned int OSUtils::ztsnprintf(char* buf, unsigned int len, const char* fmt, ...)
    {
        va_list ap;
        va_start(ap, fmt);
        const int n = vsnprintf(buf, len, fmt, ap);
        va_end(ap);

        /* Upstream throws std::length_error on overflow. Every caller in node/
         * passes a buffer that is comfortably large enough, and a sysmodule has
         * better things to do than unwind over a formatting mishap, so this
         * truncates and reports what fit. */
        if (n < 0) {
            if (len) { buf[0] = (char)0; }
            return 0;
        }
        if ((unsigned int)n >= len) {
            if (len) { buf[len - 1] = (char)0; }
            return len ? (len - 1) : 0;
        }
        return (unsigned int)n;
    }

    std::string OSUtils::networkIDStr(const uint64_t nwid)
    {
        char tmp[32] = {};
        ztsnprintf(tmp, sizeof(tmp), "%.16" PRIx64, nwid);
        return std::string(tmp);
    }

    std::string OSUtils::nodeIDStr(const uint64_t nid)
    {
        char tmp[32] = {};
        ztsnprintf(tmp, sizeof(tmp), "%.10" PRIx64, nid);
        return std::string(tmp);
    }

}   // namespace ZeroTier
