/*
 * sys-zerotier -- the three OSUtils functions node/ actually uses.
 *
 * node/ reaches into osdep/OSUtils.hpp for exactly three statics, and used to
 * get the declaration transitively through osdep/Binder.hpp. The real header
 * pulls in nlohmann/json.hpp and a pile of desktop OS surface, and worse, its
 * implementation lives in osdep/OSUtils.cpp, which a sysmodule does not build
 * -- so including it would trade a compile error for a link error.
 *
 * Declared here, implemented in ZtOSUtilsSwitch.cpp, byte-for-byte compatible
 * with upstream apart from ztsnprintf, which truncates instead of throwing.
 */
#pragma once

#include <stdint.h>
#include <string>

namespace ZeroTier {

    class OSUtils {
      public:
        static std::string  networkIDStr(const uint64_t nwid);
        static std::string  nodeIDStr(const uint64_t nid);
        static unsigned int ztsnprintf(char* buf, unsigned int len, const char* fmt, ...);
    };

}   // namespace ZeroTier
