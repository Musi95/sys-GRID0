#pragma once

#include "net.hpp"

namespace ztnx::net {
    /* Addresses and masks are in host order. An unknown configuration or a
     * point-to-point/host route must not turn a unicast into a broadcast. */
    constexpr bool IsSubnetBroadcast(u32 destination, u32 local, u32 mask)
    {
        const u32 hosts = ~mask;
        return local != 0 && mask != 0 && hosts > 1 &&
               (hosts & (hosts + 1)) == 0 && destination == (local | hosts);
    }

    constexpr bool IsLanBroadcast(u32 destination, u32 overlayIp, u32 overlayMask,
                                  u32 physicalIp, u32 physicalMask)
    {
        return destination == 0xFFFFFFFFu ||
               IsSubnetBroadcast(destination, overlayIp, overlayMask) ||
               IsSubnetBroadcast(destination, physicalIp, physicalMask);
    }
}
