/*
 * sys-zerotier -- primitives for the virtual network shim.
 *
 * Deliberately free of any Horizon, libnx or libstratosphere dependency so the
 * whole shim can be built and tested on a host machine. Nothing here allocates.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace ztnx::net {

    using u8  = uint8_t;
    using u16 = uint16_t;
    using u32 = uint32_t;
    using u64 = uint64_t;

    /* ---- byte order -------------------------------------------------- */
    /* Written by hand rather than pulled from <arpa/inet.h> so this header
     * stays usable in a freestanding sysmodule build. */

    constexpr u16 hton16(u16 v) { return (u16)((v << 8) | (v >> 8)); }
    constexpr u16 ntoh16(u16 v) { return hton16(v); }
    constexpr u32 hton32(u32 v) {
        return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
               ((v & 0x00FF0000u) >> 8)  | ((v & 0xFF000000u) >> 24);
    }
    constexpr u32 ntoh32(u32 v) { return hton32(v); }

    /* Unaligned access helpers. Packet buffers are byte arrays and the fields
     * inside them are not naturally aligned; reading them through a pointer
     * cast is undefined behaviour and traps on some ARM configurations. */
    inline u16 rd16(const u8 *p) { u16 v; memcpy(&v, p, 2); return ntoh16(v); }
    inline u32 rd32(const u8 *p) { u32 v; memcpy(&v, p, 4); return ntoh32(v); }
    inline void wr16(u8 *p, u16 v) { const u16 n = hton16(v); memcpy(p, &n, 2); }
    inline void wr32(u8 *p, u32 v) { const u32 n = hton32(v); memcpy(p, &n, 4); }

    /* ---- checksum ---------------------------------------------------- */

    /* One's complement sum, RFC 1071. `initial` carries a pseudo-header sum in
     * for UDP/TCP. Returns the value to place in the checksum field. */
    inline u16 checksum16(const void *data, size_t len, u32 initial = 0)
    {
        const u8 *p = static_cast<const u8 *>(data);
        u32 sum = initial;

        while (len > 1) {
            sum += (u32)((p[0] << 8) | p[1]);
            p   += 2;
            len -= 2;
        }
        if (len) {
            sum += (u32)(p[0] << 8);
        }
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (u16)(~sum & 0xFFFF);
    }

    /* ---- ethernet ---------------------------------------------------- */

    constexpr u16 EtherType_IPv4 = 0x0800;
    constexpr u16 EtherType_ARP  = 0x0806;

    /* ZeroTier passes MAC addresses as the low 48 bits of a u64, which is the
     * representation used throughout the shim. */
    constexpr u64 MacBroadcast = 0xFFFFFFFFFFFFull;

    inline void macToBytes(u64 mac, u8 out[6])
    {
        out[0] = (u8)(mac >> 40); out[1] = (u8)(mac >> 32); out[2] = (u8)(mac >> 24);
        out[3] = (u8)(mac >> 16); out[4] = (u8)(mac >>  8); out[5] = (u8)(mac);
    }

    inline u64 macFromBytes(const u8 in[6])
    {
        return ((u64)in[0] << 40) | ((u64)in[1] << 32) | ((u64)in[2] << 24) |
               ((u64)in[3] << 16) | ((u64)in[4] <<  8) | ((u64)in[5]);
    }

    /* ---- IPv4 -------------------------------------------------------- */

    constexpr u8 IpProto_ICMP = 1;
    constexpr u8 IpProto_UDP  = 17;

    constexpr u32 IpBroadcast = 0xFFFFFFFFu;   /* host order */

    /* Header field offsets, so the code reads like the RFC diagrams. */
    namespace ip4 {
        constexpr size_t VerIhl = 0, Tos = 1, TotalLen = 2, Id = 4, FlagsFrag = 6,
                         Ttl = 8, Proto = 9, Csum = 10, Src = 12, Dst = 16;
        constexpr size_t MinHeader = 20;
        constexpr u16 FlagDontFragment = 0x4000;
        constexpr u16 FlagMoreFragments = 0x2000;
        constexpr u16 FragOffsetMask = 0x1FFF;
    }

    namespace udp4 {
        constexpr size_t SrcPort = 0, DstPort = 2, Length = 4, Csum = 6;
        constexpr size_t Header = 8;
    }

    namespace icmp4 {
        constexpr size_t Type = 0, Code = 1, Csum = 2;
        constexpr u8 EchoRequest = 8, EchoReply = 0;
    }

    namespace arp4 {
        constexpr size_t HwType = 0, ProtoType = 2, HwLen = 4, ProtoLen = 5, Op = 6,
                         SenderMac = 8, SenderIp = 14, TargetMac = 18, TargetIp = 24;
        constexpr size_t Size = 28;
        constexpr u16 OpRequest = 1, OpReply = 2;
    }

}  // namespace ztnx::net
