# Porting ZeroTier's core to Horizon OS (Nintendo Switch)

Status: the core **builds** for aarch64 as a static library — see `README.md`
for the numbers and `patches/0001-horizon-port.patch` for the three source
changes it needs. It has not yet been built with devkitA64 itself (the
devkitPro package host was unreachable from the machine this was written on),
so the remaining unknowns are newlib and libstratosphere integration, not the
ZeroTier source.

Everything marked *verified* below was checked by actually compiling
`ZeroTierOne/node/*.cpp` with `aarch64-linux-gnu-g++ 13.3`. Everything else is
derived from source reading.

## 1. What you actually need from ZeroTierOne

Take **only `node/`** (MPL-2.0). Do *not* vendor `libzt`: it is BSL-1.1, which
is not an open-source licence and restricts production use, and if `ldn_mitm`
support is ever added the resulting GPLv2 tree cannot contain it at all. Read
libzt for design reference, reimplement.

Verified: all 31 translation units in `node/` compile clean for aarch64 with

```
-std=c++17 -O2 -march=armv8-a+crypto \
  -I. -Iinclude -isystem ext \
  -Iext/prometheus-cpp-lite-1.0/core/include \
  -Iext/prometheus-cpp-lite-1.0/simpleapi/include \
  -Iext/prometheus-cpp-lite-1.0/3rdparty/http-client-lite/include
```

(skip `node/AES_aesni.cpp`, it is x86-only). Total object size ~1.6 MB
unstripped. `-DZT_NO_PEER_METRICS=1` drops the prometheus include chain if you
would rather not carry `ext/`.

## 2. The complete libc/OS surface the core needs

Verified by taking the union of undefined symbols across all 31 objects, minus
C++ ABI and internal ZeroTier symbols:

```
malloc calloc free
memcpy memmove memset memcmp __memcpy_chk
strchr strcmp strlen strncpy strtok_r
strtoll strtoul strtoull
snprintf fprintf stderr __assert_fail exit
inet_ntop inet_pton
open read close
time nanosleep
pthread_mutex_init/lock/unlock/destroy
sqrt sqrtf expf
getauxval
__stack_chk_fail __stack_chk_guard __libc_single_threaded __errno_location
```

Everything on that list except **three items** is already provided by
devkitA64's newlib + libnx.

After `patches/0001-horizon-port.patch` is applied, the list shrinks further:
`getauxval`, `open`, `read`, `close`, `exit`, `fprintf`, `stderr`,
`__assert_fail` and `nanosleep` all disappear, leaving plain libc plus a single
function the port layer provides, `ztnx_secure_random_fill`.

## 3. The three real blockers

(All three are implemented in `patches/0001-horizon-port.patch`; this section
is the reasoning behind them. Two further findings that only surfaced when the
library was actually linked — the prometheus dependency and the core's use of
exceptions — are written up in `README.md`.)

### 3.1 `getauxval` — CPU feature detection

`node/Utils.cpp` calls `getauxval(AT_HWCAP)` / `AT_HWCAP2` to decide whether to
use the ARMv8 AES/PMULL/SHA2 instructions. There is no auxv on Horizon.

The Tegra X1's Cortex-A57 implements the ARMv8-A Crypto Extensions
unconditionally, so hardcode it:

```cpp
// node/Utils.cpp, inside CPUIDRegisters ctor for __aarch64__
#ifdef __SWITCH__
    this->aes = true; this->crc32 = true; this->pmull = true;
    this->sha1 = true; this->sha2 = true;
#else
    ... existing getauxval path ...
#endif
```

Build the AES/GMAC path with `-march=armv8-a+crypto`. This matters: it is the
difference between ~100 MB/s and ~1 GB/s on the AES-GMAC-SIV transport cipher,
and CPU time on the system core is the scarcest resource you have.

### 3.2 `open`/`read` on `/dev/urandom` — the CSPRNG

`Utils::getSecureRandom()` opens `/dev/urandom`, refills a 64 KB buffer, and
whitens it with Salsa20. Replace the file-descriptor path with the console's
hardware CSPRNG:

```cpp
#ifdef __SWITCH__
    #include <switch.h>
    // once, at init: csrngInitialize();
    csrngGetRandomBytes(randomBuf, sizeof(randomBuf));
#else
    ... existing /dev/urandom path ...
#endif
```

Keep the Salsa20 whitening; it costs nothing. Do **not** ship with the fallback
seeding (`time(0)` + three heap addresses) as the only entropy — that produces
guessable identities.

### 3.3 `time()` must be real before the first `ZT_Node_new`

Identity generation, certificate-of-membership validity windows and path
liveness all use wall-clock milliseconds. In a sysmodule you must
`timeInitialize()` and wait for `timeGetCurrentTime(TimeType_Default, ...)` to
return a sane value before creating the node. On a console that has never had
network time set, the RTC can be years off; ZeroTier will hand you a
`ZT_EVENT_ONLINE` that never arrives because the root's COM looks expired.

## 4. The five callbacks you have to write

`ZT_Node_new` takes a `ZT_Node_Callbacks` with six required entries. This is
your entire porting boundary — the core touches nothing else:

| Callback | Horizon implementation |
|---|---|
| `stateGetFunction` / `statePutFunction` | `fs::` on the SD card, under `/atmosphere/contents/<tid>/zt/`. Objects are `identity.public`, `identity.secret`, `planet`, `network.<nwid>.conf`, `peer.<addr>`. Keep writes rare — SD write latency spikes will stall the node thread. |
| `wirePacketSendFunction` | One `AF_INET` `SOCK_DGRAM` socket bound to UDP/9993 on `bsd:s`. Return 0 on success, -1 otherwise. |
| `virtualNetworkFrameFunction` | Ethernet frame arriving from the virtual L2. Hand to lwIP `netif->input`, or to the UDP fast path (§5). |
| `virtualNetworkConfigFunction` | Fired on `ZT_VIRTUAL_NETWORK_CONFIG_UPDATE`: this is where you learn your assigned IP/netmask and MAC. Store them — the `ldn:u` MITM reports this address to games. |
| `eventCallback` | `ZT_EVENT_UP/ONLINE/OFFLINE/DOWN` + trace. Drive the status shown in the config overlay. |
| `pathCheckFunction` (optional) | Return 0 for any destination on the console's own LAN subnet if you want to forbid ZeroTier from forming paths through the local network. Usually leave it null. |

Then run one thread:

```cpp
int64_t nextDeadline = 0;
for (;;) {
    const int64_t now = OSUtils::now();
    if (now >= nextDeadline) ZT_Node_processBackgroundTasks(node, nullptr, now, &nextDeadline);
    // poll the 9993 socket -> ZT_Node_processWirePacket
    // drain the outbound game-frame queue -> ZT_Node_processVirtualNetworkFrame
}
```

## 5. The IP stack question

ZeroTier hands you **Ethernet frames**. Games speak **sockets**. Something has
to sit between.

- **MVP (UDP only):** hand-assemble Ethernet + ARP + IPv4 + UDP. Native
  LAN-play titles are UDP: broadcast for discovery, unicast for gameplay.
  ~600 lines, no dependency, ~64 KB of buffers. See `BSD_MITM.md` §6.
- **Full:** lwIP (BSD licence, GPL-compatible) as a `netif` whose `linkoutput`
  is `ZT_Node_processVirtualNetworkFrame`. This is what libzt's `VirtualTap`
  does — read `libzt/src/VirtualTap.cpp` for the shape, write your own.

If you take lwIP, **do not copy `libzt/src/lwipopts.h`**. Its defaults assume a
desktop: `PBUF_POOL_SIZE 1024`, `MEMP_NUM_NETCONN 1024`,
`MEMP_NUM_TCPIP_MSG_INPKT 1024`, `TCP_WND 0xffff0`, `TCP_SND_BUF 64*TCP_MSS`.
That is tens of megabytes of pools against a budget of a few. Start from
`PBUF_POOL_SIZE 32`, `MEMP_NUM_NETCONN 16`, `TCP_WND 8*TCP_MSS`, and measure.

## 6. Sysmodule shape

Copy `ldn_mitm/ldn_mitm/res/app.json` as your NPDM starting point and change:

- `title_id`: pick an unused `0x0100000000xxxxxx` in the homebrew range.
- `pool_partition`: `2` (system) as ldn_mitm uses, or `1` (applet) if you need
  the headroom and can live with applet-pool contention.
- `main_thread_stack_size`: `0x20000` is enough for the IPC dispatcher; the ZT
  node thread gets its own stack.
- Keep `service_access: ["*"]` and `service_host: ["*"]` — you need to host
  `ldn:u` and `bsd:u` as MITM ports.

Memory discipline is the same as ldn_mitm's: one static `g_malloc_buffer` fed to
`init::InitializeAllocator`, no dynamic growth. ZeroTier will want considerably
more than ldn_mitm's 1 MB — budget 4 MB for the node (peer/path objects, the
64 KB random buffer, packet fragment queues) plus whatever lwIP takes.

Socket init inside the sysmodule follows ldn_mitm exactly
(`ldnmitm_main.cpp:41-96`): a `constexpr SocketInitConfig`, a `consteval`-sized
static transfer-memory buffer, then `bsdInitialize()` + `socketInitialize()`.
Prefer `BsdServiceType_System` (`bsd:s`, 0x7E sessions) over `bsd:u`, which was
cut to 0xF sessions in firmware 18.0.0.

## 7. Files in this skeleton

```
BSD_MITM.md       spec for the bsd:u interception layer -- the v1 core
Makefile          devkitPro/Atmosphere-libs sysmodule makefile
res/app.json      NPDM descriptor
source/main.cpp   sysmodule entry, allocator, socket + service init
source/zt_port.hpp/.cpp   the six callbacks, state store, wire socket
```

Target order: native **LAN-play** titles first (Mario Kart 8 Deluxe, Splatoon
2/3, ARMS, ...), which need only the `bsd:u` interception described in
`BSD_MITM.md`. Local-wireless titles, which additionally need an `ldn:u` MITM in
the style of ldn_mitm, come after that works.

They are structurally faithful to ldn_mitm but have never been built. Treat
them as an annotated starting point, not as working code.
