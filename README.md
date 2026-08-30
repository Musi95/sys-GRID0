# sys-zerotier

A ZeroTier node inside a Nintendo Switch system module, so that games with a
native **LAN Play** mode work over the internet with nothing else on the
network — no PC running `switch-lan-play`, no relay server, no second machine.

The native-LAN whitelist now covers the maintained Ryujinx/Ryubing LAN-mode
set, Nintendo Switch Sports and Civilization VI (21 program ids after regional
variants). Local-wireless-only titles still need a future `ldn:u` MITM.

---

## Status

| Phase | | |
|---|---|---|
| 0 · Does LAN mode need a wired link? | **answered** | No. MK8D and the other LAN titles work over Wi-Fi. |
| 1 · ZeroTier core builds for aarch64 | **done, on devkitA64** | 32 objects, `libztcore.a`, 1.15 MB. |
| 2 · Packet shim | **done, tested** | `source/net/`, 76 host checks + a 200k-frame fuzz pass. |
| 3 · Sysmodule shell | **done, running on hardware** | Joins a network, keeps its identity and address across reboots. |
| 3b · End-to-end reachability | **done, verified** | A PC on the ZeroTier network pings the console: `64 bytes from 10.147.17.243: ttl=64 time=67.1 ms`. ARP, IPv4 and ICMP all answered by `source/net/`. |
| 3c · Uplink survives LAN Play | **answered** | Stayed online for a 23-minute MK8D session with remote ZeroTier peers. |
| 4 · `bsd:u` + `nifm:u` MITM | **done, on hardware** | PIA discovery, setup and gameplay sockets mirror into VNet. |
| 5 · Internet match | **done** | MK8D completed a match with two Ryujinx installations over the internet. |
| 6 · Broader title coverage | **done on hardware** | Mario Kart 8 Deluxe, Splatoon 2 and Splatoon 3 have completed LAN play over ZeroTier with Switch/Ryujinx peers. Other whitelisted LAN titles are ready for community compatibility reports. |
| 7 · Release controls | **implemented** | The bundle includes a real Ultrahand-compatible `.ovl` with live network-ID entry/selection, status, sysmodule/BSD/NIFM switches and opt-in diagnostics. |

### What stood between "online" and "carries a packet"

Six defects, and the node reported itself healthy through every one of them.
`status.txt` said `online yes`, `netstatus ok`, address assigned -- while
nothing whatsoever could reach it.

| | Symptom | Cause |
|---|---|---|
| 1 | `am`, later `hid`, aborting `2001-0132` at boot | 4.9 MB resident against ~5 MB of total headroom for custom sysmodules. `sizeof(Switch)` alone was 2.15 MB. |
| 2 | Node created, then `std::abort` | `Node::Node` does a single 2.16 MB `::malloc`; the arena had been cut to 1 MB. |
| 3 | Every peer stuck at `latency -1`; config refetched every 61 s | `NowMs()` ran backwards by up to 999 ms, once per second. Every `rateGate*` in `Peer.hpp` tests `now - _last >= LIMIT`, so credential exchange never passed the gate. |
| 4 | `rx frames 0`; "Destination Host Unreachable" | Never called `ZT_Node_multicastSubscribe` at all. |
| 5 | Still `rx frames 0` after subscribing | Subscribed to `ADI 0`. IPv4 ARP uses `ADI = the address being resolved` -- a different group entirely. |
| 6 | First outbound frame ever sent: Data Abort, `FAR == SP` | `Multicaster.cpp:222` puts a 30,128-byte `OutboundMulticast` on the stack. The node thread had 128 KB. |

Bugs 3 and 6 are the ones worth carrying forward, because both were self-
inflicted and both survived confident reasoning. A clock this README's own
comment described as "monotonic-ish" was not monotonic in any sense; and a
stack halved during memory optimisation was sized against a measurement that
only covered code paths which had ever executed -- the outbound path had never
run once.

The general lesson, which cost about a dozen boot cycles: a ZeroTier node that
says it is online has proved only that it can talk to a root. It says nothing
about whether two members can exchange a single frame.

The core now builds with devkitA64 itself. What that took, beyond the three
patches below, was four things a generic aarch64 Linux cross-build could never
have surfaced — because it defines `__linux__`, and every one of these is a
platform assumption hiding behind that:

- **`-D__UNIX_LIKE__` is mandatory.** `node/Mutex.hpp` defines `class Mutex`
  only under `__UNIX_LIKE__` or `__WINDOWS__`, and `Constants.hpp` derives that
  from `__linux__`/`__APPLE__`/the BSDs. On Horizon, ZeroTier's most-used type
  simply did not exist. newlib supplies the `pthread_mutex_*` functions the
  header wants, so the flag is honest rather than a workaround.
- **`node/` reaches into `osdep/`.** `Bond.hpp` includes `osdep/Binder.hpp`,
  which needs `ifaddrs.h`. Replaced with forward declarations plus the four
  `node/` headers it was quietly handing down to the rest of the tree.
- **Three `OSUtils` functions**, previously arriving through that same
  transitive include, now live in `compat/ZtOSUtilsSwitch.cpp` — the real ones
  are implemented in `osdep/OSUtils.cpp`, which a sysmodule does not build.
- **`endian.h` and `sys/uio.h`** do not exist in newlib. Both shimmed in
  `compat/`; `make -f zt-core.mk probe` reports any others.

Measured with devkitA64: **651 KB .text, 523 KB .bss, 1.15 MB total** — within
3% of the generic cross-build estimate.

Verified before hardware, and still true:

- the whole ZeroTier core cross-compiles clean for aarch64 (generic GCC 13.3,
  `-march=armv8-a+crypto`, `-fexceptions -fno-rtti`);
- the packet shim builds and passes its tests on the host and cross-compiles
  for aarch64 with `-Wconversion` clean;
- the external symbol surface the core needs is now **libc plus exactly one
  function we provide**.

---

## Layout

```
source/net/          the virtual network shim -- ARP, IPv4, UDP, ICMP.
                     No Horizon dependency: this is the part that can be
                     tested without a console, and it is where the bugs live.
source/zt_port.*     the six ZeroTier callbacks, the wire socket, state on SD
source/main.cpp      sysmodule entry, fixed allocator, service bring-up
overlay/             Ultrahand-compatible UI
compat/prometheus/   stubs that replace ext/prometheus-cpp-lite (see below)
patches/             three source patches ZeroTierOne needs for Horizon
tests/               host tests for the shim, and reference.py
zt-core.mk           builds node/ into libztcore.a
res/app.json         NPDM descriptor
```

---

## Build

### 1. The ZeroTier core

```sh
git clone https://github.com/zerotier/ZeroTierOne.git ../ZeroTierOne
cd ../ZeroTierOne
git checkout 899352e38405968516bb12a770f0ac02f6058fa8   # what the patches apply against
git apply ../sys-zerotier/patches/0001-horizon-port.patch
cd -

source /opt/devkitpro/switchvars.sh    # or export DEVKITPRO=/opt/devkitpro
# Overlay build dependencies: switch-curl, switch-zlib, switch-mbedtls
make zt-core
```

Expected: `build-ztcore/libztcore.a`, 32 objects — **651 KB of .text and
523 KB of .bss**, 1.15 MB in total. That is the entire static cost of having
ZeroTier in the module, against the ~16 MB every custom sysmodule shares.

(Most of that .bss is a single 468 KB static in `NetworkConfig.o` plus the
core's 64 KB CSPRNG buffer in `Utils.o`. Both are one-time, not per-peer.)

### 2. The sysmodule

```sh
make
```

The resulting `sys-zerotier.nsp` is the sysmodule ExeFS image.

For an SD-root package containing only the sysmodule, run:

```sh
make bundle
```

This writes `dist/sys-zerotier.zip`. The analyzed Splatoon 3 startup workaround
under `exefs/` is intentionally excluded; see `SPLATOON3_BOOT_FIX.md` if it is
wanted for a separate manual test.

The ZIP installs `sys-zerotier.ovl` in `/switch/.overlays/`. Open it from
Ultrahand/Tesla to read live status, enter a 16-digit network ID with the
controller, or select a saved network. Network changes are applied while the
console is running: the sysmodule notices `networks.ini` within one second,
leaves the old network and joins the new one on its node thread. Do this before
opening a game's LAN room so it creates fresh virtual sockets.

The overlay is unloaded when closed, so it does not add resident game memory.
No same-named Ultrahand package is installed because the real overlay supersedes
it and keeping both interfaces is needlessly confusing. The missing overlay was
ultimately traced to absent embedded NACP metadata, not a package-name override.

Saved networks live in `/config/sys-zerotier/networks.ini`, outside the release
archive so an update never overwrites them:

```ini
[Friends]
nwid = 0123456789abcdef

[Tournament]
nwid = fedcba9876543210
```

Selecting a saved network records its friendly name in an internal section of
`networks.ini`; the sysmodule resolves the corresponding `nwid` itself and
switches live. A single saved network is selected automatically. A direct
`nwid = 0123456789abcdef` in `config.ini` remains supported as a fallback.

Fresh installs include `boot2.flag` and generate a sectioned
`/config/sys-zerotier/config.ini` with BSD and NIFM enabled, so the sysmodule
and both MITMs start by default. Detailed packet/service logging is disabled. Existing flat
configs remain accepted; when both formats contain a key, the last assignment
wins so Ultrahand can migrate an existing install safely.

`boot.log`, `status.txt`, and the compact `uplink.log` always remain active.
Turn on **Detailed BSD/NIFM logs** only while reproducing a compatibility issue;
the larger log rings are allocated only in that mode and are released from the
normal resident-memory budget otherwise.

### 3. The tests, which need no toolchain at all

```sh
make -C tests          # build and run, with ASan and UBSan on
make -C tests cross    # also compile the shim for aarch64
python3 tests/reference.py   # regenerate the reference packet bytes
```

---

## The three patches

`patches/0001-horizon-port.patch` is small on purpose — 46 added lines across
three files, all behind `#ifdef __SWITCH__`, so it stays easy to rebase when
ZeroTier moves.

1. **`Utils.cpp` — CPU feature detection.** The core calls
   `getauxval(AT_HWCAP)`, and Horizon has no auxiliary vector. The Tegra X1's
   Cortex-A57 implements the ARMv8 Crypto Extensions unconditionally, so the
   answer is a constant. Without this you get software AES on a CPU core shared
   with the whole operating system.

2. **`Utils.cpp` — the CSPRNG.** `getSecureRandom()` reads `/dev/urandom`.
   Replaced with a call to `ztnx_secure_random_fill()`, which the port layer
   implements over `csrng`. ZeroTier's Salsa20 whitening is kept. The fallback
   seeding in that function is `time(0)` plus three heap addresses, which would
   produce guessable node identities — it must not be the only entropy.

3. **`Switch.cpp` and `PacketMultiplexer.cpp` — thread-per-frame.** Upstream
   spawns a *detached `std::thread` per frame* on two paths (IPv6 NDP emulation,
   and frames addressed to the node itself), and a pool of post-decode ingestion
   threads. None of that is viable in a sysmodule. The port is IPv4-only and
   never generates self-addressed frames, so both paths are compiled out.

Patch 3 is the one worth knowing about even if you never build this: it is on
the outbound path, and it would have been discovered the hard way.

---

## Why `compat/prometheus/`

`node/Metrics.hpp` includes `<prometheus/simpleapi.h>` unconditionally — the
`ZT_NO_PEER_METRICS` switch only removes the *per-peer* metrics, not the
dependency. The bundled prometheus-cpp-lite uses `dynamic_cast`, so the core
will not build with `-fno-rtti`, and even with RTTI it drags a registry of
`std::map<std::string,std::string>` label sets into a module nothing will ever
scrape.

Putting `compat/` first on the include path replaces the library with counters
that are structurally identical and cost nothing. The ~78 `Metrics::x++` sites
in `node/` keep compiling and stay readable in a debugger. To get real metrics
back, delete the directory and build with RTTI.

## Exceptions

The core throws — 49 sites, all caught by 64 `catch (...)` blocks inside the
library, and every `ZT_Node_*` entry point in `Node.cpp` is wrapped and converts
a throw into `ZT_RESULT_FATAL_ERROR_INTERNAL`. So `libztcore.a` is built with
`-fexceptions` while the sysmodule itself stays `-fno-exceptions`; nothing
unwinds across the boundary. Do not try to build the core with `-fno-exceptions`
— it does not compile, and papering over it would mean patching 49 sites.

## Licensing

- ZeroTier `node/` — MPL-2.0. Fine here.
- **libzt — BSL-1.1. Do not vendor it.** Not an open-source licence, and
  outright incompatible if an `ldn_mitm` fork is ever folded in.
- Atmosphère / libstratosphere — GPLv2 with linking exceptions.
- The shim and port layer in this repository — same terms as whatever the
  project settles on; nothing here is derived from a copyleft source yet.
