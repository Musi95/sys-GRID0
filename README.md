# sys-zerotier

A very work in progress port of ZeroTier to the Nintendo Switch as a sysmodule, very AI assisted in the making, yet extremely functional with better results than i had hoped. Get the latest release from the releases page, or read the build instructions in build.md

## where sys-zerotier is at right now

The whole point of this was to make native LAN play work over the internet
without needing a PC relay or another console sitting on the same network. I
have reached that point, and it has worked in actual matches.

Heres what it does pretty much:

ZeroTier runs as a Horizon sysmodule, joins a network, keeps its identity and managed IP, and survives normal sleep and wake.

For Lan compatible games, theres two MITM's bundled with this sysmodule, one for bsd related requests and one for nifm, in actual english, these grab the lan packets, and tell your game
"Hey broadcast over the ZeroTier ip!". Currently I have tested Mario Kart 8 Deluxe, Splatoon 2 and Splatoon 3 which have all managed LAN play over
ZeroTier with Switch and Ryujinx players. Theres a whitelist coded in so that the sysmodule only picks up lan compatible games, however I dont know
if they all work... which brings me to the next point.


 There is a Ultrahand overlay ui. It shows the current status, lets a
  user pick a saved network or type the entire 16-digit network ID, applies a
  network change without rebooting, and has switches for the sysmodule, BSD,
  NIFM and detailed logging, these logs get placed in `/config/sys-zerotier` and 
  should a game crash upon trying to initialize lan, can be combined with the
  crash report and dump inside `/atmosphere/crash_reports`. (therefore im leaving
  other game tests to anyone who uses this, and will fix whenever i can. Though
  being truthful, working on this has been so fun I may just continue fixing games
  myself.)

  
   Saved networks live in `/config/sys-zerotier/networks.ini`, so an update does not
  wipe them out.



## current limitations

There are still things left to do. Games that only support local wireless mode
need an ldn MITM before they can use ZeroTier. The LAN whitelist covers the
games tested so far, but more compatibility testing is welcome. If something
breaks, include `status.txt`, `uplink.log`, and (when enabled) `bsd.log` and
`nifm.log` with the report so it can actually be investigated.

## the important folders

```text
source/                 sysmodule, ZeroTier port and LAN MITMs
source/net/             virtual IPv4 network and packet handling
overlay/                Ultrahand/Tesla overlay
compat/                 Horizon and dependency compatibility shims
patches/                small Horizon-specific ZeroTier patch
tests/                  host-side VNet tests and packet reference data
Atmosphere-libs/        pinned Atmosphère dependency submodule
ZeroTierOne/            pinned ZeroTier dependency submodule
```

For prerequisites, submodules, build outputs, installation, and tests, see
[build.md](build.md).

## licensing

The ZeroTier `node/` sources are MPL-2.0. Atmosphère/libstratosphere and the
other bundled dependencies retain their upstream licenses. The port, shim and
overlay code should be distributed with the license terms of the project as it
is released; do not add ZeroTier's separately licensed `libzt` component.
