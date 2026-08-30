# Splatoon 3 startup companion (retired test artifact)

> **Do not install this ExeFS replacement.** Hardware testing showed that it
> crashes Splatoon 3 during startup. It is retained in `exefs/` only for binary
> analysis and is excluded from `dist/sys-zerotier.zip`.

The project contains two separate Atmosphere program artifacts:

- `4200000000005A54` is sys-zerotier.
- `0100C2500FC20000` is an optional Splatoon 3 ExeFS replacement supplied for
  analysis. It works around the network-enabled startup loading screen.

Only sys-zerotier is shipped in the default SD-root package. The retired test
artifact cannot be part of the sysmodule executable.
Atmosphere loads an ExeFS replacement in the address space of the program id
whose `contents` directory contains it; the Splatoon hook therefore has to stay
under Splatoon 3's program id.

## What the supplied module does

`subsdk9` is a valid NSO built with exlaunch. Its imported symbols include:

```text
nn::nifm::IsNetworkAvailable()
```

The replacement at NSO text offset `0x5250` is equivalent to:

```cpp
bool IsNetworkAvailableOnceFalse() {
    static unsigned calls;
    if (calls++ == 0)
        return false;
    return nn::nifm::IsNetworkAvailable();
}
```

In other words, only the first availability check is forced offline. Every
later check uses Nintendo's original implementation. This automates the known
airplane-mode startup workaround without leaving LAN mode offline.

The hook is symbol-based rather than an absolute patch into Splatoon 3's main
executable. That should make it less sensitive to game updates, but it still
needs hardware validation with each materially different game/firmware build.

Binary identity of the analyzed input:

```text
main.npdm  SHA-256 34882d6694fe243e8285c3b556c11c2525c1c8a6a5e98e1d2c9d421bfd45c8a5
subsdk9    SHA-256 9e3e94758adafea2e7a43bae203d18554892fccba4264e442aab298a04f8a1e9
subsdk9    NSO build id aa0ef4061b0d776c1ad8ee3cd86c9cc8ed530095
```

The supplied files contain no source, author, license, or provenance metadata.
They are included as a user-supplied optional test component, not as original
sys-zerotier code. Obtain the author's redistribution permission or replace
them with a source-built equivalent before making a public release.

## Removing an earlier test installation

If this artifact was installed previously, rename
`/atmosphere/contents/0100C2500FC20000` to a `.bak` directory (or remove only
its `exefs/main.npdm` and `exefs/subsdk9`) before testing. Do not touch
`/atmosphere/contents/4200000000005A54`: that is sys-zerotier and may contain
the console's persistent ZeroTier identity.

The Splatoon files replace `main.npdm` and occupy the `subsdk9` slot. They can
conflict with another Splatoon 3 ExeFS mod that replaces either file. Merge the
mods at source level instead of installing two competing replacements.

Use the airplane-mode startup workaround instead. The NIFM shim now reports
offline while the ZeroTier wire is unreachable and switches to the
Ryujinx-compatible Available state only after the uplink is proven live.
