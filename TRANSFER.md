# sys-zerotier development transfer

Use `sys-zerotier-dev-transfer-2026-08-29.tgz`, not the old hidden
`.szt-transfer.tgz`. The old archive was made on August 23, contains no
`handoff.md`, and predates the MITM and Splatoon work.

The earlier `sys-zerotier-dev-transfer-2026-08-28.tgz` predates the lifecycle
fix and is retained only as an older snapshot.

The new archive is a source-oriented snapshot of the current working tree. It
contains:

- the current project sources, MITM sources, build files, documentation,
  tests, tools, and updated `handoff.md`;
- the latest hardware logs, fatal report, DTI2 thread dump, and screenshot;
- the complete ZeroTierOne source tree at commit
  `899352e38405968516bb12a770f0ac02f6058fa8`, including all local Switch
  modifications;
- the complete Atmosphere-libs source tree at commit
  `edb2cca26f658ef7863eb4c349399d273aab4fae`, including the three locally
  modified libstratosphere tracing/forwarding files; and
- the existing `dist` packages as reference artifacts.

It intentionally excludes Git histories, object files, dependency build and
library outputs, precompiled headers, the 31 MiB ELF, the Splatoon research
cache, and the currently excluded boot-fix ExeFS/NSP. Those account for nearly
all of the 13 GiB project directory and are reproducible or no longer needed.

## On the new computer

1. Extract the archive and enter `sys-zerotier`.
2. Install devkitPro/devkitA64, libnx, and the normal Atmosphere sysmodule build
   prerequisites.
3. Read `handoff.md`, beginning with the August 28 transfer/crash section.
4. Build the bundled Atmosphere-libs/libstratosphere when required by the
   project Makefile. Its generated archive is deliberately not transferred.
5. Run `make -j2` for the sysmodule and
   `ASAN_OPTIONS=detect_leaks=0 ./tests/test_vnet` for the host VNet suite.

Important: the 2026-08-29 source and package include the BSD transfer-memory
lifecycle correction described at the top of `handoff.md`. The frozen
synthetic NIFM CreateRequest experiment was removed before this build. The next
step is hardware validation; specifically preserve `bsd.log`, `nifm.log`, and
any fatal report from Splatoon Shoal initialization.

Console ZeroTier identity is not part of this development archive. Preserve
`/atmosphere/contents/4200000000005A54/zt/identity.secret` separately on the
Switch SD card. Do not copy the same identity to a second console; each console
needs a unique identity. The packer also excludes every `*.secret` and
`*token.secret` file found in the project tree.
