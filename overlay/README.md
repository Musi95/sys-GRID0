# sys-zerotier overlay

The release ZIP installs the real overlay at:

`/switch/.overlays/sys-zerotier.ovl`

Open Ultrahand/Tesla and select **sys-zerotier**. The overlay shows connection
state and the managed IP, lets you select a saved network, and includes a
controller-driven editor for entering a new 16-hex-digit ZeroTier network ID.
The editor behaves like a compact hex text field rather than sixteen separate
spinners. With a USB/Bluetooth keyboard connected, type the complete ID using
0-9/A-F, Backspace to erase, and Enter to validate, save, and connect. The
controller fallback uses the D-pad to select a hexadecimal key, A to type it,
X to erase the previous digit, Y to clear the field, and + to validate, save,
and connect. Typing the first digit replaces the currently displayed ID.

Back from the network editor returns to sys-zerotier. Back from sys-zerotier's
root page returns to Ultrahand's overlay list and terminates this overlay,
preventing Launch Recall from reopening a hidden sys-zerotier page.

Network changes are live. The running sysmodule notices the atomic
`networks.ini` update, leaves the old ZeroTier network, and joins the new one
without rebooting. Change networks outside an active match so the game opens
fresh virtual sockets on the new LAN.

The old same-named `package.ini` fallback was removed because the real overlay
supersedes it. Researching Ultrahand's scanner showed that the package was not
the root cause of the missing overlay; the absent embedded NACP asset was.

The overlay Makefile must pass `--nacp=sys-zerotier.nacp` to `elf2nro`.
Ultrahand reads the embedded NACP title/version while enumerating overlays and
silently skips an otherwise valid `.ovl` when that asset is absent. Appending
the `ULTR` signature alone is not sufficient.

## Saved networks

The sysmodule creates `/config/sys-zerotier/networks.ini` once and updates
never replace it. Add a friendly section for each network:

```ini
[Friends]
nwid = 0123456789abcdef

[Tournament]
nwid = fedcba9876543210
```

The **Saved network** picker shows the section names and writes its choice to a
small internal `[sys-zerotier]` section in this same file. The picker hides
that internal section. If the catalog contains only one valid network,
sys-zerotier uses it automatically even before a choice has been stored.

Saved-network selection is applied live. The sysmodule, BSD, NIFM, and
diagnostic toggles are boot-time settings. A live MITM service cannot be safely
unregistered while a title owns sessions.

Fresh installs enable the sysmodule, BSD bridge, and NIFM bridge by default.
The release includes `boot2.flag`, and missing `bsd_mitm` / `nifm_mitm` keys
default to enabled. Existing explicit disabled settings are preserved during
an update.

Detailed BSD/NIFM logging is off by default. Enable it only for reproducing a
compatibility problem, reboot, collect `bsd.log` and `nifm.log`, then disable
it again. `boot.log`, `status.txt`, and `uplink.log` remain active for normal
health checks.
