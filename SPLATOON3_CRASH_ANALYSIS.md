# Splatoon 3 crash analysis — 2026-08-25 capture

Artifacts analyzed from `logs and bin/`:

- `01787708226_0100c2500fc20000.log`
- `01787708226_0100c2500fc20000_thread_info.bin`
- `01787708226_0100c2500fc20000.jpg`
- `boot.log`, `bsd.log`, `uplink.log`, `status.txt`, `peers.txt`, and
  `config.ini`

## Follow-up capture — 2026-08-26

The next hardware capture reproduced every meaningful crash value: result,
thread, PC/LR, complete stack, dying message, module ids, and 39-thread count.
It again registered BSD successfully and stopped before command 2. Leaving
command 1 undeclared for raw MITM forwarding therefore did not move the crash
boundary and disproved the original command-1-only diagnosis below.

The remaining boundary is BSD client-pool construction: monitoring and the
control/domain operations that clone the sessions used by nnSdk. The new
compatibility build consequently restores the working `0x100` domain-object
capacity, raises BSD sessions from 16 to 32, and declares the nnSdk/reference
StartMonitoring ABI `(Out<s32>, u64)` with synchronous result logging. It also
logs the actual BSD token returned by RegisterClient separately from the OS
process id. These changes add exactly 84 KiB of `.bss`.

## Finding

This is not an out-of-memory crash and it is not a ZeroTier core crash. It is
the same application-side nnSdk assertion family seen during the earlier BSD
registration failures. Splatoon reaches a successful `RegisterClient`, opens
the monitoring session, and then aborts before the typed BSD command-1 handler
can log its first instruction. The remaining typed `StartMonitoring` ABI guess
is therefore the failure boundary.

This was the diagnosis for the first capture. The follow-up above showed that
raw-forwarding command 1 was insufficient and shifted the investigation to the
session/domain setup immediately following registration.

## Evidence by artifact

### Fatal report and thread capture

- Result `0xD401` / `2001-0106`, type `User Break`.
- Program `0100c2500fc20000`, process `0x8d` (Splatoon 3).
- Crashed thread: `enl::TaskThread`.
- PC is nnSdk module `[574284b4] + 0x17574c`; LR and the first frames are in
  the same module around `+0x9bd78` through `+0x9bf08`.
- This is an explicit userspace assertion path, not a data abort, stack fault,
  or kernel resource-limit exception.
- The `DTI2` thread-info binary contains the matching 39-thread capture. Its
  crashed-thread registers, thread names, stack/TLS material, and three module
  build IDs are already rendered in the accompanying Atmosphere text report;
  it does not point to a second independent crash.

### `bsd.log`

- `ShouldMitm` selects the real Splatoon session and ignores the dummy session
  as intended.
- `RegisterClient ENTER tmem 4608 KB sb_eff 4` is followed by the decoded pid
  `0x8d`, proving command 0 passed the sf metadata validator and reached our
  implementation.
- Two later BSD sessions are accepted.
- There is no `StartMonitoring ENTER`, even though the tested build contained
  that synchronous log at the first line of the handler. A buffered-log loss
  cannot explain this absence.
- No socket command is reached before the game aborts.

### `boot.log`

- The sysmodule initializes normally and both MITMs register.
- Splatoon is correctly recognized and its NIFM child service is created.
- The module uses 2,932 KiB of its 5,052 KiB pool.
- After node construction the arena still has 544 KiB free with a 500 KiB
  largest block. There is no allocator failure or resource-limit exhaustion.

### `uplink.log` and `status.txt`

- The radio transition temporarily produces `ENETUNREACH`; the bounded pause
  and exponential probe path activates instead of spinning or leaking.
- The wire resumes after 53,159 ms and later handles a `POLLHUP` by pausing
  cleanly again.
- Final state is online at managed address `10.147.17.243/24` with wire traffic
  in both directions and no game frames received before the abort.
- This connectivity interruption overlaps the airplane/Wi-Fi workflow, but
  the sysmodule survives and recovers. It is not the fatal-reporting process.

### Screenshot

The game is on the Shoal's `Preparing LAN play...` transition. This places the
failure after initial game loading and immediately at LAN activation, matching
the BSD initialization boundary in the logs.

## Expected next-run difference

The compatibility build should log `StartMonitoring ENTER`, then an `EXIT`
containing both the Horizon result and BSD errno. If `ENTER` is absent, the
nnSdk request metadata does not match the reference ABI. If `EXIT` succeeds but
the game still aborts before command 2, session/domain cloning remains the
failure boundary. Full success is progression into `Socket`, `Bind`, and
`SendTo`.
