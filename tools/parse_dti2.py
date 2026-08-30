#!/usr/bin/env python3
"""Parse Atmosphere creport DTI2 thread-info dumps.

The on-disk order mirrors ThreadInfo::DumpBinary in Atmosphere's
stratosphere/creport/source/creport_threads.cpp. Atmosphere currently writes
``m_stack_trace_size`` bytes (not qwords) for the final trace payload, so this
parser preserves that producer quirk while reporting the complete context,
TLS, name, and stack snapshot from every record.
"""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path


MAGIC = b"DTI2"
CONTEXT_SIZE = 0x320
TLS_SIZE = 0x100
NAME_SIZE = 0x21
STACK_DUMP_SIZE = 0x100


@dataclass
class Thread:
    tid: int
    registers: tuple[int, ...]
    fp: int
    lr: int
    sp: int
    pc: int
    pstate: int
    tpidr: int
    tls_address: int
    tls: bytes
    name: str
    stack_bottom: int
    stack_top: int
    stack_dump_base: int
    stack_dump: bytes
    trace_count: int
    trace_fragment: bytes


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise ValueError(
                f"truncated at 0x{self.offset:x}: need 0x{size:x} bytes, "
                f"only 0x{len(self.data) - self.offset:x} remain"
            )
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]


def parse(path: Path) -> tuple[int, list[Thread], int]:
    reader = Reader(path.read_bytes())
    magic, count, crashed_tid = struct.unpack("<4sIQ", reader.take(16))
    if magic != MAGIC:
        raise ValueError(f"bad magic {magic!r}; expected {MAGIC!r}")
    if count > 0x60:
        raise ValueError(f"invalid thread count {count} (Atmosphere maximum is 96)")

    threads: list[Thread] = []
    for _ in range(count):
        tid = reader.u64()
        context = reader.take(CONTEXT_SIZE)
        gp = struct.unpack_from("<29Q", context, 0)
        fp, lr, sp, pc = struct.unpack_from("<4Q", context, 29 * 8)
        pstate = struct.unpack_from("<I", context, 33 * 8)[0]
        tpidr = struct.unpack_from("<Q", context, CONTEXT_SIZE - 8)[0]
        tls_address = reader.u64()
        tls = reader.take(TLS_SIZE)
        raw_name = reader.take(NAME_SIZE)
        name = raw_name.split(b"\0", 1)[0].decode("utf-8", "replace")
        stack_bottom = reader.u64()
        stack_top = reader.u64()
        stack_dump_base = reader.u64()
        stack_dump = reader.take(STACK_DUMP_SIZE)
        trace_count = reader.u64()
        if trace_count > 0x20:
            raise ValueError(f"thread {tid:x} has invalid trace count {trace_count}")
        trace_fragment = reader.take(trace_count)
        threads.append(
            Thread(
                tid, gp, fp, lr, sp, pc, pstate, tpidr,
                tls_address, tls, name, stack_bottom, stack_top,
                stack_dump_base, stack_dump, trace_count, trace_fragment,
            )
        )

    if reader.offset != len(reader.data):
        raise ValueError(
            f"parsed 0x{reader.offset:x} bytes but file is 0x{len(reader.data):x}"
        )
    return crashed_tid, threads, len(reader.data)


def hex_rows(data: bytes, base: int) -> list[str]:
    return [
        f"  {base + off:016x}  " + " ".join(f"{b:02x}" for b in data[off:off + 16])
        for off in range(0, len(data), 16)
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path)
    parser.add_argument("--all", action="store_true", help="show registers for every thread")
    args = parser.parse_args()

    crashed_tid, threads, size = parse(args.dump)
    print(f"DTI2 size={size} threads={len(threads)} crashed_tid=0x{crashed_tid:x}")
    for index, thread in enumerate(threads):
        marker = "*" if thread.tid == crashed_tid else " "
        print(
            f"{marker}[{index:02d}] tid=0x{thread.tid:x} name={thread.name or '-':<24} "
            f"pc=0x{thread.pc:016x} lr=0x{thread.lr:016x} "
            f"sp=0x{thread.sp:016x} trace_count={thread.trace_count}"
        )
        if args.all or thread.tid == crashed_tid:
            for reg, value in enumerate(thread.registers):
                print(f"    X[{reg:02d}]=0x{value:016x}")
            print(
                f"    FP=0x{thread.fp:016x} LR=0x{thread.lr:016x} "
                f"SP=0x{thread.sp:016x} PC=0x{thread.pc:016x} "
                f"PSTATE=0x{thread.pstate:08x} TPIDR=0x{thread.tpidr:016x}"
            )
            print(
                f"    stack=0x{thread.stack_bottom:016x}-0x{thread.stack_top:016x} "
                f"dump_base=0x{thread.stack_dump_base:016x} "
                f"tls=0x{thread.tls_address:016x}"
            )
            print("    TLS dump:")
            print("\n".join(hex_rows(thread.tls, thread.tls_address)))
            print("    Stack dump:")
            print("\n".join(hex_rows(thread.stack_dump, thread.stack_dump_base)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
