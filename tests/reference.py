#!/usr/bin/env python3
"""
Independent reference packets for tests/test_vnet.cpp.

Written from the RFCs with Python's own struct/socket helpers, deliberately
not sharing any code with the C++ under test, so that a matching byte string
means two implementations agree rather than one implementation being
self-consistent.

    python3 tests/reference.py
"""
import struct
import socket


def ones_complement_sum(data: bytes, initial: int = 0) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = initial + sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


OUR_MAC = bytes.fromhex("02abcd001122")
PEER_MAC = bytes.fromhex("02abcd003344")
OUR_IP = socket.inet_aton("10.147.20.50")
PEER_IP = socket.inet_aton("10.147.20.51")
BCAST_IP = socket.inet_aton("10.147.20.255")


def arp_reply() -> bytes:
    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        + OUR_MAC + OUR_IP
        + PEER_MAC + PEER_IP
    )


def ipv4(src: bytes, dst: bytes, proto: int, payload: bytes, ident: int) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, src, dst
    )
    csum = ones_complement_sum(header)
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    return header + payload


def udp(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    body = struct.pack("!HHHH", sport, dport, length, 0) + payload
    pseudo = struct.pack("!4s4sBBH", src, dst, 0, 17, length)
    csum = ones_complement_sum(pseudo + body)
    if csum == 0:
        csum = 0xFFFF
    return body[:6] + struct.pack("!H", csum) + body[8:]


def main() -> None:
    print("arp reply           ", arp_reply().hex())

    payload = b"SCAN"
    datagram = udp(OUR_IP, BCAST_IP, 11451, 11451, payload)
    packet = ipv4(OUR_IP, BCAST_IP, 17, datagram, ident=1)
    print("udp broadcast (ip)  ", packet[:20].hex())
    print("udp broadcast (udp) ", packet[20:28].hex())
    print("udp broadcast (data)", packet[28:].hex())
    print("udp broadcast (all) ", packet.hex())


if __name__ == "__main__":
    main()
