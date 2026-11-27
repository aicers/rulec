#!/usr/bin/env python3
"""Creates the Apache-2.0 public protocol-probes.pcap, without network I/O.

All addresses are private or documentation ranges; all bytes are synthetic.
No signature definitions or third-party traffic are embedded. Regeneration
must reproduce the SHA-256 recorded in pcaps.json.
"""
from pathlib import Path
import socket
import struct


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def packet(src, dst, transport, proto):
    src, dst = socket.inet_aton(src), socket.inet_aton(dst)
    pseudo = src + dst + struct.pack("!BBH", 0, proto, len(transport))
    offset = 16 if proto == 6 else 6
    check = checksum(pseudo + transport)
    transport = transport[:offset] + struct.pack("!H", check) + transport[offset + 2:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 1, 0, 64, proto, 0, src, dst)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return bytes.fromhex("0200000000020200000000010800") + header + transport


def tcp_flow(client, server, port, request, response):
    packets = []
    def send(src, dst, sport, dport, seq, ack, flags, payload=b""):
        tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
        packets.append(packet(src, dst, tcp, 6))
    send(client, server, 40000, port, 1000, 0, 2)
    send(server, client, port, 40000, 2000, 1001, 18)
    send(client, server, 40000, port, 1001, 2001, 16)
    send(client, server, 40000, port, 1001, 2001, 24, request)
    send(server, client, port, 40000, 2001, 1001 + len(request), 24, response)
    send(client, server, 40000, port, 1001 + len(request), 2001 + len(response), 16)
    send(server, client, port, 40000, 2001 + len(response), 1001 + len(request), 17)
    send(client, server, 40000, port, 1001 + len(request), 2002 + len(response), 17)
    send(server, client, port, 40000, 2002 + len(response), 1002 + len(request), 16)
    return packets


def generate():
    request = b"GET / HTTP/1.1\r\nHost: example.invalid\r\nUser-Agent: curl53\r\nConnection: close\r\n\r\n"
    body = b"Burp proxy error: synthetic public regression probe\n"
    response = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
    packets = tcp_flow("10.0.0.1", "198.51.100.2", 80, request, response)
    # This deliberately nested but parseable software string exercises server-side
    # software matching, including signatures looking for a full banner in it.
    packets += tcp_flow("198.51.100.3", "10.0.0.2", 22, b"SSH-2.0-rulec_probe\r\n", b"SSH-2.0-SSH-2.0-OpenSSH_9.9\r\n")
    question = b"\x07example\x03top\x00\x00\x01\x00\x01"
    query = struct.pack("!HHHHHH", 42, 0x100, 1, 0, 0, 0) + question
    answer = struct.pack("!HHHHHH", 42, 0x8180, 1, 1, 0, 0) + question + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01"
    for src, dst, sport, dport, payload in [("10.0.0.3", "198.51.100.53", 40000, 53, query), ("198.51.100.53", "10.0.0.3", 53, 40000, answer)]:
        packets.append(packet(src, dst, struct.pack("!HHHH", sport, dport, len(payload) + 8, 0) + payload, 17))
    out = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for n, data in enumerate(packets):
        out.extend(struct.pack("<IIII", 1704067200, n * 10000, len(data), len(data)))
        out.extend(data)
    return bytes(out)


if __name__ == "__main__":
    Path(__file__).with_name("pcaps").joinpath("protocol-probes.pcap").write_bytes(generate())
