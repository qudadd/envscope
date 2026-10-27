"""UDP STUN probe derived from claude-switcher, rewritten against RFC 8489.

Copyright (c) 2026 Claude Switcher Contributors; EnvScope contributors. MIT.
Native socket measurements do not establish browser ICE behaviour.
"""
import ipaddress
import os
import socket
import struct
import zlib

COOKIE = 0x2112A442


def binding_request(transaction=None):
    transaction = transaction if transaction is not None else os.urandom(12)
    if len(transaction) != 12:
        raise ValueError("invalid transaction length")
    return struct.pack("!HHI", 0x0001, 0, COOKIE) + transaction, transaction


def parse_binding_response(packet, transaction):
    if len(transaction) != 12 or len(packet) < 20:
        raise ValueError("truncated header")
    message_type, length, cookie = struct.unpack("!HHI", packet[:8])
    if message_type != 0x0101 or cookie != COOKIE or packet[8:20] != transaction:
        raise ValueError("response identity mismatch")
    if length % 4 or len(packet) != 20 + length:
        raise ValueError("invalid message length")
    position, mapped, xor_mapped = 20, None, None
    while position < len(packet):
        if position + 4 > len(packet):
            raise ValueError("truncated attribute header")
        kind, size = struct.unpack("!HH", packet[position:position + 4])
        end = position + 4 + size
        padded_end = end + ((-size) % 4)
        if end > len(packet) or padded_end > len(packet):
            raise ValueError("truncated attribute")
        value = packet[position + 4:end]
        if kind == 0x8028:
            if size != 4 or padded_end != len(packet):
                raise ValueError("invalid fingerprint placement")
            expected = (zlib.crc32(packet[:position]) & 0xFFFFFFFF) ^ 0x5354554E
            if struct.unpack("!I", value)[0] != expected:
                raise ValueError("fingerprint mismatch")
        if kind in (0x0001, 0x0020):
            if len(value) < 4 or value[0] != 0:
                raise ValueError("invalid address attribute")
            family = value[1]
            address_size = {1: 4, 2: 16}.get(family)
            if address_size is None or size != 4 + address_size:
                raise ValueError("invalid address family or length")
            address = value[4:]
            if kind == 0x0020:
                key = struct.pack("!I", COOKIE) + transaction
                address = bytes(a ^ b for a, b in zip(address, key))
            decoded = str(ipaddress.ip_address(address))
            if kind == 0x0020:
                xor_mapped = decoded
            elif mapped is None:
                mapped = decoded
        position = padded_end
    if xor_mapped or mapped:
        return xor_mapped or mapped
    raise ValueError("no mapped address")


def query(host, port, family=4, timeout=2):
    af = socket.AF_INET if family == 4 else socket.AF_INET6
    destinations = socket.getaddrinfo(host, port, af, socket.SOCK_DGRAM)
    if not destinations:
        raise OSError("no STUN destination")
    request, transaction = binding_request()
    with socket.socket(af, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        # A connected UDP socket filters replies from a different sender.
        sock.connect(destinations[0][4])
        sock.send(request)
        packet = sock.recv(4096)
    return parse_binding_response(packet, transaction)
