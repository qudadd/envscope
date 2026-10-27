import ipaddress
import socket
import struct
import threading
import unittest
import zlib

from envscope.stun import COOKIE, binding_request, parse_binding_response, query

TXN = bytes(range(12))


def packet(address="8.8.8.8", transaction=TXN, xor=True, extra=b""):
    addr = ipaddress.ip_address(address)
    raw = addr.packed
    if xor:
        mask = struct.pack("!I", COOKIE) + transaction
        raw = bytes(a ^ b for a, b in zip(raw, mask))
    value = bytes((0, 1 if addr.version == 4 else 2)) + struct.pack("!H", 9999 ^ (COOKIE >> 16) if xor else 9999) + raw
    attr = struct.pack("!HH", 0x0020 if xor else 0x0001, len(value)) + value + extra
    return struct.pack("!HHI", 0x0101, len(attr), COOKIE) + transaction + attr


class StunTests(unittest.TestCase):
    def test_request_format(self):
        request, txn = binding_request(TXN)
        self.assertEqual(request, b"\x00\x01\x00\x00\x21\x12\xa4\x42" + TXN)
        self.assertEqual(txn, TXN)

    def test_xor_ipv4_and_ipv6(self):
        for address in ("8.8.8.8", "2001:4860:4860::8888"):
            self.assertEqual(parse_binding_response(packet(address), TXN), address)

    def test_mapped_address_fallback(self):
        self.assertEqual(parse_binding_response(packet(xor=False), TXN), "8.8.8.8")

    def test_transaction_cookie_and_type_are_verified(self):
        good = packet()
        for offset in (0, 4, 8):
            broken = bytearray(good)
            broken[offset] ^= 1
            with self.assertRaises(ValueError):
                parse_binding_response(bytes(broken), TXN)

    def test_truncation_and_padding_are_verified(self):
        good = packet()
        for broken in (good[:19], good[:-1], good + b"\x00", good[:22] + b"\xff\xff" + good[24:]):
            with self.assertRaises(ValueError):
                parse_binding_response(broken, TXN)

    def test_fingerprint(self):
        good = bytearray(packet())
        good[2:4] = struct.pack("!H", len(good) - 20 + 8)
        checksum = (zlib.crc32(good) & 0xFFFFFFFF) ^ 0x5354554E
        full = bytes(good) + struct.pack("!HHI", 0x8028, 4, checksum)
        self.assertEqual(parse_binding_response(full, TXN), "8.8.8.8")
        with self.assertRaises(ValueError):
            parse_binding_response(full[:-1] + bytes((full[-1] ^ 1,)), TXN)

    def test_real_udp_roundtrip_on_loopback_only(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))
            server.settimeout(2)
            def respond():
                request, sender = server.recvfrom(1024)
                server.sendto(packet(transaction=request[8:20]), sender)
            thread = threading.Thread(target=respond, daemon=True)
            thread.start()
            result = query("127.0.0.1", server.getsockname()[1], timeout=1)
            thread.join(timeout=2)
            self.assertEqual(result, "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
