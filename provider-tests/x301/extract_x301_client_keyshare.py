#!/usr/bin/python3
"""Extract the X301MLKEM1024 client KeyShare from OpenSSL ``-msg`` output.

Contract sources: RFC 9846 Section 4.3.8 defines the TLS 1.3 ClientHello
KeyShare encoding and forbids reuse of a locally generated KeyShare; RFC 10024
Sections 4-5 define the ML-KEM-first hybrid layout used here.  FIPS 203 fixes
the ML-KEM-1024 encapsulation-key length at 1568 bytes; the X301 byte contract
fixes its public value at 38 bytes.  The private-use NamedGroup is registered
by this project as 0xFE2E.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path


GROUP_ID = 0xFE2E
MLKEM_PUBLIC_BYTES = 1568
X301_PUBLIC_BYTES = 38
HYBRID_PUBLIC_BYTES = MLKEM_PUBLIC_BYTES + X301_PUBLIC_BYTES
KEY_SHARE_EXTENSION = 51


class ParseError(ValueError):
    """The OpenSSL trace or encoded ClientHello violates the TLS contract."""


def take(data: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    end = offset + length
    if length < 0 or end > len(data):
        raise ParseError(f"truncated {label}")
    return data[offset:end], end


def take_vector(
    data: bytes, offset: int, length_bytes: int, label: str
) -> tuple[bytes, int]:
    raw_length, offset = take(data, offset, length_bytes, f"{label} length")
    length = int.from_bytes(raw_length, "big")
    return take(data, offset, length, label)


def first_outgoing_client_hello(trace: str) -> bytes:
    lines = trace.splitlines()
    marker = re.compile(r"^>>> .*Handshake .*ClientHello$")
    hex_line = re.compile(r"^\s+(?:[0-9A-Fa-f]{2}(?:\s+|$))+$")

    for index, line in enumerate(lines):
        if not marker.match(line):
            continue
        octets: list[str] = []
        for encoded in lines[index + 1 :]:
            if not hex_line.match(encoded):
                break
            octets.extend(encoded.split())
        if not octets:
            raise ParseError("ClientHello marker has no hexadecimal body")
        message = bytes.fromhex("".join(octets))
        if len(message) < 4 or message[0] != 1:
            raise ParseError("malformed ClientHello handshake framing")
        encoded_length = int.from_bytes(message[1:4], "big")
        if encoded_length != len(message) - 4:
            raise ParseError(
                f"ClientHello length is {len(message) - 4}, expected {encoded_length}"
            )
        return message
    raise ParseError("no outgoing ClientHello in OpenSSL -msg output")


def x301_hybrid_keyshare(client_hello: bytes) -> bytes:
    offset = 4
    _, offset = take(client_hello, offset, 2, "legacy_version")
    _, offset = take(client_hello, offset, 32, "random")
    _, offset = take_vector(client_hello, offset, 1, "legacy_session_id")
    _, offset = take_vector(client_hello, offset, 2, "cipher_suites")
    _, offset = take_vector(client_hello, offset, 1, "compression_methods")
    extensions, offset = take_vector(client_hello, offset, 2, "extensions")
    if offset != len(client_hello):
        raise ParseError("trailing bytes after ClientHello extensions")

    key_share_bodies: list[bytes] = []
    ext_offset = 0
    while ext_offset < len(extensions):
        raw_type, ext_offset = take(extensions, ext_offset, 2, "extension type")
        body, ext_offset = take_vector(extensions, ext_offset, 2, "extension body")
        if int.from_bytes(raw_type, "big") == KEY_SHARE_EXTENSION:
            key_share_bodies.append(body)
    if len(key_share_bodies) != 1:
        raise ParseError(f"found {len(key_share_bodies)} key_share extensions")

    entries, entry_offset = take_vector(
        key_share_bodies[0], 0, 2, "client_shares"
    )
    if entry_offset != len(key_share_bodies[0]):
        raise ParseError("trailing bytes after client_shares")

    matches: list[bytes] = []
    entry_offset = 0
    while entry_offset < len(entries):
        raw_group, entry_offset = take(entries, entry_offset, 2, "NamedGroup")
        key_exchange, entry_offset = take_vector(
            entries, entry_offset, 2, "KeyShareEntry.key_exchange"
        )
        if int.from_bytes(raw_group, "big") == GROUP_ID:
            matches.append(key_exchange)
    if len(matches) != 1:
        raise ParseError(f"found {len(matches)} X301MLKEM1024 KeyShare entries")
    if len(matches[0]) != HYBRID_PUBLIC_BYTES:
        raise ParseError(
            f"X301MLKEM1024 KeyShare is {len(matches[0])} bytes, "
            f"expected {HYBRID_PUBLIC_BYTES}"
        )
    return matches[0]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} OPENSSL-MSG-FILE", file=sys.stderr)
        return 2
    try:
        trace = Path(sys.argv[1]).read_text(encoding="ascii")
        key_share = x301_hybrid_keyshare(first_outgoing_client_hello(trace))
    except (OSError, UnicodeError, ParseError) as error:
        print(f"keyshare parse failed: {error}", file=sys.stderr)
        return 1

    mlkem = key_share[:MLKEM_PUBLIC_BYTES]
    x301 = key_share[MLKEM_PUBLIC_BYTES:]
    print(
        f"group=0x{GROUP_ID:04x} length={len(key_share)} "
        f"mlkem_length={len(mlkem)} mlkem_sha256={digest(mlkem)} "
        f"x301_length={len(x301)} x301_sha256={digest(x301)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
