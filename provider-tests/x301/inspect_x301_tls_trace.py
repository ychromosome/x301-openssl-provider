#!/usr/bin/python3
"""Validate X301MLKEM1024 HRR and record-fragmentation traces.

Sources: RFC 8446 Sections 4.1.3 and 4.2.8, RFC 9846 Section 4.3.8,
and the fixed 1606-byte X301MLKEM1024 client-share contract.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from extract_x301_client_keyshare import (
    ParseError,
    incoming_server_hellos,
    outgoing_client_hellos,
    x301_hybrid_keyshare,
)


HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891"
    "c2a211167abb8c5e079e09e2c8a8339c"
)


def has_no_x301_share(client_hello: bytes) -> bool:
    try:
        x301_hybrid_keyshare(client_hello)
    except ParseError as error:
        return str(error) == "found 0 X301MLKEM1024 KeyShare entries"
    return False


def validate_hrr(trace: str) -> str:
    client_hellos = outgoing_client_hellos(trace)
    server_hellos = incoming_server_hellos(trace)
    if len(client_hellos) != 2 or len(server_hellos) < 2:
        raise ParseError(
            f"HRR trace has {len(client_hellos)} ClientHellos and "
            f"{len(server_hellos)} ServerHellos"
        )
    first_server = server_hellos[0]
    if first_server[6:38] != HRR_RANDOM:
        raise ParseError("first ServerHello does not carry the RFC 8446 HRR random")
    if not has_no_x301_share(client_hellos[0]):
        raise ParseError("first ClientHello unexpectedly contains an X301 share")
    second_share = x301_hybrid_keyshare(client_hellos[1])
    return (
        "hrr=PASS client_hellos=2 server_hellos="
        f"{len(server_hellos)} first_x301=absent "
        f"second_x301_length={len(second_share)}"
    )


def outgoing_record_lengths_before_first_client_hello(trace: str) -> list[int]:
    lines = trace.splitlines()
    header_marker = re.compile(r"^>>> .*RecordHeader \[length 0005\]$")
    client_marker = re.compile(r"^>>> .*Handshake .*ClientHello$")
    hex_line = re.compile(r"^\s+(?:[0-9A-Fa-f]{2}(?:\s+|$))+$")
    lengths: list[int] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if client_marker.match(line):
            break
        if header_marker.match(line):
            if index + 1 >= len(lines) or not hex_line.match(lines[index + 1]):
                raise ParseError("outgoing RecordHeader has no hexadecimal body")
            header = bytes.fromhex("".join(lines[index + 1].split()))
            if len(header) != 5:
                raise ParseError("outgoing TLS record header is not five bytes")
            if header[0] == 22:
                lengths.append(int.from_bytes(header[3:5], "big"))
            index += 1
        index += 1
    return lengths


def validate_fragmentation(trace: str, maximum: int) -> str:
    client_hellos = outgoing_client_hellos(trace)
    if not client_hellos:
        raise ParseError("fragmentation trace has no ClientHello")
    lengths = outgoing_record_lengths_before_first_client_hello(trace)
    if len(lengths) < 2:
        raise ParseError("ClientHello was not split across TLS records")
    if max(lengths) > maximum:
        raise ParseError(
            f"record payload {max(lengths)} exceeds configured maximum {maximum}"
        )
    if sum(lengths) != len(client_hellos[0]):
        raise ParseError(
            f"fragment payload sum {sum(lengths)} does not equal "
            f"ClientHello length {len(client_hellos[0])}"
        )
    share = x301_hybrid_keyshare(client_hellos[0])
    return (
        f"fragmentation=PASS records={len(lengths)} "
        f"lengths={','.join(str(value) for value in lengths)} "
        f"client_hello_length={len(client_hellos[0])} "
        f"x301_share_length={len(share)}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--hrr", action="store_true")
    mode.add_argument("--fragment-max", type=int)
    arguments = parser.parse_args()
    try:
        trace = arguments.trace.read_text(encoding="ascii")
        result = (
            validate_hrr(trace)
            if arguments.hrr
            else validate_fragmentation(trace, arguments.fragment_max)
        )
    except (OSError, UnicodeError, ParseError) as error:
        print(f"TLS trace validation failed: {error}", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
