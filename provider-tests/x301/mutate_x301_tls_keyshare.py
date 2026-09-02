#!/usr/bin/python3
"""One-shot TLS proxy for deterministic X301MLKEM1024 wire negatives.

The proxy mutates exactly one TLS 1.3 KeyShareEntry while preserving every
unrelated byte.  It covers client ML-KEM/X301 single-bit mutations, server
ML-KEM-ciphertext single-bit mutations, and the foreign-group-size negative.

Contract sources: RFC 8446 Section 4.2.8, RFC 9846 Sections 4.3.8 and 7.1,
RFC 10024 Sections 4-5, and FIPS 203's ML-KEM-1024 byte lengths.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
from dataclasses import dataclass


GROUP_ID = 0xFE2E
KEY_SHARE_EXTENSION = 51
MLKEM_BYTES = 1568
X301_BYTES = 38
HYBRID_BYTES = MLKEM_BYTES + X301_BYTES
X25519_MLKEM768_CLIENT_SHARE_BYTES = 1184 + 32
MUTATION_CASES = 64
P = 2**301 - 2**99 + 947
LOW_ORDER_X301 = (0, 1, P - 1)


class MutationError(ValueError):
    """The observed TLS message violates the frozen test contract."""


@dataclass(frozen=True)
class ShareLocation:
    key_start: int
    key_end: int
    key_length_offset: int
    shares_length_offset: int | None
    extension_length_offset: int
    extensions_length_offset: int


@dataclass
class ProxyState:
    lock: threading.Lock
    mutated: bool = False
    detail: str = ""
    encrypted_records_after_mutation: int = 0
    plaintext_alerts_after_mutation: int = 0
    fatal_error: str | None = None


def require(data: bytes | bytearray, offset: int, length: int, label: str) -> None:
    if length < 0 or offset < 0 or offset + length > len(data):
        raise MutationError(f"truncated {label}")


def vector_bounds(
    data: bytes | bytearray, offset: int, length_bytes: int, label: str
) -> tuple[int, int]:
    require(data, offset, length_bytes, f"{label} length")
    length = int.from_bytes(data[offset : offset + length_bytes], "big")
    start = offset + length_bytes
    require(data, start, length, label)
    return start, start + length


def check_handshake_framing(message: bytearray, expected_type: int, label: str) -> None:
    require(message, 0, 4, f"{label} framing")
    if message[0] != expected_type:
        raise MutationError(f"plaintext handshake record is not {label}")
    body_length = int.from_bytes(message[1:4], "big")
    if body_length + 4 != len(message):
        raise MutationError(f"{label} is fragmented or has trailing handshakes")


def find_client_share(message: bytearray) -> ShareLocation:
    check_handshake_framing(message, 1, "ClientHello")
    offset = 4
    require(message, offset, 34, "ClientHello fixed fields")
    offset += 34
    _, offset = vector_bounds(message, offset, 1, "legacy_session_id")
    _, offset = vector_bounds(message, offset, 2, "cipher_suites")
    _, offset = vector_bounds(message, offset, 1, "compression_methods")
    extensions_length_offset = offset
    extensions_start, extensions_end = vector_bounds(
        message, offset, 2, "ClientHello extensions"
    )
    if extensions_end != len(message):
        raise MutationError("trailing bytes after ClientHello extensions")

    matches: list[ShareLocation] = []
    offset = extensions_start
    while offset < extensions_end:
        require(message, offset, 4, "extension header")
        extension_type = int.from_bytes(message[offset : offset + 2], "big")
        extension_length_offset = offset + 2
        body_start, body_end = vector_bounds(message, offset + 2, 2, "extension")
        if body_end > extensions_end:
            raise MutationError("extension exceeds ClientHello extensions")
        if extension_type == KEY_SHARE_EXTENSION:
            shares_length_offset = body_start
            entries_start, entries_end = vector_bounds(
                message, body_start, 2, "client_shares"
            )
            if entries_end != body_end:
                raise MutationError("trailing bytes after client_shares")
            entry = entries_start
            while entry < entries_end:
                require(message, entry, 4, "client KeyShareEntry")
                group = int.from_bytes(message[entry : entry + 2], "big")
                key_length_offset = entry + 2
                key_start, key_end = vector_bounds(
                    message, key_length_offset, 2, "client key_exchange"
                )
                if group == GROUP_ID:
                    matches.append(
                        ShareLocation(
                            key_start,
                            key_end,
                            key_length_offset,
                            shares_length_offset,
                            extension_length_offset,
                            extensions_length_offset,
                        )
                    )
                entry = key_end
            if entry != entries_end:
                raise MutationError("malformed client KeyShareEntry boundary")
        offset = body_end
    if offset != extensions_end:
        raise MutationError("malformed ClientHello extension boundary")
    if len(matches) != 1:
        raise MutationError(f"found {len(matches)} X301MLKEM1024 client shares")
    return matches[0]


def find_server_share(message: bytearray) -> ShareLocation:
    check_handshake_framing(message, 2, "ServerHello")
    offset = 4
    require(message, offset, 34, "ServerHello fixed fields")
    offset += 34
    _, offset = vector_bounds(message, offset, 1, "legacy_session_id_echo")
    require(message, offset, 3, "cipher suite and compression method")
    offset += 3
    extensions_length_offset = offset
    extensions_start, extensions_end = vector_bounds(
        message, offset, 2, "ServerHello extensions"
    )
    if extensions_end != len(message):
        raise MutationError("trailing bytes after ServerHello extensions")

    matches: list[ShareLocation] = []
    offset = extensions_start
    while offset < extensions_end:
        require(message, offset, 4, "extension header")
        extension_type = int.from_bytes(message[offset : offset + 2], "big")
        extension_length_offset = offset + 2
        body_start, body_end = vector_bounds(message, offset + 2, 2, "extension")
        if body_end > extensions_end:
            raise MutationError("extension exceeds ServerHello extensions")
        if extension_type == KEY_SHARE_EXTENSION:
            require(message, body_start, 4, "server KeyShareEntry")
            group = int.from_bytes(message[body_start : body_start + 2], "big")
            key_length_offset = body_start + 2
            key_start, key_end = vector_bounds(
                message, key_length_offset, 2, "server key_exchange"
            )
            if key_end != body_end:
                raise MutationError("trailing bytes in server KeyShareEntry")
            if group == GROUP_ID:
                matches.append(
                    ShareLocation(
                        key_start,
                        key_end,
                        key_length_offset,
                        None,
                        extension_length_offset,
                        extensions_length_offset,
                    )
                )
        offset = body_end
    if offset != extensions_end:
        raise MutationError("malformed ServerHello extension boundary")
    if len(matches) != 1:
        raise MutationError(f"found {len(matches)} X301MLKEM1024 server shares")
    return matches[0]


def set_length(message: bytearray, offset: int, width: int, value: int) -> None:
    if value < 0 or value >= 1 << (8 * width):
        raise MutationError("adjusted TLS vector length is out of range")
    message[offset : offset + width] = value.to_bytes(width, "big")


def flip_component_bit(
    message: bytes,
    direction: str,
    component: str,
    case_index: int,
) -> tuple[bytes, str]:
    mutable = bytearray(message)
    location = (
        find_client_share(mutable)
        if direction == "client"
        else find_server_share(mutable)
    )
    key_length = location.key_end - location.key_start
    if key_length != HYBRID_BYTES:
        raise MutationError(
            f"{direction} KeyShare is {key_length} bytes, expected {HYBRID_BYTES}"
        )
    if component == "mlkem":
        component_start = location.key_start
        component_length = MLKEM_BYTES
    elif component == "x301":
        component_start = location.key_start + MLKEM_BYTES
        component_length = X301_BYTES
    else:
        raise MutationError(f"unsupported {direction}/{component} mutation")
    if not 0 <= case_index < MUTATION_CASES:
        raise MutationError("case index is outside 0..63")
    component_bit = case_index * component_length * 8 // MUTATION_CASES
    byte_offset = component_bit // 8
    bit_in_byte = component_bit % 8
    mutation_offset = component_start + byte_offset
    mask = 1 << bit_in_byte
    original = mutable[mutation_offset]
    mutable[mutation_offset] ^= mask
    replacement = mutable[mutation_offset]
    detail = (
        f"mutated=1 mode=flip direction={direction} group=0x{GROUP_ID:04x} "
        f"key_exchange_length={key_length} component={component} "
        f"case_index={case_index} component_bit={component_bit} "
        f"component_byte={byte_offset} mask=0x{mask:02x} "
        f"original=0x{original:02x} replacement=0x{replacement:02x}"
    )
    return bytes(mutable), detail


def replace_with_foreign_size(message: bytes) -> tuple[bytes, str]:
    mutable = bytearray(message)
    location = find_client_share(mutable)
    old_length = location.key_end - location.key_start
    if old_length != HYBRID_BYTES or location.shares_length_offset is None:
        raise MutationError("foreign-size mutation did not find a 1606-byte client share")
    new_length = X25519_MLKEM768_CLIENT_SHARE_BYTES
    removed = old_length - new_length
    del mutable[location.key_start + new_length : location.key_end]
    set_length(mutable, location.key_length_offset, 2, new_length)
    for length_offset in (
        location.shares_length_offset,
        location.extension_length_offset,
        location.extensions_length_offset,
    ):
        old_value = int.from_bytes(mutable[length_offset : length_offset + 2], "big")
        set_length(mutable, length_offset, 2, old_value - removed)
    set_length(mutable, 1, 3, len(mutable) - 4)
    detail = (
        f"mutated=1 mode=foreign-size direction=client "
        f"group=0x{GROUP_ID:04x} original_length={old_length} "
        f"replacement_length={new_length} removed={removed}"
    )
    return bytes(mutable), detail


def replace_client_x301_with_low_order(
    message: bytes, case_index: int
) -> tuple[bytes, str]:
    if not 0 <= case_index < len(LOW_ORDER_X301):
        raise MutationError("low-order case index is outside 0..2")
    mutable = bytearray(message)
    location = find_client_share(mutable)
    if location.key_end - location.key_start != HYBRID_BYTES:
        raise MutationError("client KeyShare has the wrong hybrid length")
    start = location.key_start + MLKEM_BYTES
    mutable[start : start + X301_BYTES] = LOW_ORDER_X301[case_index].to_bytes(
        X301_BYTES, "little"
    )
    detail = (
        f"mutated=1 mode=low-order direction=client "
        f"group=0x{GROUP_ID:04x} component=x301 case_index={case_index}"
    )
    return bytes(mutable), detail


def swap_client_components(message: bytes) -> tuple[bytes, str]:
    mutable = bytearray(message)
    location = find_client_share(mutable)
    if location.key_end - location.key_start != HYBRID_BYTES:
        raise MutationError("client KeyShare has the wrong hybrid length")
    share = bytes(mutable[location.key_start : location.key_end])
    mlkem = share[:MLKEM_BYTES]
    x301 = share[MLKEM_BYTES:]
    mutable[location.key_start : location.key_end] = x301 + mlkem
    detail = (
        f"mutated=1 mode=swap direction=client "
        f"group=0x{GROUP_ID:04x} component=x301 case_index=0"
    )
    return bytes(mutable), detail


def receive_exact(connection: socket.socket, length: int, clean_eof: bool = False) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            if clean_eof and remaining == length:
                return b""
            raise MutationError("truncated TLS record")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def relay_records(
    source: socket.socket,
    destination: socket.socket,
    direction: str,
    target_direction: str,
    mode: str,
    component: str,
    case_index: int,
    state: ProxyState,
) -> None:
    try:
        while True:
            header = receive_exact(source, 5, clean_eof=True)
            if not header:
                break
            length = int.from_bytes(header[3:5], "big")
            payload = receive_exact(source, length)
            record_type = header[0]
            with state.lock:
                already_mutated = state.mutated
            if record_type == 22 and direction == target_direction and not already_mutated:
                if mode == "flip":
                    payload, detail = flip_component_bit(
                        payload, direction, component, case_index
                    )
                elif mode == "low-order":
                    if direction != "client" or component != "x301":
                        raise MutationError("low-order applies only to client X301")
                    payload, detail = replace_client_x301_with_low_order(
                        payload, case_index
                    )
                elif mode == "swap":
                    if direction != "client":
                        raise MutationError("swap applies only to ClientHello")
                    payload, detail = swap_client_components(payload)
                else:
                    if direction != "client":
                        raise MutationError("foreign-size applies only to ClientHello")
                    payload, detail = replace_with_foreign_size(payload)
                header = header[:3] + len(payload).to_bytes(2, "big")
                with state.lock:
                    state.mutated = True
                    state.detail = detail
            elif direction == "server":
                with state.lock:
                    if state.mutated and record_type == 23:
                        state.encrypted_records_after_mutation += 1
                    elif state.mutated and record_type == 21:
                        state.plaintext_alerts_after_mutation += 1
            destination.sendall(header + payload)
    except (BrokenPipeError, ConnectionResetError, socket.timeout):
        pass
    except (MutationError, OSError) as error:
        with state.lock:
            if state.fatal_error is None:
                state.fatal_error = str(error)
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def proxy_once(
    listen_port: int,
    upstream_port: int,
    direction: str,
    mode: str,
    component: str,
    case_index: int,
) -> None:
    state = ProxyState(threading.Lock())
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", listen_port))
        listener.listen(1)
        print(f"listening=127.0.0.1:{listen_port}", flush=True)
        client, _ = listener.accept()

    with client, socket.create_connection(("127.0.0.1", upstream_port), 10) as server:
        client.settimeout(20)
        server.settimeout(20)
        upstream = threading.Thread(
            target=relay_records,
            args=(
                client,
                server,
                "client",
                direction,
                mode,
                component,
                case_index,
                state,
            ),
        )
        downstream = threading.Thread(
            target=relay_records,
            args=(
                server,
                client,
                "server",
                direction,
                mode,
                component,
                case_index,
                state,
            ),
        )
        upstream.start()
        downstream.start()
        upstream.join()
        downstream.join()

    if state.fatal_error is not None:
        raise MutationError(state.fatal_error)
    if not state.mutated:
        raise MutationError("no X301MLKEM1024 KeyShare was mutated")
    if (
        mode == "flip"
        and direction == "server"
        and state.encrypted_records_after_mutation < 1
    ):
        raise MutationError("server sent no protected record after mutation")
    print(state.detail, flush=True)
    print(
        "encrypted_records_after_mutation="
        f"{state.encrypted_records_after_mutation} "
        "plaintext_alerts_after_mutation="
        f"{state.plaintext_alerts_after_mutation}",
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--direction", choices=("client", "server"), required=True)
    parser.add_argument(
        "--mode",
        choices=("flip", "foreign-size", "low-order", "swap"),
        default="flip",
    )
    parser.add_argument("--component", choices=("mlkem", "x301"), default="mlkem")
    parser.add_argument("--case-index", type=int, default=0)
    arguments = parser.parse_args()
    try:
        proxy_once(
            arguments.listen_port,
            arguments.upstream_port,
            arguments.direction,
            arguments.mode,
            arguments.component,
            arguments.case_index,
        )
    except (MutationError, OSError) as error:
        print(f"wire mutation failed: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
