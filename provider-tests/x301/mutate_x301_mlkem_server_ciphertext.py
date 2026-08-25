#!/usr/bin/python3
"""One-shot TLS proxy that corrupts only the ML-KEM server ciphertext.

This is test infrastructure, structurally equivalent to OpenSSL's
``test/sslcorrupttest.c`` BIO filter but placed on the CLI wire.  Contract
sources: RFC 9846 Sections 4.3.8 and 7.1; RFC 10024 Sections 4-5 for the
ML-KEM-first server KeyShare; and FIPS 203 for ML-KEM-1024's 1568-byte
ciphertext and implicit-rejection semantics.  No provider failpoint is used.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading


GROUP_ID = 0xFE2E
KEY_SHARE_EXTENSION = 51
MLKEM_CIPHERTEXT_BYTES = 1568
X301_PUBLIC_BYTES = 38
HYBRID_SERVER_SHARE_BYTES = MLKEM_CIPHERTEXT_BYTES + X301_PUBLIC_BYTES


class MutationError(ValueError):
    """The observed ServerHello does not match the frozen TLS byte contract."""


def require(data: bytes | bytearray, offset: int, length: int, label: str) -> None:
    if length < 0 or offset < 0 or offset + length > len(data):
        raise MutationError(f"truncated {label}")


def vector_end(
    data: bytes | bytearray, offset: int, length_bytes: int, label: str
) -> tuple[int, int]:
    require(data, offset, length_bytes, f"{label} length")
    length = int.from_bytes(data[offset : offset + length_bytes], "big")
    start = offset + length_bytes
    require(data, start, length, label)
    return start, start + length


def mutate_server_hello(payload: bytes) -> tuple[bytes, str]:
    message = bytearray(payload)
    require(message, 0, 4, "ServerHello framing")
    if message[0] != 2:
        raise MutationError("plaintext handshake record is not ServerHello")
    body_length = int.from_bytes(message[1:4], "big")
    if body_length + 4 > len(message):
        raise MutationError("truncated ServerHello body")

    offset = 4
    require(message, offset, 2 + 32, "ServerHello fixed fields")
    offset += 2 + 32
    _, offset = vector_end(message, offset, 1, "legacy_session_id_echo")
    require(message, offset, 3, "cipher suite and compression method")
    offset += 3
    extensions_start, extensions_end = vector_end(
        message, offset, 2, "ServerHello extensions"
    )
    if extensions_end != body_length + 4:
        raise MutationError("trailing bytes inside ServerHello")

    matches: list[tuple[int, int]] = []
    offset = extensions_start
    while offset < extensions_end:
        require(message, offset, 4, "extension header")
        extension_type = int.from_bytes(message[offset : offset + 2], "big")
        body_start, body_end = vector_end(message, offset + 2, 2, "extension")
        if body_end > extensions_end:
            raise MutationError("extension exceeds ServerHello extensions")
        if extension_type == KEY_SHARE_EXTENSION:
            require(message, body_start, 4, "server KeyShareEntry")
            group = int.from_bytes(message[body_start : body_start + 2], "big")
            key_start, key_end = vector_end(
                message, body_start + 2, 2, "server key_exchange"
            )
            if key_end != body_end:
                raise MutationError("trailing bytes in server KeyShareEntry")
            if group == GROUP_ID:
                matches.append((key_start, key_end))
        offset = body_end
    if offset != extensions_end:
        raise MutationError("malformed ServerHello extension boundary")
    if len(matches) != 1:
        raise MutationError(f"found {len(matches)} X301MLKEM1024 server shares")

    key_start, key_end = matches[0]
    if key_end - key_start != HYBRID_SERVER_SHARE_BYTES:
        raise MutationError(
            f"server KeyShare is {key_end - key_start} bytes, "
            f"expected {HYBRID_SERVER_SHARE_BYTES}"
        )
    component_offset = MLKEM_CIPHERTEXT_BYTES // 2
    mutation_offset = key_start + component_offset
    original = message[mutation_offset]
    message[mutation_offset] ^= 1
    replacement = message[mutation_offset]
    detail = (
        f"mutated=1 group=0x{GROUP_ID:04x} key_exchange_length="
        f"{key_end - key_start} component=mlkem component_offset="
        f"{component_offset} original=0x{original:02x} replacement=0x{replacement:02x}"
    )
    return bytes(message), detail


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


def client_to_server(client: socket.socket, server: socket.socket) -> None:
    try:
        while True:
            data = client.recv(16384)
            if not data:
                break
            server.sendall(data)
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            server.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def proxy_once(listen_port: int, upstream_port: int) -> None:
    mutated = False
    encrypted_after_mutation = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", listen_port))
        listener.listen(1)
        print(f"listening=127.0.0.1:{listen_port}", flush=True)
        client, _ = listener.accept()

    with client, socket.create_connection(("127.0.0.1", upstream_port), 10) as server:
        client.settimeout(20)
        server.settimeout(20)
        relay = threading.Thread(
            target=client_to_server, args=(client, server), daemon=True
        )
        relay.start()
        while True:
            header = receive_exact(server, 5, clean_eof=True)
            if not header:
                break
            length = int.from_bytes(header[3:5], "big")
            payload = receive_exact(server, length)
            record_type = header[0]
            if record_type == 22 and not mutated:
                payload, detail = mutate_server_hello(payload)
                mutated = True
                print(detail, flush=True)
            elif record_type == 23 and mutated:
                encrypted_after_mutation += 1
            try:
                client.sendall(header + payload)
            except (BrokenPipeError, ConnectionResetError):
                break
        relay.join(timeout=1)

    print(
        f"encrypted_records_after_mutation={encrypted_after_mutation}", flush=True
    )
    if not mutated:
        raise MutationError("no X301MLKEM1024 ServerHello was mutated")
    if encrypted_after_mutation < 1:
        raise MutationError("server sent no encrypted handshake record after ServerHello")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    arguments = parser.parse_args()
    try:
        proxy_once(arguments.listen_port, arguments.upstream_port)
    except (MutationError, OSError) as error:
        print(f"wire mutation failed: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
