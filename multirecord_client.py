#!/usr/bin/env python3
import argparse
import socket
import ssl
import struct
import sys
import time


def build_client_hello(sni: str) -> bytes:
    """Use an in-memory SSLContext BIO to generate a genuine ClientHello."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    in_bio = ssl.MemoryBIO()
    out_bio = ssl.MemoryBIO()
    engine = ctx.wrap_bio(in_bio, out_bio, server_hostname=sni)

    try:
        engine.do_handshake()
    except ssl.SSLWantReadError:
        pass

    return out_bio.read()


def extract_sni_range(body: bytes) -> tuple[int, int] | None:
    """Extract (start_offset, end_offset) of the SNI hostname within the ClientHello body."""
    if len(body) < 38 or body[0] != 0x01:
        return None

    cursor = 38
    if cursor >= len(body):
        return None

    session_id_len = body[cursor]
    cursor += 1 + session_id_len

    if cursor + 2 > len(body):
        return None
    cipher_len = struct.unpack("!H", body[cursor:cursor + 2])[0]
    cursor += 2 + cipher_len

    if cursor + 1 > len(body):
        return None
    comp_len = body[cursor]
    cursor += 1 + comp_len

    if cursor + 2 > len(body):
        return None
    exts_len = struct.unpack("!H", body[cursor:cursor + 2])[0]
    cursor += 2

    end_exts = min(cursor + exts_len, len(body))
    while cursor + 4 <= end_exts:
        ext_type = struct.unpack("!H", body[cursor:cursor + 2])[0]
        ext_len = struct.unpack("!H", body[cursor + 2:cursor + 4])[0]
        cursor += 4
        if cursor + ext_len > end_exts:
            break

        if ext_type == 0x0000 and ext_len >= 5:
            list_len = struct.unpack("!H", body[cursor:cursor + 2])[0]
            sub = cursor + 2
            sub_end = min(cursor + 2 + list_len, cursor + ext_len)
            while sub + 3 <= sub_end:
                name_type = body[sub]
                name_len = struct.unpack("!H", body[sub + 1:sub + 3])[0]
                sub += 3
                if name_type == 0x00 and sub + name_len <= sub_end:
                    return sub, sub + name_len
                sub += name_len
        cursor += ext_len

    return None


def split_handshake_records(client_hello: bytes, offset: int = 0) -> tuple[bytes, bytes]:
    """
    Splits a single TLS handshake message across two TLS records.
    RFC 8446 Section 5.1 allows arbitrary fragmentation of handshake bodies.
    If offset is 0 or negative, automatically calculates the optimal split point
    inside the SNI hostname.
    """
    if len(client_hello) < 5 or client_hello[0] != 0x16:
        raise ValueError("Provided payload is not a valid TLS handshake record")

    version = client_hello[1:3]
    body = client_hello[5:]

    if offset <= 0:
        sni_range = extract_sni_range(body)
        if sni_range:
            s_start, s_end = sni_range
            hostname = body[s_start:s_end]
            if b"googlevideo" in hostname:
                g_idx = hostname.find(b"googlevideo")
                offset = s_start + g_idx + 4
            else:
                offset = s_start + max(1, len(hostname) // 2)
        else:
            offset = 40

    offset = max(1, min(offset, len(body) - 1))

    first_chunk = body[:offset]
    second_chunk = body[offset:]

    rec1 = b"\x16" + version + struct.pack("!H", len(first_chunk)) + first_chunk
    rec2 = b"\x16" + version + struct.pack("!H", len(second_chunk)) + second_chunk

    return rec1, rec2


def test_handshake(host: str, port: int, sni: str, split_offset: int, delay_ms: float = 0.0) -> bool:
    print(f"[*] Target: {host}:{port} (SNI: {sni})")

    raw_hello = build_client_hello(sni)
    rec1, rec2 = split_handshake_records(raw_hello, split_offset)
    actual_offset = len(rec1) - 5
    print(f"[*] Splitting handshake body at byte {actual_offset}")
    print(f"[*] Prepared records: #{len(rec1)}b + #{len(rec2)}b (original: {len(raw_hello)}b)")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)

    try:
        t0 = time.monotonic()
        sock.connect((host, port))
        rtt = (time.monotonic() - t0) * 1000
        print(f"[+] TCP connection established in {rtt:.1f}ms")

        # Send split records
        if delay_ms > 0:
            sock.sendall(rec1)
            time.sleep(delay_ms / 1000.0)
            sock.sendall(rec2)
        else:
            sock.sendall(rec1 + rec2)

        # Await ServerHello response
        data = sock.recv(8192)
        elapsed = (time.monotonic() - t0) * 1000

        if not data:
            print("[-] Connection closed by peer without data")
            return False

        # Check for TLS Handshake response
        if len(data) >= 5 and data[0] == 0x16:
            handshake_type = data[5] if len(data) > 5 else 0
            if handshake_type == 2:
                print(f"[+] Success: Received TLS ServerHello ({len(data)} bytes) in {elapsed:.1f}ms")
                return True
            print(f"[+] Received TLS record type {handshake_type} ({len(data)} bytes)")
            return True

        if b"302" in data or b"Location:" in data:
            print(f"[-] Blocked: Received HTTP 302 injection from middlebox")
            return False

        print(f"[?] Unexpected response ({len(data)} bytes): {data[:32]!r}")
        return False

    except ConnectionResetError:
        print("[-] Blocked: TCP RST injected by middlebox")
        return False
    except socket.timeout:
        print("[-] Timed out waiting for ServerHello")
        return False
    except Exception as exc:
        print(f"[-] Socket error: {exc}")
        return False
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="SplitSNI - TLS Handshake Test Probe")
    parser.add_argument("host", nargs="?", default="1.1.1.1", help="Destination IP or hostname")
    parser.add_argument("port", nargs="?", type=int, default=443, help="Destination TCP port")
    parser.add_argument("--sni", default="cloudflare.com", help="Server Name Indication (SNI)")
    parser.add_argument("--split", type=int, default=0, help="Offset to split ClientHello body (default: 0 = auto SNI split)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between record writes in ms (default: 0)")

    args = parser.parse_args()
    success = test_handshake(args.host, args.port, args.sni, args.split, args.delay)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
