#!/usr/bin/env python3
"""
SplitSNI - Lightweight TLS Record Splitting Forwarder & Proxy.
Bypasses SNI-based DPI by fragmenting ClientHello handshakes across
RFC 8446 compliant TLS records in user space.
"""

import argparse
import json
import os
import select
import socket
import struct
import sys
import threading
import urllib.request

DNS_CACHE: dict[str, str] = {}


def is_ip_address(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except (socket.error, AttributeError):
        pass
    return False


def resolve_host(host: str) -> str:
    """Resolve domain using encrypted DNS-over-HTTPS (DoH) to bypass DNS poisoning."""
    if is_ip_address(host):
        return host

    if host in DNS_CACHE:
        return DNS_CACHE[host]

    for doh_url in [
        f"https://1.1.1.1/dns-query?name={host}&type=A",
        f"https://8.8.8.8/resolve?name={host}&type=A",
    ]:
        try:
            req = urllib.request.Request(doh_url, headers={"Accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode())
                for ans in data.get("Answer", []):
                    if ans.get("type") == 1:
                        ip = ans.get("data")
                        DNS_CACHE[host] = ip
                        return ip
        except Exception:
            continue

    try:
        return socket.gethostbyname(host)
    except Exception:
        return host


def load_config(filepath: str = "config.json") -> dict:
    """Load settings from JSON config file if present."""
    if os.path.isfile(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            print(f"[!] Warning: Failed to parse {filepath}: {exc}")
    return {}


def extract_sni_range(body: bytes) -> tuple[int, int] | None:
    """Extract (start_offset, end_offset) of the SNI hostname within the ClientHello body."""
    if len(body) < 38 or body[0] != 0x01:
        return None

    # Skip handshake type (1B), length (3B), version (2B), random (32B)
    cursor = 38
    if cursor >= len(body):
        return None

    # Skip session ID
    session_id_len = body[cursor]
    cursor += 1 + session_id_len

    # Skip cipher suites
    if cursor + 2 > len(body):
        return None
    cipher_len = struct.unpack("!H", body[cursor:cursor + 2])[0]
    cursor += 2 + cipher_len

    # Skip compression methods
    if cursor + 1 > len(body):
        return None
    comp_len = body[cursor]
    cursor += 1 + comp_len

    # Parse extensions
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

        if ext_type == 0x0000 and ext_len >= 5:  # server_name extension
            list_len = struct.unpack("!H", body[cursor:cursor + 2])[0]
            sub = cursor + 2
            sub_end = min(cursor + 2 + list_len, cursor + ext_len)
            while sub + 3 <= sub_end:
                name_type = body[sub]
                name_len = struct.unpack("!H", body[sub + 1:sub + 3])[0]
                sub += 3
                if name_type == 0x00 and sub + name_len <= sub_end:  # host_name
                    return sub, sub + name_len
                sub += name_len
        cursor += ext_len

    return None


def split_tls_record(buf: bytes, default_offset: int = 40) -> bytes:
    """
    Splits a TLS ClientHello record across two RFC 8446 compliant TLS records.
    Dynamically targets the middle of the SNI hostname (and specifically breaks
    sensitive keywords like 'googlevideo') to prevent DPI pattern matching.
    """
    if len(buf) < 5 or buf[0] != 0x16 or buf[1] != 0x03:
        return buf

    total_len = struct.unpack("!H", buf[3:5])[0]
    if len(buf) < total_len + 5:
        return buf

    version = buf[1:3]
    body = buf[5:total_len + 5]
    tail = buf[total_len + 5:]

    sni_range = extract_sni_range(body)
    if sni_range:
        s_start, s_end = sni_range
        hostname = body[s_start:s_end]
        if b"googlevideo" in hostname:
            g_idx = hostname.find(b"googlevideo")
            split_at = s_start + g_idx + 4  # Splits right between 'goog' and 'levideo'
        else:
            split_at = s_start + max(1, len(hostname) // 2)
    else:
        split_at = default_offset

    split_at = max(1, min(split_at, len(body) - 1))
    rec1 = b"\x16" + version + struct.pack("!H", split_at) + body[:split_at]
    rec2 = b"\x16" + version + struct.pack("!H", len(body) - split_at) + body[split_at:]
    return rec1 + rec2 + tail


def recv_full_tls_record(sock: socket.socket, initial: bytes = b"") -> bytes:
    """Ensure the full TLS record is read from socket before processing."""
    buf = initial
    if len(buf) < 5:
        try:
            chunk = sock.recv(5 - len(buf))
            if chunk:
                buf += chunk
        except Exception:
            pass

    if len(buf) >= 5 and buf[0] == 0x16 and buf[1] == 0x03:
        record_len = struct.unpack("!H", buf[3:5])[0]
        total_len = record_len + 5
        while len(buf) < total_len:
            try:
                chunk = sock.recv(min(8192, total_len - len(buf)))
                if not chunk:
                    break
                buf += chunk
            except Exception:
                break
    return buf


def bridge(s1: socket.socket, s2: socket.socket):
    """Duplex relay between two connected sockets with TCP half-close support."""
    read_socks = [s1, s2]
    try:
        while read_socks:
            rlist, _, _ = select.select(read_socks, [], [], 60)
            if not rlist:
                break
            for sock in rlist:
                peer = s2 if sock is s1 else s1
                try:
                    chunk = sock.recv(65536)
                except Exception:
                    chunk = b""
                if not chunk:
                    if sock in read_socks:
                        read_socks.remove(sock)
                    try:
                        peer.shutdown(socket.SHUT_WR)
                    except Exception:
                        pass
                else:
                    peer.sendall(chunk)
    except Exception:
        pass
    finally:
        for s in (s1, s2):
            try:
                s.close()
            except Exception:
                pass


def handle_socks5(client: socket.socket, initial: bytes) -> tuple[str, int] | tuple[None, None]:
    """Handle SOCKS5 handshake negotiation."""
    nmethods = initial[1] if len(initial) > 1 else client.recv(1)[0]
    _ = client.recv(nmethods)
    client.sendall(b"\x05\x00")

    req = client.recv(4)
    if len(req) < 4 or req[1] != 1:  # CMD 1 = CONNECT
        return None, None

    atyp = req[3]
    if atyp == 1:  # IPv4
        host = socket.inet_ntoa(client.recv(4))
    elif atyp == 3:  # Domain name
        dlen = client.recv(1)[0]
        host = client.recv(dlen).decode(errors="ignore")
    elif atyp == 4:  # IPv6
        host = socket.inet_ntop(socket.AF_INET6, client.recv(16))
    else:
        return None, None

    port = struct.unpack("!H", client.recv(2))[0]
    client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    return host, port


def handle_client(client: socket.socket, default_host: str, default_port: int, split_offset: int):
    try:
        peek = client.recv(4096)
        if not peek:
            client.close()
            return

        target_host = default_host
        target_port = default_port
        is_connect_method = False
        is_socks5 = False

        if peek[0] == 0x05:
            target_host, target_port = handle_socks5(client, peek)
            if not target_host:
                client.close()
                return
            is_socks5 = True
            peek = b""

        elif peek.startswith(b"CONNECT "):
            first_line = peek.split(b"\r\n")[0].decode(errors="ignore")
            target = first_line.split(" ")[1]
            target_host, port_str = target.split(":")
            target_port = int(port_str)
            is_connect_method = True
            peek = b""

        # Resolve host via encrypted DoH to bypass local DNS poisoning (10.10.34.35)
        remote_ip = resolve_host(target_host)

        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.settimeout(8.0)
        upstream.connect((remote_ip, target_port))
        upstream.settimeout(None)

        if is_connect_method:
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            first_payload = recv_full_tls_record(client)
            if first_payload:
                payload = split_tls_record(first_payload, split_offset)
                upstream.sendall(payload)
        elif is_socks5:
            first_payload = recv_full_tls_record(client)
            if first_payload:
                payload = split_tls_record(first_payload, split_offset)
                upstream.sendall(payload)
        else:
            full_hello = recv_full_tls_record(client, initial=peek)
            payload = split_tls_record(full_hello, split_offset)
            upstream.sendall(payload)

        bridge(client, upstream)

    except Exception:
        try:
            client.close()
        except Exception:
            pass


def serve(bind_host: str, bind_port: int, target_host: str, target_port: int, split_offset: int):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind_host, bind_port))
    listener.listen(128)

    print(f"[*] SplitSNI listening on {bind_host}:{bind_port}")
    print(f"[*] Default upstream target: {target_host}:{target_port}")
    print(f"[*] Split offset: {split_offset} bytes")

    try:
        while True:
            conn, _ = listener.accept()
            worker = threading.Thread(
                target=handle_client,
                args=(conn, target_host, target_port, split_offset),
                daemon=True,
            )
            worker.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down listener")
    finally:
        listener.close()


def main():
    parser = argparse.ArgumentParser(description="SplitSNI - RFC 8446 multi-record TLS forwarder")
    parser.add_argument("-c", "--config", default="config.json", help="Path to config.json (default: config.json)")
    parser.add_argument("-l", "--listen", default=None, help="Bind address")
    parser.add_argument("-p", "--port", type=int, default=None, help="Bind port")
    parser.add_argument("-t", "--target-host", default=None, help="Default upstream host")
    parser.add_argument("-tp", "--target-port", type=int, default=None, help="Default upstream port")
    parser.add_argument("-s", "--split", type=int, default=None, help="ClientHello split offset")

    args = parser.parse_args()
    cfg = load_config(args.config)

    bind_host = args.listen or cfg.get("listen_host", "127.0.0.1")
    bind_port = args.port or cfg.get("listen_port", 10850)
    target_host = args.target_host or cfg.get("remote_host", "188.114.97.6")
    target_port = args.target_port or cfg.get("remote_port", 443)
    split_offset = args.split or cfg.get("split_offset", 40)

    serve(bind_host, bind_port, target_host, target_port, split_offset)


if __name__ == "__main__":
    main()
