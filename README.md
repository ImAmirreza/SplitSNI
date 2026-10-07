# SplitSNI

A lightweight, zero-privilege TLS record fragmentation tool to bypass SNI-based DPI censorship.

---

## 1. How It Works (RFC 8446 Record Splitting)

Per **RFC 8446 (TLS 1.3) Section 5.1** and **RFC 5246 (TLS 1.2) Section 6.2.1**:

> *"Handshake messages MAY be split across TLS records, or multiple handshake messages MAY be combined into a single record."*

A standard TLS implementation generates a `ClientHello` enclosed in a single TLS record:
```text
[Record Header (5 bytes)] + [ClientHello Message Body (512 bytes)]
 0x16 0x03 0x01 [Len: 512]   0x01 [Handshake Len: 508] ... [SNI Extension]
```

**SplitSNI** fragments the `ClientHello` across two legitimate TLS records:
```text
TLS Record 1 (Length: 45 bytes):
 [0x16 0x03 0x01 0x00 0x28] [0x01 0x00 0x01 0xfc ...] (Handshake header + Version + Random)

TLS Record 2 (Length: 477 bytes):
 [0x16 0x03 0x01 0x01 0xdd] [Cipher suites ... SNI Extension: "example.com" ...]
```

Both records can be sent inside the **same TCP packet** or split across separate TCP writes.

---

## 2. Why It Evades DPI Middlebox Inspection

1. **Parser Bounds Limitations:**
   Middlebox inspection engines often assume `1 TLS Record == 1 TLS Message`. When parsing Record 1, the engine reads the handshake message length (508 bytes) but sees a record length of only 40 bytes.
2. **Missing SNI Offset:**
   The parser attempts to jump to the extensions offset (~byte 150). Because that offset is past the end of Record 1, the parser encounters an out-of-bounds condition and terminates inspection without inspecting subsequent records.
3. **Standards-Compliant Server Reassembly:**
   RFC-compliant TLS servers (OpenSSL, BoringSSL, Go `crypto/tls`, Rustls) maintain a message reassembly buffer at the record layer, seamlessly merging both records and completing the handshake.

---

## 3. Comparison: SplitSNI vs. `patterniha/SNI-Spoofing`

| Feature | `patterniha/SNI-Spoofing` | **SplitSNI** |
|---|---|---|
| **Layer of Operation** | **Layer 4 (TCP / IP Headers)** | **Layer 7 (TLS Record Framing)** |
| **Privileges Required** | **Requires Root / Administrator** (Raw sockets needed to forge TCP headers) | **Zero Admin Rights** (Runs in standard user space with regular sockets) |
| **Mechanism** | Injects fake packet with past sequence numbers (`--wrong-seq`) | Slices single ClientHello into 2 RFC-standard records |
| **DPI Reliability** | Can fail against DPIs that track TCP sequence state or ignore past ACKs | Bypasses stateful DPI by breaking record-layer assumption |
| **RFC Compliance** | Non-standard TCP packet injection | **100% RFC 8446 / RFC 5246 compliant** |
| **Antivirus Safety** | May trigger antivirus / Defender flags due to raw packet crafting | Standard application traffic; zero antivirus detection risk |
| **Cross-Platform** | Requires OS-specific raw socket APIs or drivers | Pure Python / Go / Rust; works on Windows, Linux, macOS, Android |

---

## 4. How to Use with v2rayN (Easiest Setup)

### Step 1: Configure & Start SplitSNI

Edit `config.json` with your CDN/server IP and port:

```json
{
  "listen_host": "127.0.0.1",
  "listen_port": 10850,
  "remote_host": "188.114.97.6",
  "remote_port": 443,
  "split_offset": 40
}
```

Then start SplitSNI (either double-click `start_splitsni.bat` or run):

```bash
python splitsni.py
```

### Step 2: Configure v2rayN

In v2rayN, edit your existing **VLESS / VMess / Trojan** node:

1. **Address (Server IP):** Change to `127.0.0.1`
2. **Port:** Change to `10850`
3. **SNI / Host:** Keep your real domain (e.g., `your-domain.com` or your CDN domain) — **do not change it**!
4. **Path / UUID / Encryption:** Keep exactly as they are.

Click **Confirm**.

```text
[v2rayN Client]
       │  (Dials 127.0.0.1:10850 with real SNI)
       ▼
[SplitSNI]  --> Slices ClientHello into Record 1 + Record 2
       │
       ▼
[Internet / ISP DPI]  --> DPI cannot locate SNI inside Record 1
       │
       ▼
[Cloudflare Edge / VLESS/Trojan Node]  --> Reassembles records and completes TLS 1.3
```

---

## 5. Alternative Usage Modes

### SOCKS5 / HTTP Proxy Mode
SplitSNI also operates as a standard SOCKS5 and HTTP CONNECT proxy:
* **SOCKS5 Proxy:** `127.0.0.1:10850`
* **HTTP Proxy:** `127.0.0.1:10850`

Any client (Firefox, Chrome, `curl`) configured to use `127.0.0.1:10850` will have its outbound TLS connections automatically multi-record framed.


## 6. Performance & Overhead

* **Bandwidth & Throughput:** **0% reduction.** SplitSNI performs zero encryption, decryption, or payload inspection on application data. It acts as an asynchronous kernel-buffered stream relay (`select()` with 64KB buffers) running at native wire speed.
* **Latency (RTT):** Both TLS records are packed into the exact same initial TCP segment. There is zero artificial sleep or RTT delay added during connection establishment.

## 7. Acknowledgments & References

* Inspired by the network research in [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) on SNI manipulation and DPI middlebox evaluation.
* [RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3 (Section 5.1)](https://datatracker.ietf.org/doc/html/rfc8446#section-5.1)
* [RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2 (Section 6.2.1)](https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.1)
