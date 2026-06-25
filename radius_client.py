"""
Pure-Python RADIUS over TCP with SOCKS5 support.
RFC 2865 (Authentication) + RFC 2866 (Accounting) + RFC 6613 (TCP transport)
"""

import hashlib
import hmac
import os
import socket
import struct
from typing import Optional, Dict

import socks

# ── Codes ─────────────────────────────────────────────────────────────────────
ACCESS_REQUEST    = 1
ACCESS_ACCEPT     = 2
ACCESS_REJECT     = 3
ACCOUNTING_REQUEST  = 4
ACCOUNTING_RESPONSE = 5

# ── Attribute types ───────────────────────────────────────────────────────────
A_USER_NAME         = 1
A_USER_PASSWORD     = 2
A_CHAP_PASSWORD     = 3
A_NAS_IP            = 4
A_NAS_PORT          = 5
A_SERVICE_TYPE      = 6
A_FRAMED_PROTO      = 7
A_FRAMED_IP         = 8
A_CHAP_CHALLENGE    = 60
A_CALLED_STATION    = 30
A_CALLING_STATION   = 31
A_NAS_IDENTIFIER    = 32
A_ACCT_STATUS_TYPE  = 40
A_ACCT_DELAY        = 41
A_ACCT_IN_OCT       = 42
A_ACCT_OUT_OCT      = 43
A_ACCT_SESSION_ID   = 44
A_ACCT_SESSION_TIME = 46
A_ACCT_IN_PKTS      = 47
A_ACCT_OUT_PKTS     = 48
A_NAS_PORT_TYPE     = 61
A_EAP_MESSAGE       = 79
A_VENDOR_SPECIFIC   = 26

# Microsoft Vendor-ID for MS-CHAP
VENDOR_MICROSOFT    = 311
MS_CHAP_CHALLENGE   = 11
MS_CHAP2_RESPONSE   = 25

# ── Acct-Status-Type values ───────────────────────────────────────────────────
ACCT_START   = 1
ACCT_STOP    = 2
ACCT_INTERIM = 3


# ── Low-level attribute encoding ──────────────────────────────────────────────

def _attr(t: int, v: bytes) -> bytes:
    return struct.pack("!BB", t, len(v) + 2) + v

def _str(t: int, s: str) -> bytes:
    return _attr(t, s.encode())

def _int(t: int, n: int) -> bytes:
    return _attr(t, struct.pack("!I", n))

def _ip(t: int, ip: str) -> bytes:
    try:
        return _attr(t, socket.inet_aton(ip))
    except OSError:
        return _attr(t, socket.inet_aton("0.0.0.0"))


def _encrypt_password(password: str, secret: bytes, authenticator: bytes) -> bytes:
    """RFC 2865 §5.2 User-Password obfuscation (PAP)."""
    pw = password.encode()
    # pad to multiple of 16
    pad = (16 - len(pw) % 16) % 16
    if not pw:
        pad = 16
    pw += b"\x00" * pad

    out, last = b"", authenticator
    for i in range(0, len(pw), 16):
        digest = hashlib.md5(secret + last).digest()
        chunk = bytes(x ^ y for x, y in zip(pw[i:i + 16], digest))
        out += chunk
        last = chunk
    return out


def _chap_password(password: str, chap_id: int, challenge: bytes) -> bytes:
    """RFC 1994 CHAP-Password: 1-byte ident + MD5(ident+password+challenge)."""
    digest = hashlib.md5(bytes([chap_id]) + password.encode() + challenge).digest()
    return bytes([chap_id]) + digest


def _vendor_attr(vendor_id: int, vendor_type: int, value: bytes) -> bytes:
    """Build a Vendor-Specific attribute (RFC 2865 §5.26)."""
    vsa = struct.pack("!IBB", vendor_id, vendor_type, len(value) + 2) + value
    return _attr(A_VENDOR_SPECIFIC, vsa)


def _ms_chap2_response(
    username: str, password: str, challenge: bytes, peer_challenge: bytes
) -> bytes:
    """
    Build MS-CHAPv2 Response value (RFC 2759).
    Returns the 50-byte binary blob used as MS-CHAP2-Response value.
    """
    # NT hash of password
    nt_hash = hashlib.new("md4", password.encode("utf-16-le")).digest()

    # Challenge hash: SHA1(peer_challenge + challenge + username)[:8]
    c_hash = hashlib.sha1(peer_challenge + challenge + username.encode()).digest()[:8]

    # NT response (DES-based): 24 bytes
    from Crypto.Cipher import DES

    def _des_ecb(key_7: bytes, data: bytes) -> bytes:
        """DES ECB with 7-byte key expanded to 8-byte parity key."""
        def expand(k7):
            k8 = bytearray(8)
            k8[0] = k7[0] >> 1
            k8[1] = ((k7[0] & 0x01) << 6) | (k7[1] >> 2)
            k8[2] = ((k7[1] & 0x03) << 5) | (k7[2] >> 3)
            k8[3] = ((k7[2] & 0x07) << 4) | (k7[3] >> 4)
            k8[4] = ((k7[3] & 0x0F) << 3) | (k7[4] >> 5)
            k8[5] = ((k7[4] & 0x1F) << 2) | (k7[5] >> 6)
            k8[6] = ((k7[5] & 0x3F) << 1) | (k7[6] >> 7)
            k8[7] = k7[6] & 0x7F
            return bytes(b << 1 for b in k8)
        return DES.new(expand(key_7), DES.MODE_ECB).encrypt(data)

    padded = nt_hash + b"\x00" * 5
    nt_response = (
        _des_ecb(padded[0:7], c_hash)
        + _des_ecb(padded[7:14], c_hash)
        + _des_ecb(padded[14:21], c_hash)
    )

    # MS-CHAP2-Response: ident(1) + flags(1) + peer_challenge(16)
    #                    + reserved(8) + nt_response(24)
    ident = os.urandom(1)
    return ident + b"\x00" + peer_challenge + b"\x00" * 8 + nt_response


def _eap_identity_frame(username: str) -> bytes:
    """Build a minimal EAP-Response/Identity packet (RFC 3748)."""
    identity = username.encode()
    # EAP header: code(1)=2(Response), id(1)=1, length(2), type(1)=1(Identity)
    length = 5 + len(identity)
    return struct.pack("!BBHB", 2, 1, length, 1) + identity


# ── Packet builders ───────────────────────────────────────────────────────────

def build_access_request(
    identifier: int, secret: str, username: str, password: str,
    nas_ip: str, nas_port: int = 0,
    calling_station: str = None, called_station: str = None,
    nas_identifier: str = None,
    lcp_protocol: str = "PAP",
) -> bytes:
    secret_b = secret.encode()
    auth = os.urandom(16)

    proto = (lcp_protocol or "PAP").upper()

    attrs = b""
    attrs += _str(A_USER_NAME, username)
    attrs += _ip(A_NAS_IP, nas_ip)
    attrs += _int(A_NAS_PORT, nas_port)
    attrs += _int(A_SERVICE_TYPE, 2)    # Framed
    attrs += _int(A_FRAMED_PROTO, 1)    # PPP
    attrs += _int(A_NAS_PORT_TYPE, 15)  # Ethernet
    if calling_station:
        attrs += _str(A_CALLING_STATION, calling_station)
    if called_station:
        attrs += _str(A_CALLED_STATION, called_station)
    if nas_identifier:
        attrs += _str(A_NAS_IDENTIFIER, nas_identifier)

    if proto == "PAP":
        attrs += _attr(A_USER_PASSWORD, _encrypt_password(password, secret_b, auth))

    elif proto == "CHAP":
        chap_id   = identifier & 0xFF
        challenge = os.urandom(16)
        attrs += _attr(A_CHAP_CHALLENGE, challenge)
        attrs += _attr(A_CHAP_PASSWORD, _chap_password(password, chap_id, challenge))

    elif proto == "MS-CHAPv2":
        challenge      = os.urandom(16)
        peer_challenge = os.urandom(16)
        response_value = _ms_chap2_response(username, password, challenge, peer_challenge)
        attrs += _vendor_attr(VENDOR_MICROSOFT, MS_CHAP_CHALLENGE, challenge)
        attrs += _vendor_attr(VENDOR_MICROSOFT, MS_CHAP2_RESPONSE, response_value)

    elif proto == "EAP":
        eap_frame = _eap_identity_frame(username)
        attrs += _attr(A_EAP_MESSAGE, eap_frame)

    else:  # fallback PAP
        attrs += _attr(A_USER_PASSWORD, _encrypt_password(password, secret_b, auth))

    length = 20 + len(attrs)
    hdr = struct.pack("!BBH16s", ACCESS_REQUEST, identifier, length, auth)
    return hdr + attrs


def build_accounting_request(
    identifier: int, secret: str, username: str, session_id: str,
    status_type: int, nas_ip: str, nas_port: int = 0,
    session_time: int = 0, in_octets: int = 0, out_octets: int = 0,
    in_pkts: int = 0, out_pkts: int = 0, framed_ip: str = None,
    calling_station: str = None, called_station: str = None,
    nas_identifier: str = None,
) -> bytes:
    secret_b = secret.encode()

    attrs = b""
    attrs += _int(A_ACCT_STATUS_TYPE, status_type)
    attrs += _str(A_USER_NAME, username)
    attrs += _str(A_ACCT_SESSION_ID, session_id)
    attrs += _ip(A_NAS_IP, nas_ip)
    attrs += _int(A_NAS_PORT, nas_port)
    attrs += _int(A_SERVICE_TYPE, 2)
    attrs += _int(A_FRAMED_PROTO, 1)
    attrs += _int(A_NAS_PORT_TYPE, 15)
    attrs += _int(A_ACCT_DELAY, 0)

    if status_type in (ACCT_STOP, ACCT_INTERIM):
        attrs += _int(A_ACCT_SESSION_TIME, session_time)
        attrs += _int(A_ACCT_IN_OCT,  in_octets  & 0xFFFFFFFF)
        attrs += _int(A_ACCT_OUT_OCT, out_octets & 0xFFFFFFFF)
        attrs += _int(A_ACCT_IN_PKTS,  in_pkts)
        attrs += _int(A_ACCT_OUT_PKTS, out_pkts)

    if framed_ip:
        attrs += _ip(A_FRAMED_IP, framed_ip)
    if calling_station:
        attrs += _str(A_CALLING_STATION, calling_station)
    if called_station:
        attrs += _str(A_CALLED_STATION, called_station)
    if nas_identifier:
        attrs += _str(A_NAS_IDENTIFIER, nas_identifier)

    length = 20 + len(attrs)

    # Accounting authenticator = MD5(Code+ID+Len+16×0x00+Attrs+Secret)
    zero = b"\x00" * 16
    tmp = struct.pack("!BBH16s", ACCOUNTING_REQUEST, identifier, length, zero)
    auth = hashlib.md5(tmp + attrs + secret_b).digest()

    hdr = struct.pack("!BBH16s", ACCOUNTING_REQUEST, identifier, length, auth)
    return hdr + attrs


# ── TCP transport ─────────────────────────────────────────────────────────────

def _recv_packet(sock) -> Optional[bytes]:
    """Read exactly one RADIUS packet from a TCP stream."""
    buf = b""
    while len(buf) < 4:
        chunk = sock.recv(4 - len(buf))
        if not chunk:
            return None
        buf += chunk

    total = struct.unpack("!H", buf[2:4])[0]
    if not (20 <= total <= 4096):
        return None

    while len(buf) < total:
        chunk = sock.recv(total - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def send_packet(
    pkt: bytes, server_ip: str, server_port: int,
    proxy_ip: str = None, proxy_port: int = None,
    timeout: int = 15,
) -> Optional[bytes]:
    """Send RADIUS packet over TCP, optionally through SOCKS5 proxy."""
    if proxy_ip and proxy_port:
        s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        s.set_proxy(socks.SOCKS5, proxy_ip, int(proxy_port))
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.settimeout(timeout)
    try:
        s.connect((server_ip, int(server_port)))
        s.sendall(pkt)
        return _recv_packet(s)
    finally:
        s.close()


def parse_response(data: bytes) -> Dict:
    """Parse a raw RADIUS response into a dict."""
    if not data or len(data) < 20:
        return {"code": 0, "code_name": "Invalid", "framed_ip": None,
                "reply_msg": None, "attributes": {}}

    code, ident, length = struct.unpack("!BBH", data[:4])
    attrs: Dict[int, bytes] = {}
    pos = 20
    while pos + 2 <= len(data):
        t, l = data[pos], data[pos + 1]
        if l < 2:
            break
        attrs[t] = data[pos + 2: pos + l]
        pos += l

    names = {2: "Access-Accept", 3: "Access-Reject",
             5: "Accounting-Response", 11: "Access-Challenge"}

    framed_ip = None
    if A_FRAMED_IP in attrs and len(attrs[A_FRAMED_IP]) == 4:
        try:
            framed_ip = socket.inet_ntoa(attrs[A_FRAMED_IP])
        except OSError:
            pass

    reply_msg = None
    if 18 in attrs:
        try:
            reply_msg = attrs[18].decode(errors="replace")
        except Exception:
            pass

    return {
        "code": code,
        "code_name": names.get(code, f"Unknown({code})"),
        "identifier": ident,
        "framed_ip": framed_ip,
        "reply_msg": reply_msg,
        "attributes": attrs,
    }