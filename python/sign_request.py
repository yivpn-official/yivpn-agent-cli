#!/usr/bin/env python3
"""
Minimal Python 3 Ed25519 request signer & client for YIVPN Agent VPN API (ed25519-v1).
Requires: pip install cryptography
"""
import base64
import hashlib
import json
import os
import sys
import time
import urllib.request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

API_BASE = os.environ.get("YIVPN_API_BASE", "https://yivpn.net/api/v1/vpn")


def generate_keypair():
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return priv, pub_hex, priv_pem


def sign_headers(priv: Ed25519PrivateKey, pub_hex: str, method: str, canonical_path: str, raw_body: bytes = b"") -> dict:
    ts = str(int(time.time()))
    body_sha = hashlib.sha256(raw_body).hexdigest()
    payload = f"yivpn-ed25519-v1\n{method.upper()}\n{canonical_path}\n{ts}\n{body_sha}".encode("utf-8")
    sig_b64 = base64.b64encode(priv.sign(payload)).decode("ascii")
    return {
        "X-YIVPN-Pubkey": pub_hex,
        "X-YIVPN-Timestamp": ts,
        "X-YIVPN-Signature": sig_b64,
    }


if __name__ == "__main__":
    priv, pub_hex, _ = generate_keypair()
    path = "/api/v1/vpn/status"
    hdrs = sign_headers(priv, pub_hex, "GET", path)
    req = urllib.request.Request(f"https://yivpn.net{path}", headers=hdrs, method="GET")
    with urllib.request.urlopen(req, timeout=15) as resp:
        print(json.dumps(json.loads(resp.read().decode("utf-8")), indent=2))
