#!/usr/bin/env python3
"""
handshake.py  —  CSCE 465

Authenticated finite-field Diffie-Hellman handshake between a simulated
gateway and node, run in-process (no sockets). The two parties exchange
"messages" as Python dicts passed between function calls.

Security design
---------------
  * Confidential, forward-secret session keys come from an EPHEMERAL DH
    exchange in the standardized ffdhe3072 group (RFC 7919).
  * Authentication is provided by long-term 3072-bit RSA keys: each party
    signs the handshake transcript with RSA-PSS + SHA-256. The RSA keys
    sign ONLY; they never encrypt application data.
  * Binding the signature to the full transcript (both DH publics, both
    nonces, both identities, the group id and a protocol label) defeats
    tampering, reflection and unknown-key-share style attacks.

Libraries
---------
  * `cryptography` for RSA and DH primitives (no hand-rolled math).
  * stdlib `hashlib` / `hmac` for SHA-256 and HMAC-SHA256.

Run:   python3 handshake.py
"""

import os
import sys
import copy
import hashlib
import hmac
import subprocess

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.exceptions import InvalidSignature


# ===========================================================================
# Constants
# ===========================================================================
PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"
MODULUS_BYTES = 384          # 3072 bits / 8  -> fixed-width encoding of DH values and Z
NONCE_BYTES = 16
PARAMS_PEM = "ffdhe3072.pem"


# ===========================================================================
# DH group loading  (load ffdhe3072.pem, or generate it with openssl)
# ===========================================================================
def load_or_create_params(path=PARAMS_PEM):
    if not os.path.exists(path):
        print(f"[setup] {path} not found; generating with openssl ...")
        # RFC 7919 ffdhe3072 is a named group in modern openssl.
        try:
            subprocess.run(
                ["openssl", "genpkey", "-genparam", "-algorithm", "DH",
                 "-pkeyopt", "group:ffdhe3072", "-out", path],
                check=True, capture_output=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback: emit standard 3072-bit DH parameters.
            print("[setup] named-group generation unavailable; "
                  "falling back to 'openssl dhparam 3072' (slower) ...")
            subprocess.run(
                ["openssl", "dhparam", "-out", path, "3072"],
                check=True, capture_output=True,
            )
    with open(path, "rb") as f:
        params = serialization.load_pem_parameters(f.read())
    if not isinstance(params, dh.DHParameters):
        raise ValueError("PEM did not contain DH parameters")
    return params


# ===========================================================================
# Encoding helpers
# ===========================================================================
def i2osp(value, length):
    """Integer -> fixed-length big-endian bytes, left-zero-padded."""
    return value.to_bytes(length, "big")


def dh_public_bytes(pubkey):
    """ffdhe public value y as a fixed 384-byte big-endian string."""
    y = pubkey.public_numbers().y
    return i2osp(y, MODULUS_BYTES)


def tlv_encode(fields):
    """Each field: 4-byte big-endian length prefix, then the bytes."""
    out = bytearray()
    for f in fields:
        out += len(f).to_bytes(4, "big")
        out += f
    return bytes(out)


def tlv_decode(buf):
    """
    Decode a TLV buffer. Rejects a field whose declared length overruns
    the buffer, BEFORE anything downstream hashes or trusts it.
    """
    fields = []
    i = 0
    n = len(buf)
    while i < n:
        if i + 4 > n:
            raise ValueError("TLV: truncated length prefix")
        ln = int.from_bytes(buf[i:i + 4], "big")
        i += 4
        if i + ln > n:                      # declared length overruns buffer
            raise ValueError(
                f"TLV: field length {ln} overruns buffer "
                f"({n - i} bytes remain)")
        fields.append(buf[i:i + ln])
        i += ln
    return fields


def build_transcript(g_id, n_id, g_pub, n_pub, g_nonce, n_nonce):
    """Canonical transcript, fields in the exact required order."""
    return tlv_encode([
        PROTOCOL_LABEL,          # protocol label
        GROUP_ID,                # group id
        g_id,                    # gateway identity
        n_id,                    # node identity
        g_pub,                   # gateway DH public value (384B)
        n_pub,                   # node DH public value (384B)
        g_nonce,                 # gateway nonce (16B)
        n_nonce,                 # node nonce (16B)
    ])


def transcript_hash(transcript):
    return hashlib.sha256(transcript).digest()


# ===========================================================================
# KDF  (exactly as specified — do not redesign)
# ===========================================================================
def derive_keys(Z, transcript):
    TH = hashlib.sha256(transcript).digest()
    K_master = hashlib.sha256(b"CSCE465-KDF-v1" + Z + TH).digest()

    def mac(label):
        return hmac.new(K_master, label + TH, hashlib.sha256).digest()

    keys = {
        "K_master":  K_master,
        "K_g2n_enc": mac(b"gateway-to-node encryption"),
        "K_g2n_mac": mac(b"gateway-to-node MAC"),
        "K_n2g_enc": mac(b"node-to-gateway encryption"),
        "K_n2g_mac": mac(b"node-to-gateway MAC"),
        "session_id": mac(b"session identifier")[:8],
    }
    return keys


# ===========================================================================
# RSA-PSS signing / verification over  role || SHA-256(transcript)
# ===========================================================================
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                  salt_length=padding.PSS.MAX_LENGTH)


def sign_transcript(priv, role, transcript):
    msg = role + transcript_hash(transcript)
    return priv.sign(msg, PSS, hashes.SHA256())


def verify_transcript(pub, role, transcript, signature):
    msg = role + transcript_hash(transcript)
    pub.verify(signature, msg, PSS, hashes.SHA256())   # raises InvalidSignature


# ===========================================================================
# Party abstraction
# ===========================================================================
class Party:
    def __init__(self, identity, role, params):
        self.identity = identity              # bytes
        self.role = role                      # b"gateway" or b"node"
        self.params = params
        self.rsa_priv = rsa.generate_private_key(public_exponent=65537,
                                                 key_size=3072)
        self.rsa_pub = self.rsa_priv.public_key()

    def new_ephemeral(self):
        """Fresh per-session DH keypair and nonce."""
        self.dh_priv = self.params.generate_private_key()
        self.dh_pub = self.dh_priv.public_key()
        self.nonce = os.urandom(NONCE_BYTES)
        return {
            "identity": self.identity,
            "role": self.role,
            "dh_pub": dh_public_bytes(self.dh_pub),
            "nonce": self.nonce,
        }

    def peer_pubkey_from_y(self, y_bytes):
        """Reconstruct a peer DH public key from its 384-byte y value."""
        y = int.from_bytes(y_bytes, "big")
        pn = self.params.parameter_numbers()
        return dh.DHPublicNumbers(y, pn).public_key()

    def shared_Z(self, peer_y_bytes):
        peer_pub = self.peer_pubkey_from_y(peer_y_bytes)
        shared = self.dh_priv.exchange(peer_pub)          # big-endian bytes
        # Left-zero-pad Z to the modulus width.
        return shared.rjust(MODULUS_BYTES, b"\x00")


# ===========================================================================
# The handshake, driven in-process
# ===========================================================================
def run_handshake(gateway, node, g_pub_rsa, n_pub_rsa,
                  tamper=None, verbose=True):
    """
    tamper: optional callable(msg_g, msg_n, sig_g, sig_n) -> mutated tuple,
            used by the negative tests to corrupt the exchange.
    Returns (gateway_keys, node_keys). Raises on any rejection.
    """
    # ---- Round 1: each side produces its ephemeral message ----
    msg_g = gateway.new_ephemeral()
    msg_n = node.new_ephemeral()

    # ---- Each side builds the SAME canonical transcript ----
    def make_transcript(mg, mn):
        return build_transcript(
            mg["identity"], mn["identity"],
            mg["dh_pub"],   mn["dh_pub"],
            mg["nonce"],    mn["nonce"])

    transcript_g = make_transcript(msg_g, msg_n)
    transcript_n = make_transcript(msg_g, msg_n)

    # ---- Each side signs role || SHA-256(transcript) ----
    sig_g = sign_transcript(gateway.rsa_priv, b"gateway", transcript_g)
    sig_n = sign_transcript(node.rsa_priv,    b"node",    transcript_n)

    # ---- Optional corruption hook (negative tests) ----
    if tamper is not None:
        msg_g, msg_n, sig_g, sig_n = tamper(msg_g, msg_n, sig_g, sig_n)

    # =====================================================================
    # GATEWAY verifies NODE
    # =====================================================================
    # Expect the peer to actually be the node (identity + role check).
    if msg_n["identity"] != node.identity:
        raise ValueError("gateway: unexpected peer identity")
    if msg_n["role"] != b"node":
        raise ValueError("gateway: peer did not present node role "
                         "(possible reflection)")

    g_view = make_transcript(msg_g, msg_n)
    # Decode-and-validate TLV before trusting/hashing (malformed -> reject).
    tlv_decode(g_view)
    verify_transcript(n_pub_rsa, b"node", g_view, sig_n)
    Z_g = gateway.shared_Z(msg_n["dh_pub"])
    gateway_keys = derive_keys(Z_g, g_view)

    # =====================================================================
    # NODE verifies GATEWAY
    # =====================================================================
    if msg_g["identity"] != gateway.identity:
        raise ValueError("node: unexpected peer identity")
    if msg_g["role"] != b"gateway":
        raise ValueError("node: peer did not present gateway role "
                         "(possible reflection)")

    n_view = make_transcript(msg_g, msg_n)
    tlv_decode(n_view)
    verify_transcript(g_pub_rsa, b"gateway", n_view, sig_g)
    Z_n = node.shared_Z(msg_g["dh_pub"])
    node_keys = derive_keys(Z_n, n_view)

    if verbose:
        print("  gateway sees node signature: VALID")
        print("  node sees gateway signature: VALID")

    return gateway_keys, node_keys


# ===========================================================================
# Pretty-printing
# ===========================================================================
def show_keys(name, keys):
    print(f"  [{name}] session_id = {keys['session_id'].hex()}")
    for k in ("K_master", "K_g2n_enc", "K_g2n_mac", "K_n2g_enc", "K_n2g_mac"):
        print(f"           {k:<10} = {keys[k].hex()}")


# ===========================================================================
# Main: happy path + negative tests
# ===========================================================================
def main():
    params = load_or_create_params()

    def fresh_parties():
        g = Party(b"gateway.csce465.local", b"gateway", params)
        n = Party(b"node-07.csce465.local", b"node", params)
        return g, n

    print("\n" + "=" * 70)
    print("HAPPY PATH")
    print("=" * 70)
    gateway, node = fresh_parties()
    gk, nk = run_handshake(gateway, node,
                           gateway.rsa_pub, node.rsa_pub)
    show_keys("gateway", gk)
    show_keys("node", nk)
    assert gk == nk, "keys differ!"
    print("\n  RESULT: both sides derived IDENTICAL keys.")
    print(f"  SESSION ID: {gk['session_id'].hex()}")

    # -------------------------------------------------------------------
    # Negative tests — each MUST be rejected.
    # -------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("NEGATIVE TESTS (each must be rejected)")
    print("=" * 70)

    def expect_reject(label, tamper):
        gw, nd = fresh_parties()
        try:
            run_handshake(gw, nd, gw.rsa_pub, nd.rsa_pub,
                          tamper=tamper, verbose=False)
        except (InvalidSignature, ValueError) as e:
            etype = type(e).__name__
            detail = str(e) or etype
            print(f"  [REJECTED] {label:<28} -> {etype}: {detail}")
            return
        print(f"  [FAIL]     {label:<28} -> accepted (should not happen!)")
        sys.exit(1)

    # 1) Invalid signature: corrupt a byte of the node's signature.
    def t_bad_sig(mg, mn, sg, sn):
        sn = bytearray(sn); sn[0] ^= 0x01
        return mg, mn, sg, bytes(sn)
    expect_reject("invalid signature", t_bad_sig)

    # 2) Changed nonce: flip node's nonce AFTER signing (transcript mismatch).
    def t_changed_nonce(mg, mn, sg, sn):
        mn = copy.deepcopy(mn)
        mn["nonce"] = bytes([mn["nonce"][0] ^ 0x01]) + mn["nonce"][1:]
        return mg, mn, sg, sn
    expect_reject("changed nonce", t_changed_nonce)

    # 3) Changed DH public value: flip a byte of gateway's dh_pub after signing.
    def t_changed_dh(mg, mn, sg, sn):
        mg = copy.deepcopy(mg)
        mg["dh_pub"] = bytes([mg["dh_pub"][0] ^ 0x01]) + mg["dh_pub"][1:]
        return mg, mn, sg, sn
    expect_reject("changed DH public value", t_changed_dh)

    # 4) Unexpected peer identity: node claims a different identity.
    def t_bad_identity(mg, mn, sg, sn):
        mn = copy.deepcopy(mn)
        mn["identity"] = b"attacker.evil.example"
        return mg, mn, sg, sn
    expect_reject("unexpected peer identity", t_bad_identity)

    # 5) Reflected handshake: gateway's own message is bounced back to it as
    #    the "node" message (same role=gateway) — a classic reflection.
    def t_reflection(mg, mn, sg, sn):
        return mg, copy.deepcopy(mg), sg, sg
    expect_reject("reflected message", t_reflection)

    # 6) Malformed transcript: a TLV field claims more bytes than exist.
    #    The identity/nonce hooks mutate decoded dict fields; a raw TLV
    #    length-overrun is what arrives on the wire, so we exercise the
    #    decoder directly — it must reject before anything hashes the buffer.
    print("  [decoder] testing TLV length-overrun rejection directly:")
    bad = bytearray()
    bad += (10).to_bytes(4, "big")      # declares 10 bytes ...
    bad += b"abc"                        # ... but only 3 follow
    try:
        tlv_decode(bytes(bad))
        print("  [FAIL]     malformed transcript (bad TLV)  -> accepted!")
        sys.exit(1)
    except ValueError as e:
        print(f"  [REJECTED] malformed transcript (bad TLV)  -> ValueError: {e}")

    print("\nAll negative tests rejected as expected.\n")


if __name__ == "__main__":
    main()
