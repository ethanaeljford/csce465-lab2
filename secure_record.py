#!/usr/bin/env python3
"""
secure_record.py  —  CSCE 465

An Encrypt-then-MAC record layer built on the directional keys produced by
the Task 2 handshake (K_g2n_enc/mac for gateway->node, K_n2g_enc/mac for
node->gateway). Provides stateless `seal()` / `open_record()` primitives and
a stateful `SecureChannel` wrapper that tracks per-direction sequence
counters.

Record format
-------------
  header     = version(1) || direction(1) || sequence(8) || msg_type(1)
               || ciphertext_length(4)                    # 15 bytes, big-endian
  iv         = session_id(8) || sequence(8)               # 16 bytes, NOT sent
  ciphertext = AES-256-CTR(K_enc, iv, plaintext)
  tag        = HMAC-SHA256(K_mac, header || iv || ciphertext)
  wire       = header || ciphertext || tag

Why Encrypt-then-MAC: the MAC covers the header and the (reconstructed) iv as
well as the ciphertext, so any bit flip in the header or ciphertext is caught
by a constant-time tag check BEFORE a single byte is decrypted. Plaintext is
never produced on an error path.

Libraries: `cryptography` for AES-CTR; stdlib `hmac`/`hashlib` for HMAC-SHA256.
Run:       python3 secure_record.py
"""

import os
import hmac
import hashlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ===========================================================================
# Constants
# ===========================================================================
VERSION = 1
HEADER_LEN = 15          # 1 + 1 + 8 + 1 + 4
TAG_LEN = 32             # HMAC-SHA256 output
IV_LEN = 16              # session_id(8) || sequence(8)
SESSION_ID_LEN = 8

# Direction byte values.
DIR_G2N = 0x01           # gateway -> node
DIR_N2G = 0x02           # node -> gateway

MAX_SEQ = (1 << 64) - 1  # sequence is an 8-byte unsigned integer


# ===========================================================================
# Exceptions — every failure raises BEFORE decryption; no plaintext leaks.
# ===========================================================================
class RecordError(Exception):
    """Base class for any record-layer rejection."""


class BadHeader(RecordError):
    pass


class WrongDirection(RecordError):
    pass


class BadSequence(RecordError):
    pass


class AuthenticationError(RecordError):
    """HMAC tag did not verify."""


# ===========================================================================
# IV construction
#
# The IV is session_id(8) || sequence(8). It is derived independently at each
# end from the shared session_id and the sequence carried in the header; it is
# never transmitted.
#
# Why this can NEVER repeat under one key:
#   * K_enc is unique per direction (K_g2n_enc != K_n2g_enc), so the two
#     directions never share a keystream even if they used the same counter.
#   * Within one direction the sequence number is strictly increasing and
#     never reused (the channel refuses to wrap past 2**64-1), so each record
#     under that key gets a distinct sequence and therefore a distinct IV.
#   * session_id is fixed for the session, so (session_id || sequence) is a
#     bijection with sequence -> the IV is unique for every record under the
#     key. Unique (key, IV) is exactly what AES-CTR requires for safety.
# ===========================================================================
def build_iv(session_id, sequence):
    if len(session_id) != SESSION_ID_LEN:
        raise BadHeader("session_id must be 8 bytes")
    return session_id + struct.pack(">Q", sequence)


# ===========================================================================
# AES-256-CTR
# ===========================================================================
def _aes_ctr(key, iv, data):
    if len(key) != 32:
        raise ValueError("K_enc must be 32 bytes (AES-256)")
    if len(iv) != IV_LEN:
        raise ValueError("iv must be 16 bytes")
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    op = cipher.encryptor()
    return op.update(data) + op.finalize()   # CTR: encrypt == decrypt


def _pack_header(direction, sequence, msg_type, ct_len):
    return struct.pack(">BBQBI", VERSION, direction, sequence, msg_type, ct_len)


def _unpack_header(hdr):
    # Raises struct.error if the slice is the wrong size; caller guards length.
    version, direction, sequence, msg_type, ct_len = struct.unpack(">BBQBI", hdr)
    return version, direction, sequence, msg_type, ct_len


# ===========================================================================
# seal() — produce one wire record
# ===========================================================================
def seal(k_enc, k_mac, session_id, direction, sequence, msg_type, plaintext):
    """
    Encrypt-then-MAC one record. Returns the wire bytes.
    `sequence` is supplied by the caller (the channel owns the counter).
    """
    if direction not in (DIR_G2N, DIR_N2G):
        raise BadHeader(f"invalid direction byte {direction:#x}")
    if not (0 <= sequence <= MAX_SEQ):
        raise BadSequence("sequence out of range")
    if not (0 <= msg_type <= 0xFF):
        raise BadHeader("msg_type must fit in one byte")

    iv = build_iv(session_id, sequence)
    ciphertext = _aes_ctr(k_enc, iv, plaintext)
    header = _pack_header(direction, sequence, msg_type, len(ciphertext))
    tag = hmac.new(k_mac, header + iv + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + tag


# ===========================================================================
# open_record() — validate and decrypt one wire record
#
# Order of checks (fail-closed; no plaintext before the tag verifies):
#   1. parse/validate header: length + version + declared ct length
#   2. direction == expected
#   3. sequence == exact expected next
#   4. HMAC verify with hmac.compare_digest (constant time)
#   5. only then decrypt
# ===========================================================================
def open_record(k_enc, k_mac, session_id, expected_direction,
                expected_sequence, wire):
    # ---- 1. Header length + structural validation --------------------------
    if len(wire) < HEADER_LEN + TAG_LEN:
        raise BadHeader("record shorter than header + tag")

    header = wire[:HEADER_LEN]
    version, direction, sequence, msg_type, ct_len = _unpack_header(header)

    if version != VERSION:
        raise BadHeader(f"unsupported version {version}")

    # Total length must match exactly what the header declares.
    expected_total = HEADER_LEN + ct_len + TAG_LEN
    if len(wire) != expected_total:
        raise BadHeader(
            f"length mismatch: header declares ct_len={ct_len} "
            f"(total {expected_total}), got {len(wire)}")

    ciphertext = wire[HEADER_LEN:HEADER_LEN + ct_len]
    tag = wire[HEADER_LEN + ct_len:]

    # ---- 2. Direction ------------------------------------------------------
    if direction != expected_direction:
        raise WrongDirection(
            f"expected direction {expected_direction:#x}, got {direction:#x}")

    # ---- 3. Sequence: must be exactly the next one we expect ---------------
    if sequence != expected_sequence:
        raise BadSequence(
            f"expected sequence {expected_sequence}, got {sequence} "
            f"(replay or reorder)")

    # ---- 4. Reconstruct IV and verify the tag (constant time) --------------
    iv = build_iv(session_id, sequence)
    expected_tag = hmac.new(k_mac, header + iv + ciphertext,
                            hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise AuthenticationError("HMAC verification failed")

    # ---- 5. Only now decrypt ----------------------------------------------
    plaintext = _aes_ctr(k_enc, iv, ciphertext)
    return msg_type, plaintext


# ===========================================================================
# Stateful channel wrapper
# ===========================================================================
class SecureChannel:
    """
    Holds both directions' keys and the four sequence counters for one
    endpoint. `role` is "gateway" or "node" and selects which direction this
    endpoint sends on vs receives on.
    """

    def __init__(self, role, session_id, keys):
        assert role in ("gateway", "node")
        self.role = role
        self.session_id = session_id

        # keys dict uses the Task 2 names.
        self.k_g2n_enc = keys["K_g2n_enc"]
        self.k_g2n_mac = keys["K_g2n_mac"]
        self.k_n2g_enc = keys["K_n2g_enc"]
        self.k_n2g_mac = keys["K_n2g_mac"]

        if role == "gateway":
            self.send_dir, self.recv_dir = DIR_G2N, DIR_N2G
        else:
            self.send_dir, self.recv_dir = DIR_N2G, DIR_G2N

        # Sequence counters start at 0 in each direction.
        self.send_seq = 0
        self.recv_seq = 0

    def _keys_for(self, direction):
        if direction == DIR_G2N:
            return self.k_g2n_enc, self.k_g2n_mac
        return self.k_n2g_enc, self.k_n2g_mac

    def send(self, msg_type, plaintext):
        if self.send_seq > MAX_SEQ:
            raise BadSequence("sequence space exhausted; rekey required")
        k_enc, k_mac = self._keys_for(self.send_dir)
        wire = seal(k_enc, k_mac, self.session_id, self.send_dir,
                    self.send_seq, msg_type, plaintext)
        self.send_seq += 1
        return wire

    def receive(self, wire):
        k_enc, k_mac = self._keys_for(self.recv_dir)
        msg_type, plaintext = open_record(
            k_enc, k_mac, self.session_id, self.recv_dir,
            self.recv_seq, wire)
        # Advance only after a fully successful open.
        self.recv_seq += 1
        return msg_type, plaintext


# ===========================================================================
# Demo
# ===========================================================================
def _fake_session_keys():
    """
    Stand-in for the four directional keys the Task 2 handshake outputs.
    Here they are random; in the real system they come from the KDF.
    """
    return {
        "K_g2n_enc": os.urandom(32),
        "K_g2n_mac": os.urandom(32),
        "K_n2g_enc": os.urandom(32),
        "K_n2g_mac": os.urandom(32),
    }


def section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def main():
    session_id = os.urandom(SESSION_ID_LEN)
    keys = _fake_session_keys()

    gateway = SecureChannel("gateway", session_id, keys)
    node = SecureChannel("node", session_id, keys)

    MSG_DATA = 0x10

    # -------------------------------------------------------------------
    section("HAPPY PATH — in-order records, both directions")
    # -------------------------------------------------------------------
    w1 = gateway.send(MSG_DATA, b"hello node, this is the gateway")
    mt, pt = node.receive(w1)
    print(f"  gateway->node  seq0  type={mt:#x}  plaintext={pt!r}")

    w2 = gateway.send(MSG_DATA, b"second gateway message")
    mt, pt = node.receive(w2)
    print(f"  gateway->node  seq1  type={mt:#x}  plaintext={pt!r}")

    r1 = node.send(MSG_DATA, b"ack from node")
    mt, pt = gateway.receive(r1)
    print(f"  node->gateway  seq0  type={mt:#x}  plaintext={pt!r}")

    print("\n  Both directions exchanged records in order. OK.")

    # -------------------------------------------------------------------
    section("NEGATIVE TESTS — each must be rejected")
    # -------------------------------------------------------------------
    def expect_reject(label, fn):
        try:
            fn()
        except RecordError as e:
            print(f"  [REJECTED] {label:<22} -> {type(e).__name__}: {e}")
        else:
            print(f"  [FAIL]     {label:<22} -> accepted (should not happen!)")
            raise SystemExit(1)

    # Build a fresh, independent pair so these tests don't disturb counters.
    def fresh_pair():
        sid = os.urandom(SESSION_ID_LEN)
        k = _fake_session_keys()
        return (SecureChannel("gateway", sid, k),
                SecureChannel("node", sid, k))

    # 1) Modified ciphertext.
    def t_mod_ct():
        g, n = fresh_pair()
        w = bytearray(g.send(MSG_DATA, b"payload under attack"))
        w[HEADER_LEN] ^= 0x01           # flip a ciphertext byte
        n.receive(bytes(w))
    expect_reject("modified ciphertext", t_mod_ct)

    # 2) Modified header (flip a bit of msg_type).
    def t_mod_hdr():
        g, n = fresh_pair()
        w = bytearray(g.send(MSG_DATA, b"payload"))
        w[10] ^= 0x01                   # msg_type byte sits at offset 10
        n.receive(bytes(w))
    expect_reject("modified header", t_mod_hdr)

    # 3) Replay (deliver the same valid record twice).
    def t_replay():
        g, n = fresh_pair()
        w = g.send(MSG_DATA, b"replay me")
        n.receive(w)                    # seq 0 accepted
        n.receive(w)                    # same seq 0 again -> rejected
    expect_reject("replay", t_replay)

    # 4) Out-of-order (skip seq 0, deliver seq 1 first).
    def t_reorder():
        g, n = fresh_pair()
        _ = g.send(MSG_DATA, b"first")   # seq 0 (held back)
        w1 = g.send(MSG_DATA, b"second") # seq 1
        n.receive(w1)                    # receiver still expects seq 0
    expect_reject("out-of-order", t_reorder)

    # 5) Wrong direction (feed a gateway->node record to the node's sender
    #    side by asking the gateway to open its own outbound record).
    def t_wrong_dir():
        g, n = fresh_pair()
        w = g.send(MSG_DATA, b"outbound from gateway")  # direction = G2N
        g.receive(w)                    # gateway expects to RECEIVE N2G
    expect_reject("wrong direction", t_wrong_dir)

    # 6) Forged tag (attacker appends a random 32-byte tag to a chosen record).
    def t_forged_tag():
        g, n = fresh_pair()
        w = g.send(MSG_DATA, b"forge this")
        forged = bytearray(w)
        forged[-TAG_LEN:] = os.urandom(TAG_LEN)
        n.receive(bytes(forged))
    expect_reject("forged tag", t_forged_tag)

    print("\nAll negative tests rejected as expected. No plaintext released "
          "on any error path.\n")


if __name__ == "__main__":
    main()
