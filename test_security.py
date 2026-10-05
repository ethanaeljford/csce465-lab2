#!/usr/bin/env python3
"""
test_security.py  —  CSCE 465

Automated adversarial tests for the authenticated handshake (Task 2,
handshake.py) and the Encrypt-then-MAC record layer (Task 3,
secure_record.py).

Nothing here re-implements crypto: it imports the real modules and drives
their public interfaces (run_handshake + its tamper hook, Party, and
SecureChannel), asserting that every attack produces a SPECIFIC safe
failure — the exact exception type — and that the record layer never
returns plaintext on a failure path.

Run:  python -m unittest test_security.py -v
"""

import copy
import unittest

from cryptography.exceptions import InvalidSignature

import handshake
from handshake import Party, run_handshake, load_or_create_params

import secure_record
from secure_record import (
    SecureChannel,
    AuthenticationError,
    BadSequence,
    WrongDirection,
    HEADER_LEN,
    TAG_LEN,
    DIR_G2N,
)

# A valid application message type byte for the record layer.
MSG_DATA = 0x10


class SecurityTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """RSA-3072 keygen and DH params are slow — do them ONCE."""
        cls.params = load_or_create_params()
        # Two long-term identities, plus a third used as a "wrong" verifier.
        cls.gateway = Party(b"gateway.csce465.local", b"gateway", cls.params)
        cls.node = Party(b"node-07.csce465.local", b"node", cls.params)
        cls.stranger = Party(b"stranger.csce465.local", b"gateway", cls.params)

    # Helper: run a clean handshake and return (gateway_keys, node_keys).
    def _good_handshake(self):
        return run_handshake(
            self.gateway, self.node,
            self.gateway.rsa_pub, self.node.rsa_pub,
            verbose=False)

    # Helper: build a wired-up pair of channels from handshake output.
    def _channels(self):
        gk, nk = self._good_handshake()
        self.assertEqual(gk, nk, "handshake must yield identical key sets")
        sid = gk["session_id"]
        g_chan = SecureChannel("gateway", sid, gk)
        n_chan = SecureChannel("node", sid, nk)
        return g_chan, n_chan

    # ------------------------------------------------------------------
    # 1. Happy path: identical keys + bidirectional round-trip.
    # ------------------------------------------------------------------
    def test_1_happy_path(self):
        gk, nk = self._good_handshake()
        self.assertEqual(gk, nk)
        self.assertEqual(len(gk["session_id"]), 8)

        g_chan, n_chan = self._channels()

        # gateway -> node
        pt_g = b"hello node, this is the gateway"
        mt, out = n_chan.receive(g_chan.send(MSG_DATA, pt_g))
        self.assertEqual(mt, MSG_DATA)
        self.assertEqual(out, pt_g)

        # node -> gateway
        pt_n = b"ack from node"
        mt, out = g_chan.receive(n_chan.send(MSG_DATA, pt_n))
        self.assertEqual(mt, MSG_DATA)
        self.assertEqual(out, pt_n)

    # ------------------------------------------------------------------
    # 2. Modified ciphertext -> MAC failure, no plaintext.
    # ------------------------------------------------------------------
    def test_2_modified_ciphertext(self):
        g_chan, n_chan = self._channels()
        wire = bytearray(g_chan.send(MSG_DATA, b"payload under attack"))
        wire[HEADER_LEN] ^= 0x01                 # flip first ciphertext byte

        result = None
        with self.assertRaises(AuthenticationError):
            result = n_chan.receive(bytes(wire))
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # 3. Modified authenticated header -> MAC failure, no plaintext.
    #    Flip the msg_type byte (offset 10): length/direction/sequence stay
    #    valid, so the record passes those checks and the HMAC catches it,
    #    proving the header is authenticated.
    # ------------------------------------------------------------------
    def test_3_modified_header(self):
        g_chan, n_chan = self._channels()
        wire = bytearray(g_chan.send(MSG_DATA, b"payload"))
        wire[10] ^= 0x01                          # msg_type byte

        result = None
        with self.assertRaises(AuthenticationError):
            result = n_chan.receive(bytes(wire))
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # 4. Replay -> sequence-check failure, no plaintext.
    # ------------------------------------------------------------------
    def test_4_replay(self):
        g_chan, n_chan = self._channels()
        wire = g_chan.send(MSG_DATA, b"replay me")

        mt, out = n_chan.receive(wire)            # seq 0 accepted once
        self.assertEqual(out, b"replay me")

        result = None
        with self.assertRaises(BadSequence):
            result = n_chan.receive(wire)         # same bytes again
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # 5. Reflection into the opposite direction -> direction-check failure.
    #    A gateway->node record (DIR_G2N) is fed to the gateway's OWN receive
    #    side, which expects node->gateway (DIR_N2G).
    # ------------------------------------------------------------------
    def test_5_reflected_direction(self):
        g_chan, n_chan = self._channels()
        wire = g_chan.send(MSG_DATA, b"outbound from gateway")

        result = None
        with self.assertRaises(WrongDirection):
            result = g_chan.receive(wire)
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # 6a. Handshake verified with the WRONG RSA public key -> InvalidSignature.
    #     The node's signature is checked against a stranger's key.
    # ------------------------------------------------------------------
    def test_6a_wrong_public_key(self):
        with self.assertRaises(InvalidSignature):
            run_handshake(
                self.gateway, self.node,
                self.gateway.rsa_pub, self.stranger.rsa_pub,  # wrong node key
                verbose=False)

    # ------------------------------------------------------------------
    # 6b. Corrupted RSA-PSS signature -> InvalidSignature.
    # ------------------------------------------------------------------
    def test_6b_corrupted_signature(self):
        def tamper(msg_g, msg_n, sig_g, sig_n):
            bad = bytearray(sig_n)
            bad[0] ^= 0x01
            return msg_g, msg_n, sig_g, bytes(bad)

        with self.assertRaises(InvalidSignature):
            run_handshake(
                self.gateway, self.node,
                self.gateway.rsa_pub, self.node.rsa_pub,
                tamper=tamper, verbose=False)

    # ------------------------------------------------------------------
    # 6c. Reflected handshake message -> ValueError (identity/role check).
    #     The gateway's own message + signature are bounced back as the
    #     "node" message.
    # ------------------------------------------------------------------
    def test_6c_reflected_handshake(self):
        def tamper(msg_g, msg_n, sig_g, sig_n):
            return msg_g, copy.deepcopy(msg_g), sig_g, sig_g

        with self.assertRaises(ValueError):
            run_handshake(
                self.gateway, self.node,
                self.gateway.rsa_pub, self.node.rsa_pub,
                tamper=tamper, verbose=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
