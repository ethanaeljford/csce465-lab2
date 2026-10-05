#!/usr/bin/env python3

"""
baseline_ctr.py

Educational demo of why UNAUTHENTICATED AES-CTR is unsafe. Everything runs
in-process: you are the sender, the relay, and the receiver. Nothing here
touches a real system or a real key you don't generate yourself.

Two classic weaknesses are shown:

  1. MALLEABILITY (bit-flipping). CTR is a stream cipher:
         ciphertext = plaintext XOR keystream
     So if a man-in-the-middle knows the plaintext bytes at some position
     (easy for fixed-format protocol messages), they can flip those
     ciphertext bytes by delta = old XOR new. The receiver then decrypts to
     the NEW plaintext -- the relay never learns the key.

  2. NO REPLAY PROTECTION. The receiver has no record of what it already
     processed, so re-sending the same ciphertext makes it run twice.
"""

import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# --------------------------------------------------------------------------
# Shared secret (known only to the legitimate sender and receiver)
# --------------------------------------------------------------------------
KEY = os.urandom(32)      # AES-256 key
NONCE = os.urandom(16)    # CTR initial counter block (16 bytes = AES block size)

COMMAND = b'{"action":"READ","path":"notes.txt"}'   # fixed-length message


def encrypt(key, nonce, plaintext):
    enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return enc.update(plaintext) + enc.finalize()


def decrypt(key, nonce, ciphertext):
    dec = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
    return dec.update(ciphertext) + dec.finalize()


def hexdump(label, b):
    print(f"  {label:<16} {b.hex()}")


# --------------------------------------------------------------------------
# The relay: tampers with ciphertext WITHOUT the key.
# It only needs to know the plaintext token it wants to replace.
# --------------------------------------------------------------------------
def relay_tamper(ciphertext, known_plaintext, old_token, new_token):
    assert len(old_token) == len(new_token), "tokens must be equal length"

    idx = known_plaintext.index(old_token)
    delta = bytes(o ^ n for o, n in zip(old_token, new_token))  # old XOR new

    print("\n=== RELAY (no key) tampers with the ciphertext ===")
    print(f"  replacing {old_token!r} -> {new_token!r} at byte offset {idx}")
    hexdump("old token", old_token)
    hexdump("new token", new_token)
    hexdump("XOR delta", delta)
    print("  XOR relation:  cipher'[i] = cipher[i] XOR (old[i] XOR new[i])")

    ct = bytearray(ciphertext)
    affected_before = bytes(ct[idx:idx + len(delta)])
    for i, d in enumerate(delta):
        ct[idx + i] ^= d
    affected_after = bytes(ct[idx:idx + len(delta)])

    hexdump("cipher bytes", affected_before)   # just the touched bytes
    hexdump("-> flipped to", affected_after)
    return bytes(ct)


# --------------------------------------------------------------------------
# The receiver: decrypts and acts. No authentication, no replay check.
# --------------------------------------------------------------------------
def receiver_process(ciphertext, tag=""):
    pt = decrypt(KEY, NONCE, ciphertext)
    print(f"\n--- RECEIVER {tag} ---")
    print(f"  decrypted: {pt!r}")
    try:
        cmd = json.loads(pt)
        print(f"  >>> EXECUTING  action={cmd['action']}  path={cmd['path']}")
    except Exception as e:
        print(f"  parse error (would reject): {e}")


def main():
    print("Original command:", COMMAND.decode())
    ct = encrypt(KEY, NONCE, COMMAND)
    hexdump("\n  ciphertext", ct)

    # Honest path
    receiver_process(ct, tag="(honest message)")

    # 1) Malleability: flip READ -> EXEC
    tampered = relay_tamper(ct, COMMAND, b"READ", b"EXEC")
    receiver_process(tampered, tag="(after tampering)")

    # 2) Replay: send the SAME tampered ciphertext again
    print("\n=== RELAY replays the identical ciphertext ===")
    receiver_process(tampered, tag="(replay #1)")
    receiver_process(tampered, tag="(replay #2)")
    print("\nReceiver ran the command twice -- nothing detected the duplicate.")


if __name__ == "__main__":
    main()
