# HW2 — Authenticated Secure Channel for an Agent Gateway/Node

CSCE 465. A simulated gateway and node establish an authenticated, confidential channel: an RSA-authenticated finite-field Diffie–Hellman handshake derives per-direction session keys, and an Encrypt-then-MAC record layer carries messages on top of them. Includes a baseline demo showing why unauthenticated encryption fails, plus an adversarial test suite.

## Requirements

- Python 3 (3.8+)
- The [`cryptography`](https://cryptography.io) package:
  ```
  pip install cryptography
  ```
- A DH parameters file `ffdhe3072.pem` for the handshake. `handshake.py` generates it automatically on first run if it is missing; to create it manually:
  ```
  openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
  ```

## Files

- `baseline_ctr.py` — Task 1: demonstrates AES-CTR malleability (bit-flipping `READ`→`EXEC` without the key) and ciphertext replay, motivating authenticated encryption.
- `handshake.py` — Task 2: authenticated ffdhe3072 Diffie–Hellman handshake; parties sign the transcript with RSA-PSS + SHA-256 and derive per-direction session keys.
- `secure_record.py` — Task 3: Encrypt-then-MAC record layer (AES-256-CTR for confidentiality, HMAC-SHA256 for integrity) with per-direction sequence numbers and replay/reorder protection.
- `test_security.py` — Task 4: `unittest` suite that imports the above modules and asserts a specific safe failure for each adversarial case.

## How to run

```
python baseline_ctr.py
python handshake.py
python secure_record.py
python -m unittest test_security.py -v
```
