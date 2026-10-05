# AI Usage Disclosure — HW2 | Ethanael Ford 

## Tool/model and date
Claude (Anthropic). Used October 3–5, 2026, across two chat sessions: one session to help craft and refine the task prompts, and a second session where those prompts were used to produce and test the code.

## Purpose
Assistance with CSCE 465 HW2: building and testing an authenticated secure channel between a simulated agent gateway and node. AI was used to scaffold the four Python deliverables, explain the relevant cryptographic constructions, and generate adversarial tests. All design requirements came from the assignment; final review, testing, and the written report are my own.

## AI Conversation Log file
- claude_output.pdf

## What I used
AI assistance contributed to all four Python deliverables:
- `baseline_ctr.py` — Task 1: AES-CTR malleability (bit-flip) and replay demo.
- `handshake.py` — Task 2: authenticated ffdhe3072 Diffie–Hellman handshake with RSA-PSS signatures.
- `secure_record.py` — Task 3: Encrypt-then-MAC record layer (AES-256-CTR + HMAC-SHA256).
- `test_security.py` — Task 4: adversarial `unittest` suite exercising both modules.

## What I changed
Not much -- most of the output was accurate. Did however read through all the code and made sure I understood what was going on. One thing I did change however was I tried both EXEC and OPEN on part 1 as they are both 4 charachter commands and both ended up working!

## How I tested it
Ran the code, took the screenshots, and made sure the output was what I was expecting it to be. 

## One error, limitation, or rejected suggestion
There was an error when first setting up the venv that I ended up having to fix so that I could run it. 
