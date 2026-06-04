# namebump on runloom — sync-port feasibility

namebump (the PNP peer-name layer) ported to pure synchronous code on runloom
(free-threaded 3.13t, M:N), on top of the ported aionetiface base layer and its
shims (`saio`, `runloom_boot`).  Part of the 4-repo stack port — see
warpgate's `FEASIBILITY.md` for the stack-level result and aionetiface's for the
deep dive on the porting technique.

## What was done
- AST-stripped all async/await (3 files; **0 executable async nodes**).
- Reused the aionetiface sync shims unchanged.
- namebump's `Server` needs MySQL (`aiomysql`) — infra, out of scope — so the
  validation targets namebump's deterministic, security-critical core.

## Validated on `runloom.run(8, main)` (real M:N, GIL off) — **2/2**
- **keypair**: ECDSA keypair generation (33-byte compressed key).
- **signed_packet_roundtrip**: build → ECDSA-sign → pack → unpack → verify a PUT
  packet, and confirm a tampered packet is rejected — the full crypto + wire
  format, as sync code.

## Finding
ECDSA verify/decompression is deeply recursive pure Python (the `ecdsa`
library).  Run inline on a goroutine's small stack it overflows
(`RecursionError` / SIGSEGV).  The sync-port answers, both already aligned with
aionetiface's design:
- heavy crypto is **offloaded to a worker thread** (`ecdsa_*_async` →
  `saio.run_in_executor` → `runloom.monkey.offload`, full OS-thread stack), and
- `runloom_boot` pins a roomy (1 MiB) goroutine stack.

Run: `PYTHON_GIL=0 PYTHONPATH=src:<aionetiface>/src:<runloom>/src python3.13t tests_runloom/test_namebump_port.py 8`
