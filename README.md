# Namebump

Part of the Warpgate project: <https://www.warpgate.io/>

A registrationless, key-authenticated name → value store. Anyone can claim a
name on a first-come basis using an ECDSA keypair; only the holder of the
matching private key can update or delete it. Storage is rate-limited per
source IP rather than per-account, so there's no signup, captcha, or
e-mail-confirmation step — your keypair *is* the account.

Designed as the discovery/identity layer for Warpgate peers (where a node
publishes its current address bytes under a stable nickname), but the wire
protocol is general-purpose and works for any small (`<= 1 KiB`) value.

## Install

```sh
pip install namebump
```

## Quick start (public server)

```python3
import asyncio
import namebump
from namebump.client import DEST, PK  # public server endpoint + its pubkey


async def main():
    # Generate (or load) your own keypair.  This is the ONLY credential
    # for the name -- guard the private key; lose it and you've lost
    # ownership of every name signed with it.
    kp = namebump.Keypair.generate()

    # Connect.  `await Client(...)` runs .start() implicitly.
    client = await namebump.Client(DEST, PK)

    # Claim a name and store a value under it.  First successful PUT
    # binds the name to kp's public key; subsequent PUTs for the same
    # name must be signed by the same key.
    await client.put("my_unique_name", b"hello world", kp)

    # Read it back.  GET is unsigned -- any client can read any name.
    pkt = await client.get("my_unique_name")
    print(pkt.value)  # -> b"hello world"

    # Update it.  Same call shape -- PUT is upsert when you own the name.
    await client.put("my_unique_name", b"new value", kp)

    # Delete it.  Requires the owning keypair.
    await client.delete("my_unique_name", kp)


asyncio.run(main())
```

The public server (`ovh1.p2pd.net:5300`) is what `DEST` / `PK` point at. To
target a different deployment, pass its host/port and 33-byte compressed
public key.

## API

### `Keypair`

```python3
namebump.Keypair.generate()                   # new random secp256k1 keypair
namebump.Keypair(priv=<SigningKey>)           # restore from private key only
namebump.Keypair(priv=None, pub=<VerifyingKey>)  # verify-only (no PUT/DELETE)
```

`kp.vkc` is the 33-byte compressed public key — that's what the server uses
to identify the owner of a name on the wire.

### `Client`

```python3
client = await namebump.Client(
    dest,        # (host, port) tuple, e.g. ("ovh1.p2pd.net", 5300)
    dest_pk,     # 33-byte compressed public key of the server
    sys_clock=None,  # custom SysClock; defaults to time.time()
    nic=None,    # aionetiface.Interface; defaults to Interface("default")
    proto=TCP,   # TCP or UDP; affects PUT/DEL transport (GET races both)
)
```

The `nic` parameter selects which local interface the client binds outgoing
packets to. The default (`Interface("default")`) is correct for most
single-NIC setups. For multi-NIC hosts (e.g. you want the request to leave
via a specific interface to satisfy a per-IP quota row), construct an
`Interface(name)` for the target NIC and pass it.

#### `client.put(name, value, kp, behavior=DO_BUMP, ttl=None)`

Stores `value` (`bytes`, up to 1024 bytes) under `name` (`str`, up to 50
bytes UTF-8). Requires the owning keypair `kp`. Returns a `Packet` whose
`.value` echoes back what the server stored.

`behavior` controls what happens when the source IP is at its name limit:

| Constant | Behavior at quota |
| --- | --- |
| `namebump.DO_BUMP` (default) | Evict an older name owned by this IP to free a slot |
| `namebump.DONT_BUMP` | Reject the PUT — raises `PutRejected` |
| `namebump.THROW_BUMP` | Reject and raise `KeyError("putting this will bump.")` |

The bump-eviction targets the oldest *bumpable* row — names younger than
`MIN_NAME_DURATION` (30 days) are immune so a flood of fresh registrations
can't displace a recently claimed name.

`ttl` (seconds, default 10, max 60) is the freshness window the server
honors on the signed packet. Larger values give the request more time to
ride out network delays at the cost of a longer replay window.

`PutRejected` is raised when the server stored nothing — typically the
per-IP cap was hit. It's not a network failure and is not retried.

#### `client.get(name, kp=None)`

Reads the value at `name`. `kp` is optional and only used to identify the
caller when signed reads are required (the public server treats all GETs
as anonymous). Returns a `Packet`; `pkt.value` is `None` if the name doesn't
exist or has expired.

GET races both IPv4 and IPv6 transports concurrently (reads are quota-free
on the server), so a single-AF routing hole on the path to one address
family is invisible.

#### `client.delete(name, kp)`

Removes the record. Requires the owning keypair. Returns a `Packet`.

#### `client.usage(kp)`

Reports the caller's current per-IP quota state:

```python3
usage = await client.usage(kp)
# {"af": 2, "names_used": 3, "name_limit": 20}
# af=2 -> IPv4, af=10 -> IPv6
```

Useful before a batch of registrations, or for showing the user *why* a PUT
just got rejected.

## Per-IP quotas

Quotas are enforced per source IP, not per keypair, so a single host with
one IP gets a finite slice of the namespace regardless of how many keypairs
it cycles through:

| AF | Names per IP | Notes |
| --- | --- | --- |
| IPv4 | 20 | Per `/32` |
| IPv6 | 5 per /64 interface | With additional rollups (15000 per /48 subnet, 3 per global prefix, 20 per /64) to keep one provider from claiming the whole v6 space |

Names that aren't refreshed within `MIN_NAME_DURATION` (30 days, see
`defs.py`) become eligible for expiry/bump. Refreshing is a normal PUT with
the same `(name, kp)`; it resets the lifetime.

## Reliability behavior

- **Transport racing**: PUT and DELETE race TCP and UDP to the server,
  first success wins. GET additionally races IPv4 and IPv6 concurrently.
- **Retries**: every call retries up to 3 times with a 0.5s pause on
  transient network errors. Application-level rejections (`PutRejected`,
  `KeyError` from `THROW_BUMP`) are not retried.
- **Encryption**: every request body is ECIES-encrypted to the server's
  public key. Replies are ECIES-encrypted to an ephemeral client key.
- **Authentication**: every PUT/DELETE is ECDSA-signed by the owning
  keypair. Each signed packet carries an `updated` timestamp and a per-
  request `ttl`; the server rejects packets older than `now - ttl` so a
  leaked packet can't be replayed indefinitely.

## Running your own server

```sh
# 1. Database schema (MySQL/MariaDB)
mysql -u root < scripts/namebump.sql

# 2. Generate the server keypair
python3 scripts/gen_keys.py
# -> writes server pub/priv; share the pub with clients as `dest_pk`

# 3. Edit DB credentials, listen IPs, server keys
$EDITOR scripts/set_env.sh

# 4. Run
. scripts/set_env.sh
python3 -m namebump.server
```

The server listens on TCP+UDP on both AFs by default (port 5300). Clients
need the 33-byte compressed public key from step 2 to encrypt requests
against your deployment.

## FAQ

### Who can register names?

Anyone with a keypair. No registration step — first successful PUT binds
the name to the public key that signed it, and only that key can update
or delete it from then on.

### What if my IP changes?

The IP→quota row gets a fresh count under the new IP, so you keep working.
Your existing names stay bound to your *keypair*, not your IP, and any
client with the keypair can refresh them — the IP that issued the refresh
becomes the new owner-IP for quota purposes.

### Can someone squat on my name while I'm offline?

Not within `MIN_NAME_DURATION` (30 days). The bump-eviction logic skips
records younger than that, so a flood of fresh PUTs from any IP can't
displace a recent registration. If a name goes unrefreshed beyond the
lifetime window, it does become claimable — set a renewal schedule
(e.g. weekly) if persistence matters.

### What if I lose my private key?

You lose ownership. Once the name expires, anyone can claim it again. Back
up keypairs.

### Why not put nonces in every request?

The 10-second `ttl` window plus the signed `updated` timestamp gives a
narrow replay surface (~10s for an unprivileged attacker on the same path)
in exchange for a much simpler API. If you need stricter freshness, pass
a smaller `ttl` per call.

### Where are names stored?

Single MySQL/MariaDB instance per deployment, currently. The schema and
resource-limit machinery are designed so a federated/decentralised layout
(`.tld -> server(s)`) is a future-direction addition rather than a
rewrite — see the Warpgate project for the broader decentralisation
roadmap.
