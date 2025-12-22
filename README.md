# Namebump

Namebump is a registrationless key-value store where names are claimed using
public-key signatures. Storage is limited per IP address, requiring renewal as IPs
change. When limits are exceeded, older entries are automatically displaced.

```python3
import namebump
import uuid
import asyncio

async def main():
    # Generate your public key.
    kp = namebump.Keypair.generate()

    # Save a value at a unique name (must be unique.)
    name = str(uuid.uuid4())
    await namebump.put(name, "value", kp)

    # Get your val back -> value.
    value = await namebump.get(name, kp)

    # Delete it:
    await namebump.delete(name, kp)

asyncio.run(main())

```

You can also make the software only store values if it doesn't need to bump an
existing one but doing this:

```python3
    await namebump.put(name, val, kp, namebump.DONT_BUMP)
```

Or make it throw on full:

```python3
    await namebump.put(name, val, kp, namebump.THROW_BUMP)
```

To manually specify a server to use:

```python3

client = await namebump.Client(
    ("127.0.0.1", 5300),
    b"compressed ECDSA secp256k1 pub key of server"
)

client.put ... get etc

to run your own server:

    import the database into mysql: scripts/namebump.sql
    generate a keypair: python3 scripts/gen_keys.py
    edit env vars: scripts/set_env.sh

. scripts/set_env.sh
python3 -m namebump.server
```

----

### Who can register names?

Anyone. There's no captcha or registration system. The client software is
meant to allow software to be able to use a secure KVS without having to
host anything themselves. Important limitations apply, however.

### What prevents someone hijacking my name?

As long as the name is renewed before it expires the name stays associated
with the public key that claimed it. However, ownership and persistence
are only a consequence of how the names are used. It's up to the owner
to make sure the names they need stay renewed.

### What about if my IP changes?

If your IP changes a person could fill up the name queue for your old IP
to try bump off your name before you renew it. However, the software
requires names to exist for a minimum time-frame before they can be bumped.
This prevents such an attack from displacing names.

### How can you store names for the entire IP space?

There's only about 4 billion IPv4 addresses. IPv6 obviously isn't feasible to
index as-is, but if you break down the sub-components of the IPv6 address you
can discard a great portion of it and build a resource limitation scheme.
Overall, storage should fit within 4 TBs.

### Where are names stored?

On a single server for now. The architecture in the future could be federated
or decentralized across nodes (.tld -> server(S).) The design here for the data
structures and resource limits would make for a novel storage system that could be
improved in the future.
