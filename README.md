# Namebump

Namebump is a registrationless key-value store where names are claimed using
public-key signatures. Storage is limited per IP address, requiring renewal as IPs
change. When limits are exceeded, older entries are automatically displaced.

todo: usage

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
