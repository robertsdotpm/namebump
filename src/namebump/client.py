"""
- Requests will be replayable for ~5 secs until they expire. This is to make
the API easier to use and because the use-case doesn't justify adding nonces and
a bunch of other non-sense.

"""

import json
import time
import asyncio
from ecdsa import SECP256k1, SigningKey
from aionetiface import (
    Interface,
    Address,
    Pipe,
    TCP,
    UDP,
    VALID_LOCALHOST,
    fstr,
    log,
    log_exception,
    h_to_b,
    async_run,
    rand_plain,
    proto_recv,
    to_b,
)
from aionetiface.net.net_defs import NET_CONF
from aionetiface.utility.signing import ecdsa_sign_async
from aionetiface.vendor.ecies import encrypt, decrypt
from .packet import Packet
from .keypair import Keypair
from .defs import OP_GET, OP_PUT, OP_DEL, OP_USAGE, DO_BUMP, DONT_BUMP, THROW_BUMP

DEST = ("ovh1.p2pd.net", 5300)
PK = h_to_b("03f20b5dcfa5d319635a34f18cb47b339c34f515515a5be733cd7a7f8494e97136")

# Retry behaviour for every Client request. The protocol is single-shot
# per attempt -- we open a fresh TCP pipe, send one packet, await one
# response, close. A transient slow / dropped server therefore needs
# retries here rather than at the caller; otherwise every caller of put /
# get / delete would have to implement its own retry loop. Network-error
# only: we do not retry application-level errors (e.g. KeyError from
# THROW_BUMP semantics).
DEFAULT_RETRIES = 3
DEFAULT_RETRY_PAUSE = 0.5


class PutRejected(Exception):
    """Server accepted the connection but refused to store the put.

    Raised by Client.put when the server returned a response packet
    with no stored value -- typically the per-IP name-allocation cap
    (ResourceLimit on the server side) but covers any future protocol-
    level rejection that surfaces as updated=0 on the wire. Not a
    network failure, so with_retry never sees it (it propagates past
    the retry/race layer untouched, which is the correct behaviour --
    rate limits are not transient).
    """

# Per-attempt TCP connect budget for namebump server pipes.
# NET_CONF defaults to 2s, which covers a healthy box's DNS resolve
# + TCP SYN/SYN-ACK with room to spare. On slower stacks (Windows XP
# was the canonical example: resolver routinely blocks 1-3s on first
# query under any DNS contention) 2s is too tight -- DNS alone can
# eat the whole window, leaving zero room for the actual TCP connect.
# All three retries blow through with the same 2s cap and the call
# bubbles "All name servers failed" when the network is fine and only
# the per-attempt cap was wrong.
#
# 6s gives meaningful headroom on slow stacks without slowing healthy
# ones (a good box still completes in <500ms regardless of the cap).
# Worst case: 3 retries x (6 + 0.5 sleep) = 19.5s, still well under
# the typical 30s caller-level budget.
NAMEBUMP_PIPE_CONF = dict(NET_CONF, con_timeout=6, recv_timeout=6)


class Client:
    """Async client for a single namebump server.

    Usage:
        client = await Client(dest=("host", 5300), dest_pk=<33-byte pk>)
        result = await client.get("myname")
        await client.put("myname", b"value", keypair)
        await client.delete("myname", keypair)

    Each method opens a fresh pipe, sends one encrypted+signed request,
    reads the encrypted reply, then closes the pipe.

    Transport: TCP (default) or UDP. The namebump server listens on
    BOTH transports for every (v4, v6) bind, so the choice is purely
    client-side -- no protocol or wire-format change. UDP is materially
    faster + more reliable for this single-shot req/resp pattern:

      * No SYN/SYN-ACK: 1 RTT instead of 2-3.
      * No TIME_WAIT residue between back-to-back requests.
      * App-level retries (with_retry below) absorb the rare lost
        datagram, so UDP loss isn't a correctness concern.
      * Slow stacks (Windows XP especially) where TCP setup blocks
        on DNS contention or kernel scheduling get a lighter path.

    Pass proto=UDP to opt in. Default stays TCP for backward compat
    with anything that depends on the connection-oriented wire shape.
    """

    def __init__(
        self,
        dest,
        dest_pk,
        sys_clock=None,
        nic=None,
        proto=TCP,
    ):
        """Initialize the client with a server address, its public key, and optional clock/NIC."""
        if not isinstance(dest_pk, bytes) or len(dest_pk) != 33:
            raise ValueError("dest_pk must be a 33-byte compressed public key")
        if proto not in (TCP, UDP):
            raise ValueError("proto must be TCP or UDP, got {0!r}".format(proto))

        self.dest = dest
        self.dest_pk = dest_pk
        self.proto = proto

        # Ephemeral key pair used to receive the encrypted server reply.
        self.reply_sk = SigningKey.generate(curve=SECP256k1)
        self.reply_pk = self.reply_sk.get_verifying_key().to_string("compressed")

        self.sys_clock = sys_clock
        self.nic = nic
        self.af = None
        self.afs = []
        self.addr = None

    async def start(self):
        """Resolve the server address and initialise the NIC and clock; return self."""
        if not self.sys_clock:
            self.sys_clock = time

        if self.nic is None:
            self.nic = Interface("default")

        # Resolve dest, keep every AF the NIC + address both support.
        # Primary self.af is used by PUT / DEL (which stay AF-aware to
        # respect per-AF name quotas and IP-keyed reachability). GET
        # races every entry in self.afs -- v4 and v6 traverse
        # independent BGP planes, so a Cogent-vs-HE-style routing hole
        # on one AF is invisible to the other.
        self.addr = await Address(*self.dest, self.nic)
        for af in self.nic.supported():
            try:
                self.addr.select_ip(af)
                self.afs.append(af)
            except KeyError:
                continue

        if not self.afs:
            raise ConnectionError("Dest AF is not supported by NIC.")

        self.af = self.afs[0]
        return self

    def __await__(self):
        """Allow ``await Client(...)`` as a shorthand for ``await Client(...).start()``."""
        return self.start().__await__()

    async def get_dest_pipe(
        self, proto=None, af=None,
    ):
        """Open and return a fresh pipe (TCP or UDP) to the namebump server.

        Defaults to self.proto / self.af when args are None.  race_request
        below passes proto explicitly so the two attempts don't trip over
        each other's bound state.  race_get_paths additionally passes af
        so a single GET can probe both v4 and v6 transports concurrently.
        """
        if proto is None:
            proto = self.proto
        if af is None:
            af = self.af

        route = self.nic.route(af)

        # Bind to the loopback address explicitly so the connection succeeds.
        # For non-loopback destinations, bind to the default outbound address.
        # Same bind logic for both TCP and UDP -- the kernel uses the bound
        # address as the source for sendto / connect alike.
        if self.dest[0] in VALID_LOCALHOST:
            route = await route.bind(ips=self.dest[0])
        else:
            route = await route.bind()

        # Open the pipe. For TCP this performs the SYN/SYN-ACK handshake
        # under the bumped 6s con_timeout. For UDP, .connect() just
        # creates the bound socket -- there is no handshake to wait on,
        # so the call returns sub-millisecond regardless of network
        # health. UDP loss is handled by with_retry one frame up.
        try:
            pipe = await Pipe(
                proto, self.addr, route, conf=NAMEBUMP_PIPE_CONF,
            ).connect()
            if pipe is None:
                raise ConnectionError("Could not connect to namebump server.")

            return pipe
        except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
            # Caller (race_request / with_retry) sees the re-raised
            # exception and decides retry / fallback.  Skip the full
            # traceback -- this fires whenever a PNP server is briefly
            # unreachable, which is expected during the cascade.
            raise

    async def race_request(self, build_attempt):
        """Race a request over TCP and UDP concurrently; first success wins.

        build_attempt(proto) is a callable that returns a coroutine running
        a full single-shot send-recv-close cycle on the given proto.  We
        spawn one task per transport, take the first non-error result,
        and cancel the other.  When BOTH transports fail we re-raise the
        first error so with_retry's classification still works.

        Why race instead of pick: UDP wins on a healthy network (1 RTT
        vs TCP's 2-3) but a few firewall / NAT setups silently drop
        UDP -- racing means we get the lighter path when it works
        without ever falling off when it doesn't.
        """
        tasks = [
            asyncio.ensure_future(build_attempt(TCP)),
            asyncio.ensure_future(build_attempt(UDP)),
        ]
        try:
            done, pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED,
            )
            # Walk the first-finisher set first. If a winner succeeded,
            # cancel the laggard and return immediately. If the winner
            # ERRORED, leave the laggard alone -- it may still succeed.
            # The earlier shape cancelled the laggard pre-check, then
            # awaited it post-check, which converted its real result
            # into CancelledError.
            for t in done:
                try:
                    result = t.result()
                    for p in pending:
                        p.cancel()
                    return result
                except asyncio.CancelledError:  # pylint: disable=try-except-raise
                    raise
                except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
                    # First-finisher errored.  Expected when one
                    # transport (UDP/TCP) is blocked but the other
                    # works; the laggard below may still succeed.
                    log(fstr(
                        "namebump.race_request: first-finisher {0}: {1}",
                        (type(exc).__name__, str(exc) or "(no message)"),
                    ))

            # First finisher errored; let the laggard run to completion
            # without cancelling it. with_retry one frame up will catch
            # any final ConnectionError and decide whether to retry.
            for t in pending:
                try:
                    return await t
                except asyncio.CancelledError:  # pylint: disable=try-except-raise
                    raise
                except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
                    log(fstr(
                        "namebump.race_request: laggard {0}: {1}",
                        (type(exc).__name__, str(exc) or "(no message)"),
                    ))

            # Both transports failed.
            raise ConnectionError(
                "Both TCP and UDP attempts failed for {0}".format(self.dest)
            )
        finally:
            # Best-effort cancel + drain so neither task leaks beyond
            # this race -- avoids stray pipe.close()-during-loop-shutdown
            # warnings on test teardown.
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def race_get_paths(self, build_attempt):
        """Race build_attempt(af, proto) across every (af, proto) combination.

        Used by GET only.  Reads are quota-free at the server, and v4 and
        v6 traverse independent BGP planes / peering relationships, so
        racing both AFs catches Cogent-vs-HE-style routing holes that a
        single-AF lookup silently misses.  PUT and DEL stay on
        race_request (one AF, both transports) to respect per-AF name
        quotas and avoid double-spending the tighter v6 budget.

        On a single-stack NIC self.afs has one entry, so this collapses
        to a TCP/UDP-only race -- equivalent to race_request.
        """
        combos = [(af, proto) for af in self.afs for proto in (TCP, UDP)]
        tasks = [
            asyncio.ensure_future(build_attempt(af, proto))
            for af, proto in combos
        ]
        pending = list(tasks)
        try:
            last_exc = None
            while pending:
                done_set, still_pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED,
                )
                pending = list(still_pending)
                for t in done_set:
                    try:
                        result = t.result()
                        for p in pending:
                            p.cancel()
                        return result
                    except asyncio.CancelledError:  # pylint: disable=try-except-raise
                        raise
                    except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
                        last_exc = exc
                        log_exception()
            if last_exc is not None:
                raise last_exc
            raise ConnectionError(
                "All AF/proto attempts failed for {0}".format(self.dest)
            )
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def return_resp(self, pipe):
        """Read, decrypt, and deserialise the server's response from the pipe.

        Raises ConnectionError on decrypt / unpack failure so the
        with_retry + race_request layers above treat "got garbage on
        the pipe" as a transient network error (retry-eligible)
        rather than a hard programming error. Concretely: UDP pipes
        are unconnected and can receive stray datagrams from any
        peer; if proto_recv hands back a non-namebump frame, the tag
        check inside ecies sym_decrypt raises AssertionError. That's
        an "I/O quality" issue, not a logic bug.
        """

        buf = await proto_recv(pipe)

        # proto_recv returns None on timeout / closed pipe. Without this guard
        # the None falls into decrypt() and crashes on msg[0:33] with a
        # TypeError that the with_retry/race layers don't classify as
        # transient -- so a slow link looks like a hard programming error
        # and never retries.
        if buf is None:
            raise ConnectionError(
                "namebump return_resp: recv returned None (timeout or closed pipe)"
            )
        try:
            buf = decrypt(self.reply_sk, buf)
            pkt = Packet.unpack(buf)
        except (AssertionError, ValueError, KeyError) as exc:
            raise ConnectionError(
                "namebump return_resp: malformed/foreign response: {0!r}".format(exc)
            ) from exc
        if not pkt.updated:
            pkt.value = None
        return pkt

    async def send_pkt(
        self, pipe, pkt, kp, sign=True,
        af=None,
    ):
        """Serialise, optionally sign, encrypt, and send a packet to the server."""
        if af is None:
            af = self.af
        pkt.reply_pk = self.reply_pk
        msg = pkt.get_msg_to_sign()
        if sign:
            # ECDSA sign (~2-10ms) via the shared
            # aionetiface.utility.signing.ecdsa_sign_async helper so
            # the client's event loop stays free for concurrent
            # in-flight requests / response readers.
            sig = await ecdsa_sign_async(kp.private, msg)
        else:
            sig = b""

        buf = msg + sig
        enc_msg = encrypt(self.dest_pk, buf)
        # Use the configured destination port (self.dest[1]) instead of
        # hard-coding 5300 -- in practice every namebump server runs on
        # NB_PORT, but the hard-code blocked the dev / test path that
        # spins up a server on a different port and breaks if a caller
        # ever overrides dest. self.dest is the canonical source.
        dest = (self.addr.select_ip(af).ip, self.dest[1])
        send_success = await pipe.send(enc_msg, dest)
        if not send_success:
            raise IOError("client send pkt failure")

    async def with_retry(self, attempt_coro_factory):
        """Run attempt_coro_factory() up to DEFAULT_RETRIES times.

        Retries on network-class errors (OSError, ConnectionError,
        asyncio.TimeoutError) only. Application errors (e.g. KeyError
        from THROW_BUMP) propagate immediately. CancelledError always
        propagates immediately.
        """
        last_exc = None
        for attempt in range(DEFAULT_RETRIES):
            try:
                return await attempt_coro_factory()
            except asyncio.CancelledError:  # pylint: disable=try-except-raise
                raise
            except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
                last_exc = exc
                log_exception()

            if attempt + 1 < DEFAULT_RETRIES:
                await asyncio.sleep(DEFAULT_RETRY_PAUSE)
        # All attempts failed -- re-raise the last network error so the
        # caller sees the same exception type they would have seen
        # without retries.
        if last_exc is not None:
            raise last_exc
        raise ConnectionError("Could not reach namebump server.")

    async def get(
        self, name, kp=None
    ):
        """Fetch the value for name, optionally identifying the caller with a keypair."""
        expected_name = to_b(name)

        def attempt_for(af, proto):
            async def one_attempt():
                pipe = None
                try:
                    t = self.sys_clock.time()
                    pipe = await self.get_dest_pipe(proto=proto, af=af)
                    vkc = kp.vkc if kp else self.reply_pk
                    pkt = Packet(OP_GET, name, vkc=vkc, updated=t)
                    await self.send_pkt(pipe, pkt, kp, sign=bool(kp), af=af)
                    resp = await self.return_resp(pipe)
                    # Validate the response matches the request.  return_resp
                    # only proves the packet decrypted under our reply key;
                    # it doesn't prove this server reply is the answer to
                    # THIS query.  Two ways the wrong reply can land here:
                    #
                    # 1. UDP socket-port reuse -- a late put-ACK from an
                    #    earlier Nickname.put on the same Client instance
                    #    can sit in the kernel buffer of a freshly-opened
                    #    UDP socket if the ephemeral port is recycled and
                    #    the dest (host, port) matches.  decrypt() succeeds
                    #    because the reply key is the same for puts and gets.
                    #
                    # 2. race_get_paths fires TCP + UDP concurrently and
                    #    FIRST_COMPLETED wins -- a stray UDP datagram with
                    #    a different op or name then beats the correct TCP
                    #    answer and gets returned to Nickname.get.
                    #
                    # Both produce a deeply surprising failure where the
                    # caller acts on a peer addr that belongs to a totally
                    # different nickname.  Treat mismatches as transient so
                    # with_retry / race_get_paths drains the kernel buffer
                    # and tries again on a fresh socket.
                    if resp is None:
                        raise ConnectionError(
                            "namebump get: empty response"
                        )
                    if getattr(resp, "op", None) != OP_GET:
                        raise ConnectionError(fstr(
                            "namebump get: op mismatch (got {0}, expected "
                            "{1}) -- likely stray put-response on a "
                            "recycled UDP port",
                            (getattr(resp, "op", None), OP_GET),
                        ))
                    if getattr(resp, "name", None) != expected_name:
                        raise ConnectionError(fstr(
                            "namebump get: name mismatch (got {0}, expected "
                            "{1}) -- response is for a different nickname",
                            (getattr(resp, "name", None), expected_name),
                        ))
                    return resp
                finally:
                    if pipe is not None:
                        await pipe.close()
            return one_attempt()

        async def race():
            return await self.race_get_paths(attempt_for)
        return await self.with_retry(race)

    async def put(
        self,
        name,
        value,
        kp,
        behavior=DO_BUMP,
        ttl=None,
    ):
        """Write a signed name-value pair to the server, applying the given bump behavior.

        ttl: per-request lifetime in seconds the server will honour before
        rejecting the signed packet as expired (see DEFAULT_REQUEST_TTL /
        MAX_REQUEST_TTL in defs). Pass None to use the wire-format default.
        """
        def attempt_for(proto):
            async def one_attempt():
                pipe = None
                try:
                    t = self.sys_clock.time()
                    pipe = await self.get_dest_pipe(proto=proto)
                    throw_bump = behavior == THROW_BUMP
                    effective_behavior = DONT_BUMP if throw_bump else behavior

                    pkt = Packet(
                        OP_PUT, name, value, kp.vkc, None, t, effective_behavior,
                        ttl=ttl,
                    )

                    await self.send_pkt(pipe, pkt, kp)

                    ret = await self.return_resp(pipe)
                    if throw_bump and not ret.value:
                        # Application-level signal -- not a network failure,
                        # so it propagates through with_retry without retrying.
                        raise KeyError("putting this will bump.")
                    return ret
                finally:
                    if pipe is not None:
                        await pipe.close()
            return one_attempt()

        async def race():
            return await self.race_request(attempt_for)
        ret = await self.with_retry(race)
        # Server clears the stored value (and updated=0) on ResourceLimit
        # so the client's return_resp converts pkt.value to None. Without
        # this guard, callers see a "successful" packet with value=None
        # and silently treat the put as stored -- matrix tests had been
        # interpreting cap-rejected puts as success, then failing later
        # at lookup. Surface the failure here as an explicit exception.
        if ret is None or ret.value is None:
            raise PutRejected(
                "namebump put rejected by server (likely ResourceLimit; "
                "name='{0}' dest={1})".format(name, self.dest)
            )
        return ret

    async def delete(
        self,
        name,
        kp,
        ttl=None,
    ):
        """Send a signed delete request for name and return the server's response."""
        def attempt_for(proto):
            async def one_attempt():
                pipe = None
                try:
                    t = self.sys_clock.time()
                    pipe = await self.get_dest_pipe(proto=proto)
                    pkt = Packet(OP_DEL, name, vkc=kp.vkc, updated=t, ttl=ttl)
                    await self.send_pkt(pipe, pkt, kp)
                    return await self.return_resp(pipe)
                finally:
                    if pipe is not None:
                        await pipe.close()
            return one_attempt()

        async def race():
            return await self.race_request(attempt_for)
        return await self.with_retry(race)

    async def usage(self, kp, ttl=None):
        """Signed-owner query for the per-IP name quota state.

        Returns a dict ``{"af": int, "names_used": int, "name_limit": int}``
        describing how many names the requesting client_ip currently
        holds on the AF this connection is using, against the cap.
        Raises ``namebump.PutRejected`` (parent type) on a server-side
        rejection just like put/delete.  Read-only on the server --
        does not modify any state.
        """
        def attempt_for(proto):
            async def one_attempt():
                pipe = None
                try:
                    t = self.sys_clock.time()
                    pipe = await self.get_dest_pipe(proto=proto)
                    pkt = Packet(
                        OP_USAGE, name=b"", value=b"",
                        vkc=kp.vkc, updated=t, ttl=ttl,
                    )
                    await self.send_pkt(pipe, pkt, kp)
                    return await self.return_resp(pipe)
                finally:
                    if pipe is not None:
                        await pipe.close()
            return one_attempt()

        async def race():
            return await self.race_request(attempt_for)
        ret = await self.with_retry(race)
        if ret is None or ret.value is None:
            return None
        try:
            return json.loads(ret.value.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None


if __name__ == "__main__":

    async def workspace():
        """Exercise the put, get, and delete client calls end-to-end against a live server."""
        name = str(rand_plain(10))
        kp = Keypair.generate()
        client = await Client(DEST, PK)

        out = await client.put(name, "value", kp)

        out = await client.get(name)

        out = await client.delete(name, kp)

        out = await client.get(name, kp)

    async_run(workspace())
