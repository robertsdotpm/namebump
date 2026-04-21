"""
- Requests will be replayable for ~5 secs until they expire. This is to make
the API easier to use and because the use-case doesn't justify adding nonces and
a bunch of other non-sense.

"""

import time
from ecdsa import SECP256k1, SigningKey
from aionetiface import *
from aionetiface.utility.sys_clock import *
from aionetiface.vendor.ecies import *
from .packet import *
from .keypair import *
from .defs import *

DEST = ("ovh1.p2pd.net", 5300)
PK = h_to_b("03f20b5dcfa5d319635a34f18cb47b339c34f515515a5be733cd7a7f8494e97136")

class Client():
    """Async client for a single namebump server.

    Usage:
        client = await Client(dest=("host", 5300), dest_pk=<33-byte pk>)
        result = await client.get("myname")
        await client.put("myname", b"value", keypair)
        await client.delete("myname", keypair)

    Each method opens a fresh TCP connection, sends one encrypted+signed
    request, reads the encrypted reply, then closes the connection.
    """

    def __init__(self, dest, dest_pk, sys_clock=None, nic=None):
        if not isinstance(dest_pk, bytes) or len(dest_pk) != 33:
            raise ValueError("dest_pk must be a 33-byte compressed public key")

        self.dest = dest
        self.dest_pk = dest_pk

        # Ephemeral key pair used to receive the encrypted server reply.
        self.reply_sk = SigningKey.generate(curve=SECP256k1)
        self.reply_pk = self.reply_sk.get_verifying_key().to_string("compressed")

        self.sys_clock = sys_clock
        self.nic = nic
        self.af = None
        self.addr = None

    async def start(self):
        if not self.sys_clock:
            self.sys_clock = time

        if self.nic is None:
            self.nic = Interface("default")

        # Resolve dest to an IP.  If dest is a domain that has both A and AAAA
        # records, prefer the AF that the local NIC also supports.
        # TODO: This selection logic should live in aionetiface.
        self.addr = await Address(*self.dest, self.nic)
        for af in self.nic.supported():
            try:
                self.addr.select_ip(af)
                self.af = af
                break
            except KeyError:
                continue

        if not self.af:
            raise Exception("Dest AF is not supported by NIC.")
        
        return self

    def __await__(self):
        return self.start().__await__()

    async def get_dest_pipe(self):
        route = self.nic.route(self.af)

        # Bind to the loopback address explicitly so the connection succeeds.
        # For non-loopback destinations, bind to the default outbound address.
        # TODO: move this and similar FE80 logic into bind.
        if self.dest[0] in VALID_LOCALHOST:
            route = await route.bind(ips=self.dest[0])
        else:
            route = await route.bind()

        # Make TCP connection to namebump server.
        try:
            pipe = await Pipe(TCP, self.addr, route).connect()
            if pipe is None:
                raise Exception("Could not connect to namebump server.")
            
            return pipe
        except Exception:
            log_exception()
            raise

    async def return_resp(self, pipe):
        buf = await proto_recv(pipe)
        buf = decrypt(self.reply_sk, buf)
        pkt = Packet.unpack(buf)
        if not pkt.updated:
            pkt.value = None
        return pkt

    async def send_pkt(self, pipe, pkt, kp, sign=True):
        pkt.reply_pk = self.reply_pk
        msg = pkt.get_msg_to_sign()
        if sign:
            sig = kp.private.sign(msg)
        else:
            sig = b""

        buf = msg + sig
        enc_msg = encrypt(self.dest_pk, buf)
        dest = (self.addr.select_ip(self.af).ip, 5300)
        send_success = await pipe.send(enc_msg, dest)
        if not send_success:
            raise IOError("client send pkt failure")

    async def get(self, name, kp=None):
        pipe = None
        try:
            t = self.sys_clock.time()
            pipe = await self.get_dest_pipe()
            vkc = kp.vkc if kp else self.reply_pk
            pkt = Packet(OP_GET, name, vkc=vkc, updated=t)
            await self.send_pkt(pipe, pkt, kp, sign=bool(kp))
            return await self.return_resp(pipe)
        except asyncio.CancelledError:
            raise
        except Exception:
            log_exception()
            raise
        finally:
            if pipe is not None:
                await pipe.close()

    async def put(self, name, value, kp, behavior=DO_BUMP):
        pipe = None
        try:
            t = self.sys_clock.time()
            pipe = await self.get_dest_pipe()
            throw_bump = behavior == THROW_BUMP
            if behavior == THROW_BUMP:
                behavior = DONT_BUMP

            pkt = Packet(OP_PUT, name, value, kp.vkc, None, t, behavior)
            await self.send_pkt(pipe, pkt, kp)

            ret = await self.return_resp(pipe)
            if throw_bump and not ret.value:
                raise KeyError("putting this will bump.")

            return ret
        except Exception:
            log_exception()
            raise
        finally:
            if pipe is not None:
                await pipe.close()

    async def delete(self, name, kp):
        pipe = None
        try:
            t = self.sys_clock.time()
            pipe = await self.get_dest_pipe()
            pkt = Packet(OP_DEL, name, vkc=kp.vkc, updated=t)
            await self.send_pkt(pipe, pkt, kp)
            return await self.return_resp(pipe)
        except Exception:
            log_exception()
            raise
        finally:
            if pipe is not None:
                await pipe.close()

async def put(name, value, kp, behavior=DO_BUMP):
    client = await Client(DEST, PK)
    ret = await client.put(name, value, kp, behavior)
    if ret: return ret.value

async def get(name, kp=None):
    client = await Client(DEST, PK)
    ret = await client.get(name, kp)
    if ret: return ret.value

async def delete(name, kp):
    client = await Client(DEST, PK)
    ret = await client.delete(name, kp)
    if ret: return ret.value

if __name__ == "__main__":
    async def workspace():
        name = str(rand_plain(10))
        kp = Keypair.generate()

        out = await put(name, "value", kp)
        print(out)

        out = await get(name)
        print(out)

        out = await delete(name, kp)
        print(out)

        out = await get(name, kp)
        print(out)

    async_run(workspace())
