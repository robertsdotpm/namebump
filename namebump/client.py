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
from .utils import *
from .keypair import *

DEST = ("ovh1.p2pd.net", 5300)
PK = h_to_b("03f20b5dcfa5d319635a34f18cb47b339c34f515515a5be733cd7a7f8494e97136")

class Client():
    def __init__(self, dest, dest_pk, sys_clock=None, nic=Interface("default")):
        # Specific namebump server details.
        self.dest = dest
        self.dest_pk = dest_pk
        assert(isinstance(dest_pk, bytes))
        assert(len(dest_pk) == 33)

        # Ephemeral key to receive encrypted reply on.
        self.reply_sk = SigningKey.generate(curve=SECP256k1)
        self.reply_pk = self.reply_sk.get_verifying_key().to_string("compressed")
        assert(len(self.reply_pk) == 33)

        # Requests have a timestamp so they can expire.
        # Sys_clock is initialised from an NTP call.
        self.sys_clock = sys_clock

        # Other network-specific info.
        self.nic = nic
        self.af = None
        self.addr = None

    async def start(self):
        if not self.sys_clock:
            self.sys_clock = time

        """
        A dest may be passed in as a domain name that supports
        different address families. This code tries to select an AF
        that the local NIC also supports.

        TODO: This should really be moved to aionetiface too.
        """
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

        # Dest is a loopback address.
        # Otherwise the connection won't succeed.
        # TODO: move this and similar FE80 logic into bind tbh.
        if self.dest[0] in VALID_LOCALHOST:
            route = await route.bind(ips=self.dest[0])
        
        # Destination is not loopback.
        if self.dest[0] not in VALID_LOCALHOST:
            route = await route.bind()

        # Make TCP connection to namebump server.
        try:
            pipe = await Pipe(TCP, self.addr, route).connect()
            return pipe
        except Exception:
            log_exception()
            return None

    async def return_resp(self, pipe):
        try:
            buf = await proto_recv(pipe)
            buf = decrypt(self.reply_sk, buf)
            pkt = PNPPacket.unpack(buf)
            if not pkt.updated:
                pkt.value = None

            return pkt
        except Exception:
            log_exception()
            return None
        finally:
            await pipe.close()

    async def send_pkt(self, pipe, pkt, kp, sign=True):
        pkt.reply_pk = self.reply_pk
        pnp_msg = pkt.get_msg_to_sign()
        if sign:
            sig = kp.private.sign(pnp_msg)
        else:
            sig = b""

        buf = pnp_msg + sig
        enc_msg = encrypt(self.dest_pk, buf)
        dest = (self.addr.select_ip(self.af).ip, 5300)
        send_success = await pipe.send(enc_msg, dest)
        if not send_success:
            log(fstr("pnp client send pkt failure."))

    async def get(self, name, kp=None):
        try:
            pipe = await self.get_dest_pipe()
            vkc = kp.vkc if kp else self.reply_pk
            pkt = PNPPacket(name, vkc=vkc)
            await self.send_pkt(pipe, pkt, kp, sign=False)
            return await self.return_resp(pipe)
        except asyncio.CancelledError:
            raise
        except Exception:
            log_exception()

    async def put(self, name, value, kp, behavior=BEHAVIOR_DO_BUMP):
        t = int(self.sys_clock.time())
        pipe = await self.get_dest_pipe()
        try:
            pkt = PNPPacket(name, value, kp.vkc, None, t, behavior)
            await self.send_pkt(pipe, pkt, kp)
            return await self.return_resp(pipe)
        except Exception:
            log_exception()

    async def delete(self, name, kp):
        try:
            t = int(self.sys_clock.time())
            pipe = await self.get_dest_pipe()
            pkt = PNPPacket(name, vkc=kp.vkc, updated=t)
            await self.send_pkt(pipe, pkt, kp)
            return await self.return_resp(pipe)
        except Exception:
            log_exception()

async def put(name, value, kp, behavior=BEHAVIOR_DO_BUMP):
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

        """
        pk = MAIN_PK
        client = await Client(
            ("127.0.0.1", 5300),
            pk
        )

        ret = await client.put(name, "v", kp)
        print(ret)
        print(ret.value)

        ret = await client.get(name, kp)
        print(ret)
        print(ret.value)

        """

        out = await put(name, "value", kp)
        print(out)

        out = await get(name, kp)
        print(out)

        out = await delete(name, kp)
        print(out)

        out = await get(name, kp)
        print(out)


    async_run(workspace())