"""


"""

# TODO: different key per request.

import time
from ecdsa import SECP256k1, SigningKey
from aionetiface import *
from aionetiface.utility.sys_clock import *
from aionetiface.vendor.ecies import *
from .utils import *
from .keypair import *

"""
Important: since this immediately returns if one
were to follow-up with another call without waiting for
status receipt it may return an invalid value
indicating that the server hasn't done the previous call yet.

        self.sk = sk
        self.vkc = sk.verifying_key.to_string("compressed")
"""


class Client():
    def __init__(self, dest, dest_pk, sys_clock=None, nic=Interface("default")):
        self.dest_pk = dest_pk
        assert(isinstance(dest_pk, bytes))
        self.nic = nic
        self.dest = dest
        self.reply_sk = SigningKey.generate(curve=SECP256k1)
        self.reply_pk = self.reply_sk.get_verifying_key().to_string("compressed")
        self.sys_clock = sys_clock
        assert(len(self.reply_pk) == 33)

    async def start(self):
        if not self.sys_clock:
            self.sys_clock = time
            
            #await SysClock(self.nic)

        return self

    def __await__(self):
        return self.start().__await__()

    async def get_dest_pipe(self):
        addr = Address(self.dest[0], self.dest[1])
        await addr.res(self.nic.route())
        ipr = addr.v4_ipr or addr.v6_ipr
        route = self.nic.route(ipr.af)
        if self.dest[0] in VALID_LOCALHOST:
            route = await route.bind(ips=self.dest[0])
        else:
            route = await route.bind()

        try:
            pipe = await Pipe(TCP, self.dest, route).connect()
            return pipe
        except Exception:
            log_exception()
            return None

    async def return_resp(self, pipe):
        try:
            buf = await proto_recv(pipe)
            buf = decrypt(self.reply_sk, buf)
            #print("decrypted pnp resp:", buf)
            pkt = PNPPacket.unpack(buf)
            #print(pkt)
            
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
        end = 1 if self.proto == TCP else 3
        for _ in range(0, end):
            send_success = await pipe.send(enc_msg, self.dest)
            if not send_success:
                log(fstr("pnp client send pkt failure."))

            if end > 1:
                await asyncio.sleep(0.5)

    async def fetch(self, name, kp):
        try:
            pipe = await self.get_dest_pipe()
            pkt = PNPPacket(name, vkc=kp.public)
            await self.send_pkt(pipe, pkt, kp, sign=False)
            return await self.return_resp(pipe)
        except asyncio.CancelledError:
            raise
        except Exception:
            log_exception()

    async def push(self, name, value, kp, behavior=BEHAVIOR_DO_BUMP):
        try:
            t = int(self.sys_clock.time())
            pipe = await self.get_dest_pipe()
            pkt = PNPPacket(name, value, kp.public, None, t, behavior)
            await self.send_pkt(pipe, pkt, kp)
            return await self.return_resp(pipe)
        except Exception:
            log_exception()

    async def delete(self, name, kp):
        try:
            t = int(self.sys_clock.time())
            pipe = await self.get_dest_pipe()
            pkt = PNPPacket(name, vkc=kp.public, updated=t)
            await self.send_pkt(pipe, pkt, kp)
            return await self.return_resp(pipe)
        except Exception:
            log_exception()

async def put(name, value, kp):
    pass

async def get():
    pass

async def delete():
    pass

if __name__ == "__main__":
    async def workspace():
        nic = Interface("default")
        dest = ("10.0.1.204", 5300)
        addr = Address(*dest)
        await addr.res(nic.route())

        r = nic.route()
        pipe = await Pipe(TCP, ("10.0.1.204", 5300), r).connect()

        print(pipe)
        return

        kp = Keypair.generate()
        client = await Client(
            ("10.0.1.123", 5300),
            b"03f20b5dcfa5d319635a34f18cb47b339c34f515515a5be733cd7a7f8494e97136"
        )

        return

        name = str(rand_plain(10))
        ret = await client.push(name, "v", kp)
        print(ret)

    async_run(workspace())