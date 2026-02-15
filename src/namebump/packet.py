import time
import random
import struct
from ecdsa import VerifyingKey, SECP256k1, SigningKey
from aionetiface.utility.utils import *
from .defs import *

#####################################################################################

class Packet():
    def __init__(self, op, name, value=b"", vkc=None, sig=None, updated=None, behavior=DO_BUMP, pkid=None, reply_pk=None, reply_sk=None):
        if updated is not None:
            self.updated = updated
        else:
            raise Exception("packet update time not set.")

        self.op = op
        self.name = to_b(name)
        self.name_len = min(len(self.name), NB_NAME_LEN)
        self.value = to_b(value)
        self.value_len = min(len(self.value), NB_VAL_LEN)
        self.vkc = vkc
        self.sig = sig
        self.behavior = behavior
        self.pkid = pkid or random.randrange(0, 2 ** 32)

        self.reply_pk = reply_pk
        self.reply_sk = reply_sk
        if vkc is not None:
            assert(len(vkc) == 33)

    def gen_reply_key(self):
        self.reply_sk = SigningKey.generate(curve=SECP256k1)
        self.reply_pk = self.reply_sk.get_verifying_key().to_string("compressed")

    def get_msg_to_sign(self):
        return Packet(
            self.op,
            self.name,
            self.value,
            updated=self.updated,
            vkc=self.vkc,
            sig=None,
            behavior=self.behavior,
            pkid=self.pkid,
            reply_pk=self.reply_pk,
        ).pack()

    def is_valid_sig(self):
        vk = VerifyingKey.from_string(self.vkc, curve=SECP256k1)
        msg = self.get_msg_to_sign()
        try:
            # recover_verify_key(msg, self.sig, vk_b)
            vk.verify(self.sig, msg)
            return True
        except Exception:
            log_exception()
            return False

    def pack(self):
        buf = b""

        buf += bytes([self.op])

        # ID for packet.
        buf += struct.pack("<I", self.pkid)
        assert(len(buf) == 5)

        # Reply pk.
        if self.reply_pk is not None:
            buf += self.reply_pk
            assert(len(self.reply_pk) == 33)
        else:
            buf += b"\0" * 33
        assert(len(buf) == 38)

        # Behavior for changes.
        buf += bytes([self.behavior])

        # Prevent replay.
        buf += struct.pack("<Q", self.updated)
        assert(len(buf) == 47)

        # Header (lens.)
        buf += struct.pack("<H", self.name_len)
        buf += struct.pack("<H", self.value_len)
        assert(len(buf) == 51)

        # Body (var len - limit)
        buf += self.name[:NB_NAME_LEN]
        buf += self.value[:NB_VAL_LEN]
        
        # Variable length.
        if self.vkc is not None:
            buf += self.vkc
        if self.sig is not None:
            buf += self.sig

        return buf
    
    @staticmethod
    def unpack(buf):
        # Point at start of buffer.
        p = 0

        # Operation.
        op = buf[p]
        p += 1

        # Packet ID.
        pkid = struct.unpack("<I", buf[p:p + 4])[0]; p += 4;

        # Reply pk.
        reply_pk = buf[p:p + 33]; p += 33;
        if reply_pk == b"\0" * 33:
            reply_pk = None

        # Extract behavior.
        behavior = buf[p]; p += 1;

        # Extract timestamp portion.
        updated = struct.unpack("<Q", buf[p:p + 8])[0]; p += 8;

        # Extract header portion.
        name_len = struct.unpack("<H", buf[p:p + 2])[0]; p += 2;
        val_len = struct.unpack("<H", buf[p:p + 2])[0]; p += 2;
        min(name_len, NB_NAME_LEN)
        min(val_len, NB_VAL_LEN)

        # Extract body fields.
        name = buf[p:p + name_len]; p += name_len;
        val = buf[p:p + val_len]; p += val_len;

        # Extract sig field.
        vkc = buf[p:p + 33]; p += 33;
        #print(vkc)
        sig = buf[p:]
        #print(sig)

        return Packet(op, name, val, vkc, sig, updated, behavior, pkid, reply_pk)

