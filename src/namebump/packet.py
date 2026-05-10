import random
import struct
import time
from ecdsa import VerifyingKey, SECP256k1, SigningKey, BadSignatureError
from aionetiface.utility.utils import log_exception, to_b
from .defs import DEFAULT_REQUEST_TTL, DO_BUMP, NB_NAME_LEN, NB_VAL_LEN


class Packet:
    """Wire-protocol message for namebump get/put/delete operations.

    Wire layout (fixed header = 59 bytes, followed by variable-length body):
        [0]       op        – 1 byte   operation code (OP_*)
        [1:5]     pkid      – 4 bytes  random packet ID (little-endian u32)
        [5:38]    reply_pk  – 33 bytes ephemeral ECIES reply key (zeros = absent)
        [38]      behavior  – 1 byte   bump behaviour flag (DO/DONT/THROW)
        [39:47]   updated   – 8 bytes  request timestamp (little-endian f64)
        [47:55]   ttl       – 8 bytes  request lifetime in seconds (little-endian f64)
        [55:57]   name_len  – 2 bytes  clamped name length
        [57:59]   val_len   – 2 bytes  clamped value length
        [59:]     name      – up to NB_NAME_LEN bytes
                  value     – up to NB_VAL_LEN bytes
                  vkc       – 33 bytes owner compressed public key (optional)
                  sig       – remaining bytes ECDSA signature (optional)

    The ttl field is included in the signed payload (see get_msg_to_sign), so
    a captured packet cannot be replayed past its owner-chosen window simply
    by rewriting the ttl on the wire. The server further caps acceptable ttls
    at MAX_REQUEST_TTL to prevent unbounded replay even by the legitimate
    signer.
    """

    def __init__(
        self,
        op,
        name,
        value=b"",
        vkc=None,
        sig=None,
        updated=None,
        behavior=DO_BUMP,
        pkid=None,
        reply_pk=None,
        reply_sk=None,
        ttl=None,
    ):
        self.updated = updated if updated is not None else time.time()
        self.ttl = ttl if ttl is not None else float(DEFAULT_REQUEST_TTL)
        self.op = op
        self.name = to_b(name)
        self.name_len = min(len(self.name), NB_NAME_LEN)
        self.value = to_b(value)
        self.value_len = min(len(self.value), NB_VAL_LEN)
        self.vkc = vkc
        self.sig = sig
        self.behavior = behavior
        self.pkid = pkid or random.randrange(0, 2**32)

        self.reply_pk = reply_pk
        self.reply_sk = reply_sk
        if vkc is not None:
            if len(vkc) != 33:
                raise ValueError(
                    "vkc must be 33 bytes (compressed public key), got {}".format(len(vkc))
                )

    def gen_reply_key(self):
        """Generate a fresh ephemeral ECDSA reply key pair and attach it to this packet."""
        self.reply_sk = SigningKey.generate(curve=SECP256k1)
        self.reply_pk = self.reply_sk.get_verifying_key().to_string("compressed")

    def get_msg_to_sign(self):
        """Return the canonical serialised bytes that the signature covers."""
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
            ttl=self.ttl,
        ).pack()

    def is_valid_sig(self):
        """Return True if the packet's ECDSA signature is valid for its vkc owner key."""
        vk = VerifyingKey.from_string(self.vkc, curve=SECP256k1)
        msg = self.get_msg_to_sign()
        try:
            vk.verify(self.sig, msg)
            return True
        except BadSignatureError:
            log_exception()
            return False

    def pack(self):
        """Serialise the packet to its wire-format byte string."""
        buf = b""

        buf += bytes([self.op])

        # ID for packet.
        buf += struct.pack("<I", self.pkid)
        assert len(buf) == 5, "pack: expected 5 bytes after pkid, got {}".format(len(buf))

        # Reply pk.
        if self.reply_pk is not None:
            if len(self.reply_pk) != 33:
                raise ValueError("reply_pk must be 33 bytes, got {}".format(len(self.reply_pk)))
            buf += self.reply_pk
        else:
            buf += b"\0" * 33
        assert len(buf) == 38, "pack: expected 38 bytes after reply_pk, got {}".format(
            len(buf)
        )

        # Behavior for changes.
        buf += bytes([self.behavior])

        # Prevent replay.
        buf += struct.pack("<d", self.updated)
        assert len(buf) == 47, "pack: expected 47 bytes after updated, got {}".format(
            len(buf)
        )

        # Per-request TTL (signed): server rejects if now - updated > ttl.
        buf += struct.pack("<d", self.ttl)
        assert len(buf) == 55, "pack: expected 55 bytes after ttl, got {}".format(
            len(buf)
        )

        # Header (lens.)
        buf += struct.pack("<H", self.name_len)
        buf += struct.pack("<H", self.value_len)
        assert len(buf) == 59, "pack: expected 59-byte header, got {}".format(len(buf))

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
        """Deserialise a wire-format buffer into a Packet instance."""
        # Point at start of buffer.
        p = 0

        # Operation.
        op = buf[p]
        p += 1

        # Packet ID.
        pkid = struct.unpack("<I", buf[p : p + 4])[0]
        p += 4

        # Reply pk.
        reply_pk = buf[p : p + 33]
        p += 33
        if reply_pk == b"\0" * 33:
            reply_pk = None

        # Behavior flag.
        behavior = buf[p]
        p += 1

        # Timestamp.
        updated = struct.unpack("<d", buf[p : p + 8])[0]
        p += 8

        # Per-request TTL (seconds).
        ttl = struct.unpack("<d", buf[p : p + 8])[0]
        p += 8

        # Name and value lengths (clamped to their declared maximums).
        name_len = min(struct.unpack("<H", buf[p : p + 2])[0], NB_NAME_LEN)
        p += 2
        val_len = min(struct.unpack("<H", buf[p : p + 2])[0], NB_VAL_LEN)
        p += 2

        # Name and value bodies.
        name = buf[p : p + name_len]
        p += name_len
        val = buf[p : p + val_len]
        p += val_len

        # Compressed verifying key and signature (optional — absent in server responses).
        remaining = len(buf) - p
        if remaining >= 33:
            vkc = buf[p : p + 33]
            p += 33
        else:
            vkc = None
        sig = buf[p:]

        return Packet(op, name, val, vkc, sig, updated, behavior, pkid, reply_pk, ttl=ttl)
