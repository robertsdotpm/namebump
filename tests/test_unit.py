"""
Unit tests for namebump packet serialization, keypair operations, and server
helpers. These tests run without a live MySQL server or network connection.
"""

import unittest
from namebump.packet import Packet
from namebump.keypair import Keypair
from namebump.defs import (
    OP_GET,
    OP_PUT,
    OP_DEL,
    OP_ERROR,
    DO_BUMP,
    DONT_BUMP,
    THROW_BUMP,
    NB_NAME_LEN,
    NB_VAL_LEN,
)
from namebump.server import get_v6_parts


FIXED_TIME = 1_700_000_000.0


# ---------------------------------------------------------------------------
# Packet round-trip tests
# ---------------------------------------------------------------------------


class TestPacketRoundTrip(unittest.TestCase):
    def _make_packet(
        self,
        op=OP_GET,
        name=b"testname",
        value=b"testvalue",
        vkc=None,
        behavior=DO_BUMP,
        reply_pk=None,
    ):
        kp = Keypair.generate()
        return Packet(
            op=op,
            name=name,
            value=value,
            vkc=vkc or kp.vkc,
            updated=FIXED_TIME,
            behavior=behavior,
            reply_pk=reply_pk,
        ), kp

    def test_pack_unpack_get(self):
        pkt, kp = self._make_packet(op=OP_GET)
        buf = pkt.pack()
        restored = Packet.unpack(buf)

        self.assertEqual(restored.op, OP_GET)
        self.assertEqual(restored.name, b"testname")
        self.assertEqual(restored.value, b"testvalue")
        self.assertEqual(restored.updated, FIXED_TIME)
        self.assertEqual(restored.behavior, DO_BUMP)

    def test_pack_unpack_put(self):
        pkt, kp = self._make_packet(op=OP_PUT, value=b"hello world")
        buf = pkt.pack()
        restored = Packet.unpack(buf)

        self.assertEqual(restored.op, OP_PUT)
        self.assertEqual(restored.value, b"hello world")

    def test_pack_unpack_del(self):
        pkt, kp = self._make_packet(op=OP_DEL, value=b"")
        buf = pkt.pack()
        restored = Packet.unpack(buf)

        self.assertEqual(restored.op, OP_DEL)

    def test_pack_unpack_error(self):
        kp = Keypair.generate()
        pkt = Packet(
            op=OP_ERROR,
            name=b"Error",
            value=b"something went wrong",
            vkc=kp.vkc,
            updated=FIXED_TIME,
        )
        restored = Packet.unpack(pkt.pack())
        self.assertEqual(restored.op, OP_ERROR)
        self.assertEqual(restored.value, b"something went wrong")

    def test_pkid_preserved(self):
        pkt, _ = self._make_packet()
        original_pkid = pkt.pkid
        restored = Packet.unpack(pkt.pack())
        self.assertEqual(restored.pkid, original_pkid)

    def test_reply_pk_preserved(self):
        reply_kp = Keypair.generate()
        pkt, _ = self._make_packet(reply_pk=reply_kp.vkc)
        restored = Packet.unpack(pkt.pack())
        self.assertEqual(restored.reply_pk, reply_kp.vkc)

    def test_reply_pk_none_roundtrip(self):
        pkt, _ = self._make_packet(reply_pk=None)
        pkt.reply_pk = None
        restored = Packet.unpack(pkt.pack())
        self.assertIsNone(restored.reply_pk)

    def test_name_truncated_to_max_len(self):
        long_name = b"x" * (NB_NAME_LEN + 20)
        pkt, _ = self._make_packet(name=long_name)
        restored = Packet.unpack(pkt.pack())
        self.assertLessEqual(len(restored.name), NB_NAME_LEN)

    def test_value_truncated_to_max_len(self):
        long_val = b"v" * (NB_VAL_LEN + 20)
        pkt, _ = self._make_packet(value=long_val)
        restored = Packet.unpack(pkt.pack())
        self.assertLessEqual(len(restored.value), NB_VAL_LEN)

    def test_behavior_dont_bump_preserved(self):
        pkt, _ = self._make_packet(behavior=DONT_BUMP)
        restored = Packet.unpack(pkt.pack())
        self.assertEqual(restored.behavior, DONT_BUMP)

    def test_behavior_throw_bump_preserved(self):
        pkt, _ = self._make_packet(behavior=THROW_BUMP)
        restored = Packet.unpack(pkt.pack())
        self.assertEqual(restored.behavior, THROW_BUMP)

    def test_empty_name_and_value(self):
        pkt, _ = self._make_packet(name=b"", value=b"")
        restored = Packet.unpack(pkt.pack())
        self.assertEqual(restored.name, b"")
        self.assertEqual(restored.value, b"")

    def test_non_ascii_bytes_in_value(self):
        value = bytes(range(0, 256))
        pkt, _ = self._make_packet(value=value[:NB_VAL_LEN])
        restored = Packet.unpack(pkt.pack())
        self.assertEqual(restored.value, value[:NB_VAL_LEN])

    def test_string_name_converted_to_bytes(self):
        pkt, _ = self._make_packet(name="hello")
        self.assertIsInstance(pkt.name, bytes)

    def test_string_value_converted_to_bytes(self):
        pkt, _ = self._make_packet(value="world")
        self.assertIsInstance(pkt.value, bytes)

    def test_fixed_header_size(self):
        pkt, _ = self._make_packet()
        buf = pkt.pack()
        # Header up to and including lengths is always 51 bytes
        self.assertGreaterEqual(len(buf), 51)

    def test_updated_timestamp_zero(self):
        pkt, kp = self._make_packet()
        pkt2 = Packet(OP_GET, b"n", updated=0.0, vkc=kp.vkc)
        restored = Packet.unpack(pkt2.pack())
        self.assertEqual(restored.updated, 0.0)


# ---------------------------------------------------------------------------
# Signature tests
# ---------------------------------------------------------------------------


class TestPacketSignature(unittest.TestCase):
    def _signed_packet(self, op=OP_PUT):
        kp = Keypair.generate()
        pkt = Packet(
            op=op, name=b"myname", value=b"myval", vkc=kp.vkc, updated=FIXED_TIME
        )
        msg = pkt.get_msg_to_sign()
        pkt.sig = kp.private.sign(msg)
        return pkt, kp

    def test_valid_signature_accepted(self):
        pkt, _ = self._signed_packet()
        self.assertTrue(pkt.is_valid_sig())

    def test_tampered_value_fails_verification(self):
        pkt, _ = self._signed_packet()
        pkt.value = b"tampered"
        self.assertFalse(pkt.is_valid_sig())

    def test_tampered_name_fails_verification(self):
        pkt, _ = self._signed_packet()
        pkt.name = b"tampered"
        self.assertFalse(pkt.is_valid_sig())

    def test_wrong_key_fails_verification(self):
        pkt, _ = self._signed_packet()
        other_kp = Keypair.generate()
        pkt.vkc = other_kp.vkc
        self.assertFalse(pkt.is_valid_sig())

    def test_empty_sig_fails_verification(self):
        pkt, _ = self._signed_packet()
        pkt.sig = b""
        self.assertFalse(pkt.is_valid_sig())

    def test_corrupted_sig_fails_verification(self):
        pkt, _ = self._signed_packet()
        pkt.sig = b"\x00" * len(pkt.sig)
        self.assertFalse(pkt.is_valid_sig())

    def test_sign_verify_del_op(self):
        pkt, _ = self._signed_packet(op=OP_DEL)
        self.assertTrue(pkt.is_valid_sig())

    def test_get_msg_to_sign_excludes_sig(self):
        pkt, kp = self._signed_packet()
        msg1 = pkt.get_msg_to_sign()
        pkt.sig = b"something_else"
        msg2 = pkt.get_msg_to_sign()
        # The message to sign should not depend on the sig field
        self.assertEqual(msg1, msg2)

    def test_reply_key_generation(self):
        kp = Keypair.generate()
        pkt = Packet(OP_GET, b"name", vkc=kp.vkc, updated=FIXED_TIME)
        pkt.gen_reply_key()
        self.assertIsNotNone(pkt.reply_sk)
        self.assertIsNotNone(pkt.reply_pk)
        self.assertEqual(len(pkt.reply_pk), 33)


# ---------------------------------------------------------------------------
# Keypair tests
# ---------------------------------------------------------------------------


class TestKeypair(unittest.TestCase):
    def test_generate_produces_valid_keypair(self):
        kp = Keypair.generate()
        self.assertIsNotNone(kp.private)
        self.assertIsNotNone(kp.public)

    def test_vkc_is_33_bytes(self):
        kp = Keypair.generate()
        self.assertEqual(len(kp.vkc), 33)

    def test_two_generated_keys_differ(self):
        kp1 = Keypair.generate()
        kp2 = Keypair.generate()
        self.assertNotEqual(kp1.vkc, kp2.vkc)

    def test_sign_and_verify(self):
        kp = Keypair.generate()
        msg = b"hello world"
        sig = kp.private.sign(msg)
        # Should not raise
        kp.public.verify(sig, msg)

    def test_keypair_from_existing_private_key(self):
        from ecdsa import SigningKey, SECP256k1

        sk = SigningKey.generate(curve=SECP256k1)
        kp = Keypair(priv=sk)
        self.assertEqual(kp.public, sk.get_verifying_key())


# ---------------------------------------------------------------------------
# get_v6_parts tests
# ---------------------------------------------------------------------------


class TestGetV6Parts(unittest.TestCase):
    def test_known_address_parses_correctly(self):
        from aionetiface import IPRange

        ipr = IPRange("2001:0db8:85a3:0000:0000:8a2e:0370:7334", bitlen=0)
        parts = get_v6_parts(ipr)
        self.assertEqual(len(parts), 4)

    def test_returns_four_integers(self):
        from aionetiface import IPRange

        ipr = IPRange("fe80:0000:0000:0000:0202:b3ff:fe1e:8329", bitlen=0)
        parts = get_v6_parts(ipr)
        for part in parts:
            self.assertIsInstance(part, int)

    def test_different_addresses_give_different_glob_main(self):
        from aionetiface import IPRange

        ipr1 = IPRange("2001:0db8:85a3:0000:0000:8a2e:0370:7334", bitlen=0)
        ipr2 = IPRange("fe80:0000:0000:0000:0202:b3ff:fe1e:8329", bitlen=0)
        parts1 = get_v6_parts(ipr1)
        parts2 = get_v6_parts(ipr2)
        self.assertNotEqual(parts1[0], parts2[0])

    def test_same_address_consistent_results(self):
        from aionetiface import IPRange

        ipr = IPRange("2001:0db8:85a3:0000:0000:8a2e:0370:7334", bitlen=0)
        self.assertEqual(get_v6_parts(ipr), get_v6_parts(ipr))


# ---------------------------------------------------------------------------
# Packet construction error tests
# ---------------------------------------------------------------------------


class TestPacketConstructionErrors(unittest.TestCase):
    def test_missing_updated_raises(self):
        kp = Keypair.generate()
        with self.assertRaises(Exception):
            Packet(OP_GET, b"name", vkc=kp.vkc)

    def test_vkc_wrong_length_raises(self):
        with self.assertRaises((ValueError, AssertionError)):
            Packet(OP_GET, b"name", vkc=b"\x02" * 32, updated=FIXED_TIME)


if __name__ == "__main__":
    unittest.main()
