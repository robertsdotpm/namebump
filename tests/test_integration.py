"""
Integration tests for namebump PUT / GET / DELETE against the live PNP server.

Requires network access and a reachable PNP server.  The test is skipped
automatically if the server is unreachable so it does not break offline CI.

Run manually:
    python3 -m pytest tests/test_integration.py -v
"""

import asyncio
import hashlib
import socket
import unittest

from ecdsa import SigningKey, SECP256k1
from namebump.client import Client, PK
from namebump.client import DEST
from namebump import Keypair
from aionetiface import Interface
from server_retry_helpers import with_server_retry

# Fixed test keypair — reuses the same name slot on each run so it doesn't
# accumulate entries against the IP's registration quota.
_TEST_SK_BYTES = hashlib.sha256(b"namebump_pytest_fixed_key").digest()
TEST_KP = Keypair(SigningKey.from_string(_TEST_SK_BYTES, curve=SECP256k1))


def _server_reachable(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _skip_if_offline():
    host, port = DEST
    if not _server_reachable(host, port):
        raise unittest.SkipTest("PNP server {}:{} unreachable".format(host, port))


class TestLiveServer(AsyncTestCase):
    """PUT / GET / DELETE round-trip against the live namebump server."""

    async def asyncSetUp(self):
        _skip_if_offline()
        self.nic = Interface("default")
        self.client = await Client(DEST, PK, nic=self.nic)
        # Use a fixed keypair so repeated runs reuse the same name slot
        # rather than accumulating new entries against the IP's quota.
        self.kp = TEST_KP
        self.name = "pt_" + self.kp.vkc.hex()[:16]

        # Probe that we have a writable slot.  A successful PUT echoes the
        # value back; b"" means the server hit its per-IP quota
        # (ResourceLimit).  Wrap in with_server_retry so a single transient
        # network blip during setup doesn't pretend the slot is full.
        try:
            probe = await with_server_retry(
                lambda: self.client.put(self.name, b"\x01probe", self.kp),
            )
        except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
            self.skipTest(
                "PNP server {0} unreachable after retries: {1!r}".format(
                    DEST, exc,
                )
            )
        if probe.value != b"\x01probe":
            self.skipTest(
                "server PUT quota full or clock skew – old entries expire after 7 days"
            )

    async def asyncTearDown(self):
        # Reclaim the slot (PUT empty) rather than DELETE so the next test
        # can always UPDATE (quota-safe) instead of INSERT.
        try:
            await self.retry_put(b"")
        except Exception:
            pass

    # ---- retrying client wrappers ----
    # Each thin wrapper runs the underlying Client op under
    # with_server_retry so a single transient flake against the live
    # PNP DEST doesn't fail the whole test. Client.with_retry already
    # gives 3x retry per network attempt; this gives the *test* an
    # extra outer loop that re-runs the full pipe-open + send + recv
    # cycle, useful when a single server is mid-restart and the inner
    # retries all hit the same dead state.
    async def retry_put(self, value, behavior=None):
        kw = {} if behavior is None else {"behavior": behavior}
        return await with_server_retry(
            lambda: self.client.put(self.name, value, self.kp, **kw),
        )

    async def retry_get(self, name=None):
        target = self.name if name is None else name
        return await with_server_retry(lambda: self.client.get(target))

    async def retry_delete(self):
        return await with_server_retry(
            lambda: self.client.delete(self.name, self.kp),
        )

    async def test_put_returns_value(self):
        pkt = await self.retry_put(b"hello")
        self.assertIsNotNone(pkt, "PUT should return a Packet")
        self.assertEqual(pkt.value, b"hello")

    async def test_get_after_put_returns_value(self):
        await self.retry_put(b"hello")
        pkt = await self.retry_get()
        self.assertIsNotNone(pkt, "GET should return a Packet")
        self.assertIsNotNone(pkt.value, "GET value should not be None after PUT")
        self.assertEqual(pkt.value, b"hello")

    async def test_get_nonexistent_name_returns_none_value(self):
        absent = hashlib.sha256(b"namebump_pytest_absent_key").hexdigest()[:16]
        pkt = await self.retry_get(absent)
        # Server returns a Packet but with value=None (updated=0) for missing names.
        self.assertIsNotNone(pkt)
        self.assertIsNone(pkt.value)

    async def test_delete_removes_name(self):
        await self.retry_put(b"todelete")
        await self.retry_delete()
        pkt = await self.retry_get()
        self.assertIsNone(pkt.value, "GET after DELETE should return no value")

    async def test_put_get_delete_full_roundtrip(self):
        value = b"roundtrip_value_" + self.kp.vkc.hex()[:8].encode()

        # PUT
        put_pkt = await self.retry_put(value)
        self.assertEqual(put_pkt.value, value, "PUT should echo back the stored value")

        # GET
        get_pkt = await self.retry_get()
        self.assertEqual(get_pkt.value, value, "GET should return the stored value")

        # DELETE
        del_pkt = await self.retry_delete()
        self.assertIsNotNone(del_pkt)

        # GET after DELETE
        gone_pkt = await self.retry_get()
        self.assertIsNone(gone_pkt.value, "name should be gone after DELETE")

    async def test_overwrite_value(self):
        await self.retry_put(b"first")
        # Small sleep so timestamp differs (server rejects duplicate timestamps).
        await asyncio.sleep(0.05)
        await self.retry_put(b"second")
        pkt = await self.retry_get()
        self.assertEqual(pkt.value, b"second", "second PUT should overwrite first")


if __name__ == "__main__":
    unittest.main()
