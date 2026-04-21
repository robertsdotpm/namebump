"""
Integration tests for namebump PUT / GET / DELETE against the live PNP server.

Requires network access and a reachable PNP server.  The test is skipped
automatically if the server is unreachable so it does not break offline CI.

Run manually:
    python3 -m pytest tests/test_integration.py -v
"""

import asyncio
import socket
import time
import unittest

from namebump.client import Client, PK
from namebump.client import DEST
from namebump import Keypair
from aionetiface import Interface


def _server_reachable(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _skip_if_offline():
    host, port = DEST
    if not _server_reachable(host, port):
        raise unittest.SkipTest(f"PNP server {host}:{port} unreachable")


class TestLiveServer(unittest.IsolatedAsyncioTestCase):
    """PUT / GET / DELETE round-trip against the live namebump server."""

    async def asyncSetUp(self):
        _skip_if_offline()
        self.nic = Interface("default")
        self.client = await Client(DEST, PK, nic=self.nic)
        self.kp = Keypair.generate()
        # Use a unique name so parallel runs don't collide.
        self.name = "pytest_" + str(int(time.time() * 1000))[-8:]

    async def test_put_returns_value(self):
        pkt = await self.client.put(self.name, b"hello", self.kp)
        self.assertIsNotNone(pkt, "PUT should return a Packet")
        self.assertEqual(pkt.value, b"hello")

    async def test_get_after_put_returns_value(self):
        await self.client.put(self.name, b"hello", self.kp)
        pkt = await self.client.get(self.name)
        self.assertIsNotNone(pkt, "GET should return a Packet")
        self.assertIsNotNone(pkt.value, "GET value should not be None after PUT")
        self.assertEqual(pkt.value, b"hello")

    async def test_get_nonexistent_name_returns_none_value(self):
        pkt = await self.client.get("no_such_name_xyz_" + str(int(time.time())))
        # Server returns a Packet but with value=None (updated=0) for missing names.
        self.assertIsNotNone(pkt)
        self.assertIsNone(pkt.value)

    async def test_delete_removes_name(self):
        await self.client.put(self.name, b"todelete", self.kp)
        await self.client.delete(self.name, self.kp)
        pkt = await self.client.get(self.name)
        self.assertIsNone(pkt.value, "GET after DELETE should return no value")

    async def test_put_get_delete_full_roundtrip(self):
        value = b"roundtrip_value_" + str(int(time.time())).encode()

        # PUT
        put_pkt = await self.client.put(self.name, value, self.kp)
        self.assertEqual(put_pkt.value, value, "PUT should echo back the stored value")

        # GET
        get_pkt = await self.client.get(self.name)
        self.assertEqual(get_pkt.value, value, "GET should return the stored value")

        # DELETE
        del_pkt = await self.client.delete(self.name, self.kp)
        self.assertIsNotNone(del_pkt)

        # GET after DELETE
        gone_pkt = await self.client.get(self.name)
        self.assertIsNone(gone_pkt.value, "name should be gone after DELETE")

    async def test_overwrite_value(self):
        await self.client.put(self.name, b"first", self.kp)
        # Small sleep so timestamp differs (server rejects duplicate timestamps).
        await asyncio.sleep(0.05)
        await self.client.put(self.name, b"second", self.kp)
        pkt = await self.client.get(self.name)
        self.assertEqual(pkt.value, b"second", "second PUT should overwrite first")


if __name__ == "__main__":
    unittest.main()
