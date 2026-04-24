"""Test configuration for namebump test suite."""
import unittest

import pytest

from aionetiface import aionetiface_setup_event_loop
from aionetiface.testing import AsyncTestCase, allow_windows_firewall, remove_windows_firewall

aionetiface_setup_event_loop()

if not hasattr(unittest, "IsolatedAsyncioTestCase"):
    unittest.IsolatedAsyncioTestCase = AsyncTestCase


@pytest.fixture(scope="session", autouse=True)
def windows_firewall_rule():
    allow_windows_firewall("python-test-suite")
    yield
    remove_windows_firewall("python-test-suite")
