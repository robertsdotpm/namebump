"""Test configuration for namebump test suite."""
import unittest

from aionetiface.testing import AsyncTestCase

if not hasattr(unittest, "IsolatedAsyncioTestCase"):
    unittest.IsolatedAsyncioTestCase = AsyncTestCase
