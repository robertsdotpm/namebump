import sys

# Prevent double imports.
if not '-m' in sys.argv:
    from .defs import DO_BUMP, DONT_BUMP, THROW_BUMP
    from .client import Client, get, put, delete
    from .keypair import Keypair