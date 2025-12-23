import sys

# Prevent double imports.
if not '-m' in sys.argv:
    from .client import Client, get, put, delete, DO_BUMP, DONT_BUMP, THROW_BUMP
    from .keypair import Keypair
    from .server import Server, start_server, verified_pruning
    from .defs import *