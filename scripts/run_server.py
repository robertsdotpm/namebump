from namebump.server import start_server
from namebump.defs import NB_PORT
import asyncio


async def run_server() -> None:
    await start_server(NB_PORT)

    # Sleep forever.
    while True:
        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(run_server())
