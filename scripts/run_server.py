import namebump
import asyncio

async def run_server():
    await namebump.start_server()

    # Sleep forever.
    while 1:
        await asyncio.sleep(1)

asyncio.run(run_server())

