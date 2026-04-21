import namebump.namebump as namebump
import asyncio

async def run_server():
    await namebump.start_server()

    # Sleep forever.
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(run_server())
