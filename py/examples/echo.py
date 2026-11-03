"""An echo host and a guest that pair through a relay and exchange one message.

Run it with a relay on a private address (PROTOCOL.md 8.1):

    RELAY_URL=ws://10.255.0.1:8010 RELAY_KEY=<project key> \
        uv run --project py python py/examples/echo.py
"""

import asyncio
import os
import tempfile

from relay import Guest, Host, Relay


async def main() -> None:
    relay = os.environ.get("RELAY_URL", "ws://10.255.0.1:8010")
    key = os.environ.get("RELAY_KEY", "example-key")
    with tempfile.TemporaryDirectory() as directory:
        host = await Host.open(
            f"{directory}/host", relays=[Relay(relay, key=key)]
        )
        guest = await Guest.open(f"{directory}/guest")

        pairing = await host.pair("echo")
        link = await guest.pair(pairing.payload)
        # A person reads link.code on the guest and types it into the host.
        device = await pairing.confirm(link.code)
        await link.bound()

        async def echo() -> None:
            async for sender, message in host:
                await sender.send(message)

        task = asyncio.create_task(echo())
        await link.send(b"hello from the guest")
        async for reply in link:
            print(f"guest received: {reply!r}")
            break

        await link.unpair()
        await guest.close()
        await host.close()
        task.cancel()


asyncio.run(main())
