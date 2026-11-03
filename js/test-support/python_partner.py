"""The Python side of the cross-language tests, driven over stdin and stdout.

One JSON object per line each way. The JavaScript test is the other side.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import sys
import threading


def emit(event: str, **fields: object) -> None:
    print(json.dumps({"event": event, **fields}), flush=True)


async def commands():
    """Lines from stdin, read by a daemon thread so a stop does not wait on it."""

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def read() -> None:
        for line in sys.stdin:
            loop.call_soon_threadsafe(queue.put_nowait, line)
        loop.call_soon_threadsafe(queue.put_nowait, None)

    threading.Thread(target=read, daemon=True).start()
    while True:
        line = await queue.get()
        if line is None:
            return
        yield json.loads(line)


async def host_mode(args: argparse.Namespace) -> None:
    from relay import Host, Relay

    host = await Host.open(args.state, relays=[Relay(args.relay, key=args.key)])
    pairing = await host.pair("python")
    emit("pairing", payload=pairing.payload, device=pairing.device)
    device = None

    async def collect() -> None:
        async for _, message in host:
            emit("message", data=base64.b64encode(message).decode())

    task = asyncio.create_task(collect())
    try:
        async for command in commands():
            if "code" in command:
                try:
                    device = await pairing.confirm(command["code"])
                except Exception as error:  # noqa: BLE001 - the test reads the name
                    emit("error", message=f"{type(error).__name__}: {error}")
                    return
                emit("bound", id=device.id, name=device.name)
            elif "send" in command:
                await device.send(base64.b64decode(command["send"]))
                emit("sent")
            elif "stop" in command:
                return
    finally:
        task.cancel()
        await host.close()
        emit("closed")


async def guest_mode(args: argparse.Namespace) -> None:
    from relay import Guest

    guest = await Guest.open(args.state)
    link = await guest.pair(args.payload)
    emit("code", code=link.code)
    await link.bound()
    emit("bound")

    async def collect() -> None:
        async for message in link:
            emit("message", data=base64.b64encode(message).decode())

    task = asyncio.create_task(collect())
    try:
        async for command in commands():
            if "send" in command:
                await link.send(base64.b64decode(command["send"]))
                emit("sent")
            elif "stop" in command:
                return
    finally:
        task.cancel()
        await link.unpair()
        await guest.close()
        emit("closed")


async def main(args: argparse.Namespace) -> None:
    if args.mode == "host":
        await host_mode(args)
    else:
        await guest_mode(args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["host", "guest"])
    parser.add_argument("--state", required=True)
    parser.add_argument("--relay")
    parser.add_argument("--key")
    parser.add_argument("--payload")
    asyncio.run(main(parser.parse_args()))
