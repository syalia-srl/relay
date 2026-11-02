import asyncio
import logging
import re
from contextlib import asynccontextmanager

from fastapi import FastAPI
from .router import router, store

GC_EVERY = 300

_TOKEN = re.compile(r"token=[^\s\"&]+")


class RedactTokens(logging.Filter):
    """uvicorn names each WebSocket by its request line, and the line carries the
    slot token: whoever reads the relay's logs would hold every slot."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if "token=" in message:
            record.msg, record.args = _TOKEN.sub("token=<redacted>", message), None
        return True


for _name in ("uvicorn.error", "uvicorn.access"):
    logging.getLogger(_name).addFilter(RedactTokens())


@asynccontextmanager
async def lifespan(app: FastAPI):
    async def sweep() -> None:
        while True:
            store.gc()
            await asyncio.sleep(GC_EVERY)

    task = asyncio.create_task(sweep())
    yield
    task.cancel()


app = FastAPI(title="inbox-relay", lifespan=lifespan)
app.include_router(router)
