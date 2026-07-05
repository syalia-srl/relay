from fastapi import FastAPI
from .router import router

app = FastAPI(title="inbox-relay")
app.include_router(router)
