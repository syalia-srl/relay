FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install uv && uv pip install --system -e .
COPY src/ src/
# Channels survive a restart only if /data is a volume (docker run -v relay-data:/data).
RUN mkdir -p /data
ENV RELAY_STATE_PATH=/data/channels.json
EXPOSE 8010
# No access log: a WebSocket's request line carries its slot token in the query.
CMD ["uvicorn", "inbox_relay.main:app", "--host", "0.0.0.0", "--port", "8010", "--no-access-log"]
