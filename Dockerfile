FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install uv && uv pip install --system -e .
COPY src/ src/
EXPOSE 8010
CMD ["uvicorn", "inbox_relay.main:app", "--host", "0.0.0.0", "--port", "8010"]
