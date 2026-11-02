# tests/conftest.py — the store's file lives in a temp dir, set before the app imports.
import os
import tempfile

os.environ["RELAY_STATE_PATH"] = os.path.join(tempfile.mkdtemp(prefix="relay-state-"), "channels.json")
