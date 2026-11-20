"""A custodian in Python (relay.rooms) for the JS rooms tests.

    keygen PEM                                     make a signing key, print its public JWK
    remove PEM BASE_URL ROOM DEVICE TOKEN TARGET   remove TARGET from the room, print the roster's readers
"""

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from relay.rooms import RoomClient, new_signing_key, public_jwk


def main(command: str, pem: str, *rest: str) -> None:
    if command == "keygen":
        key = new_signing_key()
        Path(pem).write_bytes(
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        )
        Path(pem).chmod(0o600)
        print(json.dumps(public_jwk(key)))
    elif command == "remove":
        base_url, room, device, token, target = rest
        key = serialization.load_pem_private_key(Path(pem).read_bytes(), None)
        client = RoomClient(base_url, token, room=room, device=device, key=key)
        client.remove(target)
        print(json.dumps(sorted(client.roster().readers())))
    else:
        sys.exit(f"unknown command {command}")


if __name__ == "__main__":
    main(*sys.argv[1:])
