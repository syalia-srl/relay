"""Check noise_ref against the published cacophony vectors for IKpsk1 and KK.

Usage: python check_cacophony.py [cacophony.txt]
Without an argument it reads cacophony_subset.json, the two entries we use.
"""

import json
import sys
from pathlib import Path

from noise_ref import HandshakeState

PROTOCOLS = {"Noise_IKpsk1_25519_AESGCM_SHA256": "IKpsk1", "Noise_KK_25519_AESGCM_SHA256": "KK"}


def run(vector: dict) -> None:
    x = lambda key: bytes.fromhex(vector[key]) if key in vector else None  # noqa: E731
    pattern = PROTOCOLS[vector["protocol_name"]]
    psk_i = bytes.fromhex(vector["init_psks"][0]) if vector.get("init_psks") else None
    psk_r = bytes.fromhex(vector["resp_psks"][0]) if vector.get("resp_psks") else None
    i = HandshakeState(pattern, True, x("init_prologue"), x("init_static"), x("init_remote_static"),
                       psk_i, x("init_ephemeral"))
    r = HandshakeState(pattern, False, x("resp_prologue"), x("resp_static"), x("resp_remote_static"),
                       psk_r, x("resp_ephemeral"))
    sessions = None
    for n, message in enumerate(vector["messages"]):
        payload, expected = bytes.fromhex(message["payload"]), bytes.fromhex(message["ciphertext"])
        initiator_sends = n % 2 == 0
        if sessions is None:
            sender, receiver = (i, r) if initiator_sends else (r, i)
            ct = sender.write_message(payload)
            assert ct == expected, f"handshake message {n}"
            assert receiver.read_message(ct) == payload
            if i.finished():
                assert i.h == r.h == bytes.fromhex(vector["handshake_hash"]), "handshake hash"
                (i1, i2), (r1, r2) = i.split(), r.split()
                sessions = {True: (i1, r1), False: (r2, i2)}
        else:
            send, recv = sessions[initiator_sends]
            ct = send.encrypt(b"", payload)
            assert ct == expected, f"transport message {n}"
            assert recv.decrypt(b"", ct) == payload


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name("cacophony_subset.json")
    vectors = [v for v in json.load(open(path))["vectors"] if v["protocol_name"] in PROTOCOLS]
    found = sorted(v["protocol_name"] for v in vectors)
    assert found == sorted(PROTOCOLS), f"expected one vector per protocol, found {found}"
    for vector in vectors:
        run(vector)
    print(f"{len(vectors)} cacophony vectors pass for IKpsk1 and KK")


if __name__ == "__main__":
    main()
