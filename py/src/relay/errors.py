"""The errors the library raises (API.md, "Errors")."""

from __future__ import annotations


class RelayError(Exception):
    """The base of everything this library raises."""


class PairingFailed(RelayError):
    """A pairing ended without binding a key."""


class WrongCode(PairingFailed):
    """The typed code matches no pending key, and the pairing may continue."""

    def __init__(self, tries_left: int):
        super().__init__(f"wrong code, {tries_left} tries left")
        self.tries_left = tries_left


class Revoked(RelayError):
    """The host revoked this guest, or forgot its channels."""


class PayloadInvalid(RelayError):
    """A pairing payload is malformed, expired or unacceptable (PROTOCOL.md section 4)."""


class ProtocolViolation(RelayError):
    """Internal: a frame or message breaks PROTOCOL.md."""
