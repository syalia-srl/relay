/**
 * The errors the library throws (API.md, "Errors"), and the internal signals the
 * socket loops use to tell "go back to step 1 of PROTOCOL.md §8.2" from a bug.
 */

export class RelayError extends Error {
  constructor(message) {
    super(message);
    this.name = new.target.name;
  }
}

/** A pairing ended without binding a key. */
export class PairingFailed extends RelayError {}

/** The typed code matches no pending key, and the pairing may continue. */
export class WrongCode extends RelayError {
  constructor(triesLeft) {
    super(`wrong code, ${triesLeft} tries left`);
    this.triesLeft = triesLeft;
  }
}

/** The host revoked this guest, or forgot its channels. */
export class Revoked extends RelayError {}

/** A pairing payload is malformed, expired or unacceptable (PROTOCOL.md §4). */
export class PayloadInvalid extends RelayError {}

/**
 * Internal: a frame or message breaks PROTOCOL.md. Every failure inside the
 * library is this one class, so a socket loop has a single thing to catch and a
 * hostile relay can never end it with an uncaught error.
 */
export class ProtocolViolation extends RelayError {}

/** Internal: the AES-GCM tag did not verify. */
export class TagFailure extends ProtocolViolation {}

/** Internal: the relay closed the WebSocket, with the code it sent. */
export class SocketClosed extends Error {
  constructor(code) {
    super(`the relay closed with ${code}`);
    this.name = new.target.name;
    this.code = code;
  }
}

/** Internal: the relay no longer has the channel (4401 or 4410). */
export class ChannelGone extends SocketClosed {}
