"""Static source-review fixture, not a secure chat protocol. Do not deploy."""

from crypto import open_key as unwrap


def receive_envelope(secret_key, ciphertext):
    try:
        return unwrap(secret_key, ciphertext)
    except ValueError:
        raise ValueError("Envelope rejected") from None
