"""Illustrative wrapper: provider code is outside this fixture."""

from pqcrypto.kem.ml_kem_768 import decrypt as decapsulate


def recover_key(secret_key, ciphertext):
    operation = decapsulate
    return operation(secret_key, ciphertext)
