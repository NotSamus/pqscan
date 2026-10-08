"""Illustrative scan fixture, not a complete authenticated protocol."""
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

public_key, private_key = ml_kem_768.generate_keypair()
signing_public, signing_private = ml_dsa_65.generate_keypair()
