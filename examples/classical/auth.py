"""Scan fixture; dependencies are not needed to scan this file."""
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
token = jwt.encode({"sub": "example"}, private_key, algorithm="RS256")
