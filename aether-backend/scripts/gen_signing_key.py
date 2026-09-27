"""
Generate an Ed25519 keypair for Project AETHER custody chain signing.

Usage:
    python scripts/gen_signing_key.py

Outputs base64-encoded strings for:
    AETHER_SIGNING_KEY (private key)
    AETHER_SIGNING_PUBLIC_KEY (public key)
"""
import base64
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_keypair() -> tuple[str, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    priv_b64 = base64.b64encode(priv_bytes).decode("ascii")
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    return priv_b64, pub_b64


def main() -> None:
    priv_b64, pub_b64 = generate_keypair()
    print("=== AETHER Ed25519 Custody Signing Keypair ===")
    print(f"AETHER_SIGNING_KEY={priv_b64}")
    print(f"AETHER_SIGNING_PUBLIC_KEY={pub_b64}")
    print("\nCopy the above lines into your .env file to enable hardware/Ed25519 custody chain signing.")


if __name__ == "__main__":
    main()
