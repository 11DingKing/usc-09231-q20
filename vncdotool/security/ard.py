"""Apple Remote Desktop authentication: Diffie-Hellman, security type 30."""
from __future__ import annotations

import os
import warnings
from struct import unpack
from typing import Any, Generator

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.utils import CryptographyDeprecationWarning

from ..const import AuthTypes
from .base import SecurityError, SecurityHandler, security_result

# Each credential is sent in a fixed 64-byte field: UTF-8 bytes, a NUL
# terminator, and random padding so the ciphertext leaks nothing about
# how long the credential is.
_FIELD_SIZE = 64


def _field(value: str, name: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) + 1 > _FIELD_SIZE:
        raise SecurityError(
            f"{name} does not fit in {_FIELD_SIZE} bytes with its terminator"
        )
    return encoded + b"\0" + os.urandom(_FIELD_SIZE - len(encoded) - 1)


class DiffieHellmanSecurity(SecurityHandler):
    """DH key exchange, then the credentials AES-encrypted with MD5(shared).

    The algorithms are what Apple Remote Desktop speaks; like the DES use
    in VNC authentication, stronger ones would simply not interoperate.
    """

    SECURITY_TYPE = AuthTypes.DIFFIE_HELLMAN

    def handle(self, client: Any) -> Generator[int, bytes, bool]:
        (generator, key_len) = unpack("!HH", (yield 4))
        prime = int.from_bytes((yield key_len), "big")
        server_public = int.from_bytes((yield key_len), "big")

        client.ardRequestCredentials()
        username = _field(client.factory.username, "username")
        password = _field(client.factory.password, "password")

        # DH here is legacy but protocol-mandated, so the deprecation
        # warnings from cryptography are expected and not actionable.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            numbers = dh.DHParameterNumbers(p=prime, g=generator)
            private = numbers.parameters().generate_private_key()
            peer = dh.DHPublicNumbers(server_public, numbers).public_key()
            shared = private.exchange(peer)

        digest = hashes.Hash(hashes.MD5())
        digest.update(shared)
        encryptor = Cipher(algorithms.AES(digest.finalize()), modes.ECB()).encryptor()
        ciphertext = encryptor.update(username + password) + encryptor.finalize()

        client_public = private.public_key().public_numbers().y.to_bytes(key_len, "big")
        client.transport.write(ciphertext + client_public)
        return (yield from security_result(client))
