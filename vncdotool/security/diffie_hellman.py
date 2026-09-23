"""Apple Remote Desktop Diffie-Hellman security type (30)."""
from __future__ import annotations

import os
from struct import unpack
from typing import Any, Generator

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from typing import Any, Generator

from ..const import AuthTypes
from .base import SecurityError, SecurityHandler, security_result

# Each credential occupies a 64-byte field NUL terminated, so at most 63
# bytes of value fit.
FIELD_SIZE = 64


class DiffieHellmanHandler(SecurityHandler):
    SECURITY_TYPE = AuthTypes.DIFFIE_HELLMAN

    def handle(self, client: Any) -> Generator[int, bytes, bool]:
        generator, key_len = unpack("!HH", (yield 2))
        modulus = yield key_len
        server_key_bytes = yield key_len

        client.ardRequestCredentials()
        self._encrypt(client, generator, modulus, server_key_bytes, key_len)
        return (yield from security_result(client))

    def _encrypt(
        self,
        client: Any,
        generator: int,
        modulus: bytes,
        server_key_bytes: bytes,
        key_len: int,
    ) -> None:
        username = client.factory.username
        password = client.factory.password
        fields = []
        for field, value in (("username", username), ("password", password)):
            encoded = value.encode("utf-8")
            if len(encoded) >= FIELD_SIZE:
                raise SecurityError(
                    f"{field} does not fit in the {FIELD_SIZE - 1} byte field"
                )
            # NUL terminate, then randomise the rest of the field so the
            # ciphertext leaks nothing about credentials across exchanges.
            fields.append(encoded + b"\0" + os.urandom(FIELD_SIZE - len(encoded) - 1))
        user_bytes = b"".join(fields)

        p = int.from_bytes(modulus, "big")
        sk = int.from_bytes(server_key_bytes, "big")
        param_numbers = dh.DHParameterNumbers(p=p, g=generator)
        server_public = dh.DHPublicNumbers(sk, param_numbers).public_key()

        private_key = param_numbers.parameters().generate_private_key()
        shared = private_key.exchange(server_public)

        digest = hashes.Hash(hashes.MD5())
        digest.update(shared)
        encryptor = Cipher(
            algorithms.AES(digest.finalize()), modes.ECB()
        ).encryptor()
        ciphertext = encryptor.update(user_bytes)
        ciphertext += encryptor.finalize()

        client_public = private_key.public_key().public_numbers().y.to_bytes(
            key_len, "big"
        )
        client.transport.write(ciphertext + client_public)
