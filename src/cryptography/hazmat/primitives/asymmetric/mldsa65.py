# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import abc

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import _serialization


class MLDSA65PublicKey(metaclass=abc.ABCMeta):
    @classmethod
    def from_public_bytes(cls, data: bytes) -> MLDSA65PublicKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mldsa65_supported():
            raise UnsupportedAlgorithm(
                "mlds65 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        return rust_openssl.mldsa65.from_public_bytes(data)

    @abc.abstractmethod
    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes:
        """
        The serialized bytes of the public key.
        """

    @abc.abstractmethod
    def public_bytes_raw(self) -> bytes:
        """
        The raw bytes of the public key.
        Equivalent to public_bytes(Raw, Raw).
        """

    @abc.abstractmethod
    def verify(self, signature: bytes, data: bytes) -> None:
        """
        Verify the signature.
        """

    @abc.abstractmethod
    def __eq__(self, other: object) -> bool:
        """
        Checks equality.
        """


MLDSA65PublicKey.register(rust_openssl.mldsa65.MLDSA65PublicKey)


class MLDSA65PrivateKey(metaclass=abc.ABCMeta):
    @classmethod
    def generate(cls) -> MLDSA65PrivateKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mldsa65_supported():
            raise UnsupportedAlgorithm(
                "mldsa65 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        return rust_openssl.mldsa65.generate_key()

    @classmethod
    def from_private_bytes(cls, data: bytes) -> MLDSA65PrivateKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mldsa65_supported():
            raise UnsupportedAlgorithm(
                "mldsa65 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        return rust_openssl.mldsa65.from_private_bytes(data)

    @abc.abstractmethod
    def public_key(self) -> MLDSA65PublicKey:
        """
        The MLDSA65PublicKey derived from the private key.
        """

    @abc.abstractmethod
    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        The serialized bytes of the private key.
        """

    @abc.abstractmethod
    def private_bytes_raw(self) -> bytes:
        """
        The raw bytes of the private key.
        Equivalent to private_bytes(Raw, Raw, NoEncryption()).
        """

    @abc.abstractmethod
    def sign(self, data: bytes) -> bytes:
        """
        Signs the data.
        """


MLDSA65PrivateKey.register(rust_openssl.mldsa65.MLDSA65PrivateKey)
