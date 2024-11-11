from __future__ import annotations

import base64
from pathlib import Path
from typing import Union

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from ecpy.curves import Curve, Point


class ECCKey:
    def __init__(
            self,
            key: EccKey
    ):
        """Represents a PlayReady ECC key"""
        self.key = key

    @classmethod
    def generate(cls):
        return cls(key=ECC.generate(curve='P-256'))

    @classmethod
    def construct(
            cls,
            private_key: Union[bytes, int],
            public_key_x: Union[bytes, int],
            public_key_y: Union[bytes, int]
    ):
        if isinstance(private_key, bytes):
            private_key = int.from_bytes(private_key, 'big')
        if not isinstance(private_key, int):
            raise ValueError(f"Expecting Bytes or Int input, got {private_key!r}")

        if isinstance(public_key_x, bytes):
            public_key_x = int.from_bytes(public_key_x, 'big')
        if not isinstance(public_key_x, int):
            raise ValueError(f"Expecting Bytes or Int input, got {public_key_x!r}")

        if isinstance(public_key_y, bytes):
            public_key_y = int.from_bytes(public_key_y, 'big')
        if not isinstance(public_key_y, int):
            raise ValueError(f"Expecting Bytes or Int input, got {public_key_y!r}")

        # The public is always derived from the private key; loading the other stuff won't work
        key = ECC.construct(
            curve='P-256',
            d=private_key,
        )

        return cls(key=key)

    @classmethod
    def loads(cls, data: Union[str, bytes]) -> ECCKey:
        if isinstance(data, str):
            data = base64.b64decode(data)
        if not isinstance(data, bytes):
            raise ValueError(f"Expecting Bytes or Base64 input, got {data!r}")

        if len(data) not in [96, 32]:
            raise ValueError(f"Invalid data length. Expecting 96 or 32 bytes, got {len(data)}")

        return cls.construct(
            private_key=data[:32],
            public_key_x=data[32:64],
            public_key_y=data[64:96]
        )

    @classmethod
    def load(cls, path: Union[Path, str]) -> ECCKey:
        if not isinstance(path, (Path, str)):
            raise ValueError(f"Expecting Path object or path string, got {path!r}")
        with Path(path).open(mode="rb") as f:
            return cls.loads(f.read())

    def dumps(self):
        return self.private_bytes() + self.public_bytes()

    def dump(self, path: Union[Path, str]) -> None:
        if not isinstance(path, (Path, str)):
            raise ValueError(f"Expecting Path object or path string, got {path!r}")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.dumps())

    def get_point(self, curve: Curve) -> Point:
        return Point(self.key.pointQ.x, self.key.pointQ.y, curve)

    def private_bytes(self) -> bytes:
        return self.key.d.to_bytes()

    def private_sha256_digest(self) -> bytes:
        hash_object = SHA256.new()
        hash_object.update(self.private_bytes())
        return hash_object.digest()

    def public_bytes(self) -> bytes:
        return self.key.pointQ.x.to_bytes() + self.key.pointQ.y.to_bytes()

    def public_sha256_digest(self) -> bytes:
        hash_object = SHA256.new()
        hash_object.update(self.public_bytes())
        return hash_object.digest()
