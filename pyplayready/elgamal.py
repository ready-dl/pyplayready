from typing import Tuple

from ecpy.curves import Curve, Point
import secrets


class ElGamal:
    def __init__(self, curve: Curve):
        self.curve = curve

    @staticmethod
    def to_bytes(n: int) -> bytes:
        byte_len = (n.bit_length() + 7) // 8
        if byte_len % 2 != 0:
            byte_len += 1
        return n.to_bytes(byte_len, 'big')

    def encrypt(
            self,
            message_point: Point,
            public_key: Point
    ) -> Tuple[Point, Point]:
        ephemeral_key = secrets.randbelow(self.curve.order)
        point1 = ephemeral_key * self.curve.generator
        point2 = message_point + (ephemeral_key * public_key)
        return point1, point2

    @staticmethod
    def decrypt(
            encrypted: Tuple[Point, Point],
            private_key: int
    ) -> Point:
        point1, point2 = encrypted
        shared_secret = private_key * point1
        decrypted_message = point2 - shared_secret
        return decrypted_message
