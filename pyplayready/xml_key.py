from ecpy.curves import Point, Curve

from pyplayready.ecc_key import ECCKey
from pyplayready.elgamal import ElGamal


class XmlKey:
    def __init__(self):
        self._shared_point = ECCKey.generate()
        self.shared_key_x = self._shared_point.key.pointQ.x
        self.shared_key_y = self._shared_point.key.pointQ.y

        self._shared_key_x_bytes = ElGamal.to_bytes(int(self.shared_key_x))
        self.aes_iv = self._shared_key_x_bytes[:16]
        self.aes_key = self._shared_key_x_bytes[16:]

    def get_point(self, curve: Curve) -> Point:
        return Point(self.shared_key_x, self.shared_key_y, curve)
