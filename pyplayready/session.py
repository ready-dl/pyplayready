from typing import Optional

from Crypto.Random import get_random_bytes

from pyplayready.key import Key
from pyplayready.ecc_key import ECCKey
from pyplayready.xml_key import XmlKey


class Session:
    def __init__(self, number: int):
        self.number = number
        self.id = get_random_bytes(16)
        self.xml_key = XmlKey()
        self.signing_key: ECCKey = None
        self.encryption_key: ECCKey = None
        self.keys: list[Key] = []


__all__ = ("Session",)