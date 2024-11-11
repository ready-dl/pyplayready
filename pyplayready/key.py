from enum import Enum
from uuid import UUID


class Key:
    class KeyType(Enum):
        Invalid = 0x0000
        AES128CTR = 0x0001
        RC4 = 0x0002
        AES128ECB = 0x0003
        Cocktail = 0x0004
        UNKNOWN = 0xffff

        @classmethod
        def _missing_(cls, value):
            return cls.UNKNOWN

    class CipherType(Enum):
        Invalid = 0x0000
        RSA128 = 0x0001
        ChainedLicense = 0x0002
        ECC256 = 0x0003
        ECCforScalableLicenses = 4
        UNKNOWN = 0xffff

        @classmethod
        def _missing_(cls, value):
            return cls.UNKNOWN

    def __init__(
            self,
            key_id: UUID,
            key_type: int,
            cipher_type: int,
            key_length: int,
            key: bytes
    ):
        self.key_id = key_id
        self.key_type = self.KeyType(key_type)
        self.cipher_type = self.CipherType(cipher_type)
        self.key_length = key_length
        self.key = key
