from __future__ import annotations
import collections.abc

# monkey patch for construct 2.8.8 compatibility
if not hasattr(collections, 'Sequence'):
    collections.Sequence = collections.abc.Sequence

import base64
from pathlib import Path
from typing import Union, Optional
from enum import IntEnum

from Crypto.PublicKey import ECC

from construct import Bytes, Const, Int32ub, GreedyRange, Switch, Container, ListContainer
from construct import Int16ub, Array
from construct import Struct, this

from pyplayready.crypto import Crypto
from pyplayready.exceptions import InvalidCertificateChain, InvalidCertificate
from pyplayready.crypto.ecc_key import ECCKey


class BCertCertType(IntEnum):
    UNKNOWN = 0x00000000
    PC = 0x00000001
    DEVICE = 0x00000002
    DOMAIN = 0x00000003
    ISSUER = 0x00000004
    CRL_SIGNER = 0x00000005
    SERVICE = 0x00000006
    SILVERLIGHT = 0x00000007
    APPLICATION = 0x00000008
    METERING = 0x00000009
    KEYFILESIGNER = 0x0000000a
    SERVER = 0x0000000b
    LICENSESIGNER = 0x0000000c
    SECURETIMESERVER = 0x0000000d
    RPROVMODELAUTH = 0x0000000e


class BCertObjType(IntEnum):
    BASIC = 0x0001
    DOMAIN = 0x0002
    PC = 0x0003
    DEVICE = 0x0004
    FEATURE = 0x0005
    KEY = 0x0006
    MANUFACTURER = 0x0007
    SIGNATURE = 0x0008
    SILVERLIGHT = 0x0009
    METERING = 0x000A
    EXTDATASIGNKEY = 0x000B
    EXTDATACONTAINER = 0x000C
    EXTDATASIGNATURE = 0x000D
    EXTDATA_HWID = 0x000E
    SERVER = 0x000F
    SECURITY_VERSION = 0x0010
    SECURITY_VERSION_2 = 0x0011
    UNKNOWN_OBJECT_ID = 0xFFFD


class BCertFlag(IntEnum):
    EMPTY = 0x00000000
    EXTDATA_PRESENT = 0x00000001


class BCertObjFlag(IntEnum):
    EMPTY = 0x0000
    MUST_UNDERSTAND = 0x0001
    CONTAINER_OBJ = 0x0002


class BCertSignatureType(IntEnum):
    P256 = 0x0001


class BCertKeyType(IntEnum):
    ECC256 = 0x0001


class BCertKeyUsage(IntEnum):
    UNKNOWN = 0x00000000
    SIGN = 0x00000001
    ENCRYPT_KEY = 0x00000002
    SIGN_CRL = 0x00000003
    ISSUER_ALL = 0x00000004
    ISSUER_INDIV = 0x00000005
    ISSUER_DEVICE = 0x00000006
    ISSUER_LINK = 0x00000007
    ISSUER_DOMAIN = 0x00000008
    ISSUER_SILVERLIGHT = 0x00000009
    ISSUER_APPLICATION = 0x0000000a
    ISSUER_CRL = 0x0000000b
    ISSUER_METERING = 0x0000000c
    ISSUER_SIGN_KEYFILE = 0x0000000d
    SIGN_KEYFILE = 0x0000000e
    ISSUER_SERVER = 0x0000000f
    ENCRYPTKEY_SAMPLE_PROTECTION_RC4 = 0x00000010
    RESERVED2 = 0x00000011
    ISSUER_SIGN_LICENSE = 0x00000012
    SIGN_LICENSE = 0x00000013
    SIGN_RESPONSE = 0x00000014
    PRND_ENCRYPT_KEY_DEPRECATED = 0x00000015
    ENCRYPTKEY_SAMPLE_PROTECTION_AES128CTR = 0x00000016
    ISSUER_SECURETIMESERVER = 0x00000017
    ISSUER_RPROVMODELAUTH = 0x00000018


class BCertFeatures(IntEnum):
    TRANSMITTER = 0x00000001
    RECEIVER = 0x00000002
    SHARED_CERTIFICATE = 0x00000003
    SECURE_CLOCK = 0x00000004
    ANTIROLLBACK_CLOCK = 0x00000005
    RESERVED_METERING = 0x00000006
    RESERVED_LICSYNC = 0x00000007
    RESERVED_SYMOPT = 0x00000008
    SUPPORTS_CRLS = 0x00000009
    SERVER_BASIC_EDITION = 0x0000000A
    SERVER_STANDARD_EDITION = 0x0000000B
    SERVER_PREMIUM_EDITION = 0x0000000C
    SUPPORTS_PR3_FEATURES = 0x0000000D
    DEPRECATED_SECURE_STOP = 0x0000000E


class _BCertStructs:
    BasicInfo = Struct(
        "cert_id" / Bytes(16),
        "security_level" / Int32ub,
        "flags" / Int32ub,
        "cert_type" / Int32ub,
        "public_key_digest" / Bytes(32),
        "expiration_date" / Int32ub,
        "client_id" / Bytes(16)
    )

    # TODO: untested
    DomainInfo = Struct(
        "service_id" / Bytes(16),
        "account_id" / Bytes(16),
        "revision_timestamp" / Int32ub,
        "domain_url_length" / Int32ub,
        "domain_url" / Bytes((this.domain_url_length + 3) & 0xfffffffc)
    )

    # TODO: untested
    PCInfo = Struct(
        "security_version" / Int32ub
    )

    DeviceInfo = Struct(
        "max_license" / Int32ub,
        "max_header" / Int32ub,
        "max_chain_depth" / Int32ub
    )

    FeatureInfo = Struct(
        "feature_count" / Int32ub,  # max. 32
        "features" / Array(this.feature_count, Int32ub)
    )

    KeyInfo = Struct(
        "key_count" / Int32ub,
        "cert_keys" / Array(this.key_count, Struct(
            "type" / Int16ub,
            "length" / Int16ub,
            "flags" / Int32ub,
            "key" / Bytes(this.length // 8),
            "usages_count" / Int32ub,
            "usages" / Array(this.usages_count, Int32ub)
        ))
    )

    ManufacturerInfo = Struct(
        "flags" / Int32ub,
        "manufacturer_name_length" / Int32ub,
        "manufacturer_name" / Bytes((this.manufacturer_name_length + 3) & 0xfffffffc),
        "model_name_length" / Int32ub,
        "model_name" / Bytes((this.model_name_length + 3) & 0xfffffffc),
        "model_number_length" / Int32ub,
        "model_number" / Bytes((this.model_number_length + 3) & 0xfffffffc),
    )

    SignatureInfo = Struct(
        "signature_type" / Int16ub,
        "signature_size" / Int16ub,
        "signature" / Bytes(this.signature_size),
        "signature_key_size" / Int32ub,
        "signature_key" / Bytes(this.signature_key_size // 8)
    )

    # TODO: untested
    SilverlightInfo = Struct(
        "security_version" / Int32ub,
        "platform_identifier" / Int32ub
    )

    # TODO: untested
    MeteringInfo = Struct(
        "metering_id" / Bytes(16),
        "metering_url_length" / Int32ub,
        "metering_url" / Bytes((this.metering_url_length + 3) & 0xfffffffc)
    )

    ExtDataSignKeyInfo = Struct(
        "key_type" / Int16ub,
        "key_length" / Int16ub,
        "flags" / Int32ub,
        "key" / Bytes(this.key_length // 8)
    )

    # TODO: untested
    DataRecord = Struct(
        "data_size" / Int32ub,
        "data" / Bytes(this.data_size)
    )

    ExtDataSignature = Struct(
        "signature_type" / Int16ub,
        "signature_size" / Int16ub,
        "signature" / Bytes(this.signature_size)
    )

    ExtDataContainer = Struct(
        "record_count" / Int32ub,  # always 1
        "records" / Array(this.record_count, DataRecord),
        "signature" / ExtDataSignature
    )

    # TODO: untested
    ServerInfo = Struct(
        "warning_days" / Int32ub
    )

    # TODO: untested
    SecurityVersion = Struct(
        "security_version" / Int32ub,
        "platform_identifier" / Int32ub
    )

    Attribute = Struct(
        "flags" / Int16ub,
        "tag" / Int16ub,
        "length" / Int32ub,
        "attribute" / Switch(
            lambda this_: this_.tag,
            {
                BCertObjType.BASIC: BasicInfo,
                BCertObjType.DOMAIN: DomainInfo,
                BCertObjType.PC: PCInfo,
                BCertObjType.DEVICE: DeviceInfo,
                BCertObjType.FEATURE: FeatureInfo,
                BCertObjType.KEY: KeyInfo,
                BCertObjType.MANUFACTURER: ManufacturerInfo,
                BCertObjType.SIGNATURE: SignatureInfo,
                BCertObjType.SILVERLIGHT: SilverlightInfo,
                BCertObjType.METERING: MeteringInfo,
                BCertObjType.EXTDATASIGNKEY: ExtDataSignKeyInfo,
                BCertObjType.EXTDATACONTAINER: ExtDataContainer,
                BCertObjType.EXTDATASIGNATURE: ExtDataSignature,
                BCertObjType.EXTDATA_HWID: Bytes(this.length - 8),
                BCertObjType.SERVER: ServerInfo,
                BCertObjType.SECURITY_VERSION: SecurityVersion,
                BCertObjType.SECURITY_VERSION_2: SecurityVersion
            },
            default=Bytes(this.length - 8)
        )
    )

    BCert = Struct(
        "signature" / Const(b"CERT"),
        "version" / Int32ub,
        "total_length" / Int32ub,
        "certificate_length" / Int32ub,
        "attributes" / GreedyRange(Attribute)
    )

    BCertChain = Struct(
        "signature" / Const(b"CHAI"),
        "version" / Int32ub,
        "total_length" / Int32ub,
        "flags" / Int32ub,
        "certificate_count" / Int32ub,
        "certificates" / GreedyRange(BCert)
    )


class Certificate(_BCertStructs):
    """Represents a BCert"""

    def __init__(
            self,
            parsed_bcert: Container,
            bcert_obj: _BCertStructs.BCert = _BCertStructs.BCert
    ):
        self.parsed = parsed_bcert
        self._BCERT = bcert_obj

    @classmethod
    def new_leaf_cert(
            cls,
            cert_id: bytes,
            security_level: int,
            client_id: bytes,
            signing_key: ECCKey,
            encryption_key: ECCKey,
            group_key: ECCKey,
            parent: CertificateChain,
            expiry: int = 0xFFFFFFFF
    ) -> Certificate:
        basic_info = Container(
            cert_id=cert_id,
            security_level=security_level,
            flags=BCertFlag.EMPTY,
            cert_type=BCertCertType.DEVICE,
            public_key_digest=signing_key.public_sha256_digest(),
            expiration_date=expiry,
            client_id=client_id
        )
        basic_info_attribute = Container(
            flags=BCertObjFlag.MUST_UNDERSTAND,
            tag=BCertObjType.BASIC,
            length=len(_BCertStructs.BasicInfo.build(basic_info)) + 8,
            attribute=basic_info
        )

        device_info = Container(
            max_license=10240,
            max_header=15360,
            max_chain_depth=2
        )
        device_info_attribute = Container(
            flags=BCertObjFlag.MUST_UNDERSTAND,
            tag=BCertObjType.DEVICE,
            length=len(_BCertStructs.DeviceInfo.build(device_info)) + 8,
            attribute=device_info
        )

        feature = Container(
            feature_count=3,
            features=ListContainer([
                BCertFeatures.SECURE_CLOCK,
                BCertFeatures.SUPPORTS_CRLS,
                BCertFeatures.SUPPORTS_PR3_FEATURES
            ])
        )
        feature_attribute = Container(
            flags=BCertObjFlag.MUST_UNDERSTAND,
            tag=BCertObjType.FEATURE,
            length=len(_BCertStructs.FeatureInfo.build(feature)) + 8,
            attribute=feature
        )

        signing_key_public_bytes = signing_key.public_bytes()
        cert_key_sign = Container(
            type=BCertKeyType.ECC256,
            length=len(signing_key_public_bytes) * 8,  # bits
            flags=BCertFlag.EMPTY,
            key=signing_key_public_bytes,
            usages_count=1,
            usages=ListContainer([
                BCertKeyUsage.SIGN
            ])
        )

        encryption_key_public_bytes = encryption_key.public_bytes()
        cert_key_encrypt = Container(
            type=BCertKeyType.ECC256,
            length=len(encryption_key_public_bytes) * 8,  # bits
            flags=BCertFlag.EMPTY,
            key=encryption_key_public_bytes,
            usages_count=1,
            usages=ListContainer([
                BCertKeyUsage.ENCRYPT_KEY
            ])
        )

        key_info = Container(
            key_count=2,
            cert_keys=ListContainer([
                cert_key_sign,
                cert_key_encrypt
            ])
        )
        key_info_attribute = Container(
            flags=BCertObjFlag.MUST_UNDERSTAND,
            tag=BCertObjType.KEY,
            length=len(_BCertStructs.KeyInfo.build(key_info)) + 8,
            attribute=key_info
        )

        manufacturer_info = parent.get(0).get_attribute(BCertObjType.MANUFACTURER)

        new_bcert_container = Container(
            signature=b"CERT",
            version=1,
            total_length=0,  # filled at a later time
            certificate_length=0,  # filled at a later time
            attributes=ListContainer([
                basic_info_attribute,
                device_info_attribute,
                feature_attribute,
                key_info_attribute,
                manufacturer_info,
            ])
        )

        payload = _BCertStructs.BCert.build(new_bcert_container)
        new_bcert_container.certificate_length = len(payload)
        new_bcert_container.total_length = len(payload) + 144  # signature length

        sign_payload = _BCertStructs.BCert.build(new_bcert_container)
        signature = Crypto.ecc256_sign(group_key, sign_payload)

        group_key_public_bytes = group_key.public_bytes()

        signature_info = Container(
            signature_type=BCertSignatureType.P256,
            signature_size=len(signature),
            signature=signature,
            signature_key_size=len(group_key_public_bytes) * 8,  # bits
            signature_key=group_key_public_bytes
        )
        signature_info_attribute = Container(
            flags=BCertObjFlag.MUST_UNDERSTAND,
            tag=BCertObjType.SIGNATURE,
            length=len(_BCertStructs.SignatureInfo.build(signature_info)) + 8,
            attribute=signature_info
        )
        new_bcert_container.attributes.append(signature_info_attribute)

        return cls(new_bcert_container)

    @classmethod
    def loads(cls, data: Union[str, bytes]) -> Certificate:
        if isinstance(data, str):
            data = base64.b64decode(data)
        if not isinstance(data, bytes):
            raise ValueError(f"Expecting Bytes or Base64 input, got {data!r}")

        cert = _BCertStructs.BCert
        return cls(
            parsed_bcert=cert.parse(data),
            bcert_obj=cert
        )

    def get_attribute(self, type_: int):
        for attribute in self.parsed.attributes:
            if attribute.tag == type_:
                return attribute

    def get_security_level(self) -> int:
        basic_info_attribute = self.get_attribute(BCertObjType.BASIC).attribute
        if basic_info_attribute:
            return basic_info_attribute.security_level

    @staticmethod
    def _unpad(name: bytes):
        return name.rstrip(b'\x00').decode("utf-8", errors="ignore")

    def get_name(self):
        manufacturer_info = self.get_attribute(BCertObjType.MANUFACTURER).attribute
        if manufacturer_info:
            return f"{self._unpad(manufacturer_info.manufacturer_name)} {self._unpad(manufacturer_info.model_name)} {self._unpad(manufacturer_info.model_number)}"

    def get_issuer_key(self) -> Optional[bytes]:
        key_info_object = self.get_attribute(BCertObjType.KEY)
        if not key_info_object:
            return

        key_info_attribute = key_info_object.attribute
        return next(map(lambda key: key.key, filter(lambda key: 6 in key.usages, key_info_attribute.cert_keys)), None)

    def dumps(self) -> bytes:
        return self._BCERT.build(self.parsed)

    def verify(self, public_key: bytes, index: int):
        signature_object = self.get_attribute(BCertObjType.SIGNATURE)
        if not signature_object:
            raise InvalidCertificate(f"No signature object found in certificate {index}")

        signature_attribute = signature_object.attribute

        raw_signature_key = signature_attribute.signature_key
        if public_key != raw_signature_key:
            raise InvalidCertificate(f"Signature keys of certificate {index} do not match")

        signature_key = ECC.construct(
            curve='P-256',
            point_x=int.from_bytes(raw_signature_key[:32], 'big'),
            point_y=int.from_bytes(raw_signature_key[32:], 'big')
        )

        sign_payload = self.dumps()[:-signature_object.length]

        if not Crypto.ecc256_verify(
            public_key=signature_key,
            data=sign_payload,
            signature=signature_attribute.signature
        ):
            raise InvalidCertificate(f"Signature of certificate {index} is not authentic")

        return self.get_issuer_key()


class CertificateChain(_BCertStructs):
    """Represents a BCertChain"""

    ECC256MSBCertRootIssuerPubKey = bytes.fromhex("864d61cff2256e422c568b3c28001cfb3e1527658584ba0521b79b1828d936de1d826a8fc3e6e7fa7a90d5ca2946f1f64a2efb9f5dcffe7e434eb44293fac5ab")

    def __init__(
            self,
            parsed_bcert_chain: Container,
            bcert_chain_obj: _BCertStructs.BCertChain = _BCertStructs.BCertChain
    ):
        self.parsed = parsed_bcert_chain
        self._BCERT_CHAIN = bcert_chain_obj

    @classmethod
    def loads(cls, data: Union[str, bytes]) -> CertificateChain:
        if isinstance(data, str):
            data = base64.b64decode(data)
        if not isinstance(data, bytes):
            raise ValueError(f"Expecting Bytes or Base64 input, got {data!r}")

        cert_chain = _BCertStructs.BCertChain
        return cls(
            parsed_bcert_chain=cert_chain.parse(data),
            bcert_chain_obj=cert_chain
        )

    @classmethod
    def load(cls, path: Union[Path, str]) -> CertificateChain:
        if not isinstance(path, (Path, str)):
            raise ValueError(f"Expecting Path object or path string, got {path!r}")
        with Path(path).open(mode="rb") as f:
            return cls.loads(f.read())

    def dumps(self) -> bytes:
        return self._BCERT_CHAIN.build(self.parsed)

    def get_security_level(self) -> int:
        # not sure if there's a better way than this
        return self.get(0).get_security_level()

    def get_name(self) -> str:
        return self.get(0).get_name()

    def verify(self) -> bool:
        issuer_key = self.ECC256MSBCertRootIssuerPubKey

        try:
            for i in reversed(range(self.count())):
                certificate = self.get(i)
                issuer_key = certificate.verify(issuer_key, i)

                if not issuer_key and i != 0:
                    raise InvalidCertificate(f"Certificate {i} is not valid")
        except InvalidCertificate as e:
            raise InvalidCertificateChain(e)

        return True

    def append(self, bcert: Certificate) -> None:
        self.parsed.certificate_count += 1
        self.parsed.certificates.append(bcert.parsed)
        self.parsed.total_length += len(bcert.dumps())

    def prepend(self, bcert: Certificate) -> None:
        self.parsed.certificate_count += 1
        self.parsed.certificates.insert(0, bcert.parsed)
        self.parsed.total_length += len(bcert.dumps())

    def remove(self, index: int) -> None:
        if self.count() <= 0:
            raise InvalidCertificateChain("CertificateChain does not contain any Certificates")
        if index >= self.count():
            raise IndexError(f"No Certificate at index {index}, {self.count()} total")

        self.parsed.certificate_count -= 1
        self.parsed.total_length -= len(self.get(index).dumps())
        self.parsed.certificates.pop(index)

    def get(self, index: int) -> Certificate:
        if self.count() <= 0:
            raise InvalidCertificateChain("CertificateChain does not contain any Certificates")
        if index >= self.count():
            raise IndexError(f"No Certificate at index {index}, {self.count()} total")

        return Certificate(self.parsed.certificates[index])

    def count(self) -> int:
        return self.parsed.certificate_count
