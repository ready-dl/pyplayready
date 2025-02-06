from __future__ import annotations

import base64
import time
from typing import List, Union, Optional
from uuid import UUID
import xml.etree.ElementTree as ET

import xmltodict
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor

from ecpy.curves import Point, Curve

from pyplayready.crypto import Crypto
from pyplayready.drmresults import DRMResult
from pyplayready.system.bcert import CertificateChain
from pyplayready.crypto.ecc_key import ECCKey
from pyplayready.license.key import Key
from pyplayready.license.xmrlicense import XMRLicense, XMRObjectTypes
from pyplayready.exceptions import (InvalidSession, TooManySessions, InvalidLicense, ServerException)
from pyplayready.system.session import Session
from pyplayready.system.wrmheader import WRMHeader


class Cdm:
    MAX_NUM_OF_SESSIONS = 16

    rgbMagicConstantZero = bytes.fromhex("7ee9ed4af773224f00b8ea7efb027cbb")

    def __init__(
            self,
            security_level: int,
            certificate_chain: Optional[CertificateChain],
            encryption_key: Optional[ECCKey],
            signing_key: Optional[ECCKey],
            client_version: str = "10.0.16384.10011",
    ):
        self.security_level = security_level
        self.certificate_chain = certificate_chain
        self.encryption_key = encryption_key
        self.signing_key = signing_key
        self.client_version = client_version

        self.__crypto = Crypto()
        self._wmrm_key = Point(
            x=0xc8b6af16ee941aadaa5389b4af2c10e356be42af175ef3face93254e7b0b3d9b,
            y=0x982b27b5cb2341326e56aa857dbfd5c634ce2cf9ea74fca8f2af5957efeea562,
            curve=Curve.get_curve("secp256r1")
        )

        self.__sessions: dict[bytes, Session] = {}

    @classmethod
    def from_device(cls, device) -> Cdm:
        """Initialize a Playready CDM from a Playready Device (.prd) file"""
        return cls(
            security_level=device.security_level,
            certificate_chain=device.group_certificate,
            encryption_key=device.encryption_key,
            signing_key=device.signing_key
        )

    def open(self) -> bytes:
        """Open a Playready Content Decryption Module (CDM) session"""
        if len(self.__sessions) > self.MAX_NUM_OF_SESSIONS:
            raise TooManySessions(f"Too many Sessions open ({self.MAX_NUM_OF_SESSIONS}).")

        session = Session(len(self.__sessions) + 1)
        self.__sessions[session.id] = session

        return session.id

    def close(self, session_id: bytes) -> None:
        """Close a Playready Content Decryption Module (CDM) session """
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id.hex()} is invalid.")
        del self.__sessions[session_id]

    def _get_key_data(self, session: Session) -> bytes:
        return self.__crypto.ecc256_encrypt(
            public_key=self._wmrm_key,
            plaintext=session.xml_key.get_point()
        )

    def _get_cipher_data(self, session: Session) -> bytes:
        b64_chain = base64.b64encode(self.certificate_chain.dumps()).decode()
        body = xmltodict.unparse({
            'Data': {
                'CertificateChains': {
                    'CertificateChain': b64_chain
                },
                'Features': {
                    'Feature': {
                        '@Name': 'AESCBC',
                        '#text': '""'
                    },
                    'REE': {
                        'AESCBCS': None
                    }
                }
            }
        }, full_document=False)

        cipher = AES.new(
            key=session.xml_key.aes_key,
            mode=AES.MODE_CBC,
            iv=session.xml_key.aes_iv
        )

        ciphertext = cipher.encrypt(pad(
            body.encode(),
            AES.block_size
        ))

        return session.xml_key.aes_iv + ciphertext

    @staticmethod
    def _build_main_body(la_content: dict, signed_info: dict, signature: str, public_signing_key: str) -> dict:
        return {
            'soap:Envelope': {
                '@xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
                '@xmlns:xsd': 'http://www.w3.org/2001/XMLSchema',
                '@xmlns:soap': 'http://schemas.xmlsoap.org/soap/envelope/',
                'soap:Body': {
                    'AcquireLicense': {
                        '@xmlns': 'http://schemas.microsoft.com/DRM/2007/03/protocols',
                        'challenge': {
                            'Challenge': {
                                '@xmlns': 'http://schemas.microsoft.com/DRM/2007/03/protocols/messages',
                                'LA': la_content["LA"],
                                'Signature': {
                                    'SignedInfo': signed_info["SignedInfo"],
                                    '@xmlns': 'http://www.w3.org/2000/09/xmldsig#',
                                    'SignatureValue': signature,
                                    'KeyInfo': {
                                        '@xmlns': 'http://www.w3.org/2000/09/xmldsig#',
                                        'KeyValue': {
                                            'ECCKeyValue': {
                                                'PublicKey': public_signing_key
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

    def _build_digest_content(
            self,
            wrm_header: str,
            nonce: str,
            wmrm_cipher: str,
            cert_cipher: str,
            protocol_version: int
    ) -> dict:
        return {
            'LA': {
                '@xmlns': 'http://schemas.microsoft.com/DRM/2007/03/protocols',
                '@Id': 'SignedData',
                '@xml:space': 'preserve',
                'Version': protocol_version,
                'ContentHeader': xmltodict.parse(wrm_header),
                'CLIENTINFO': {
                    'CLIENTVERSION': self.client_version
                },
                'LicenseNonce': nonce,
                'ClientTime': int(time.time()),
                'EncryptedData': {
                    '@xmlns': 'http://www.w3.org/2001/04/xmlenc#',
                    '@Type': 'http://www.w3.org/2001/04/xmlenc#Element',
                    'EncryptionMethod': {
                        '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
                    },
                    'KeyInfo': {
                        '@xmlns': 'http://www.w3.org/2000/09/xmldsig#',
                        'EncryptedKey': {
                            '@xmlns': 'http://www.w3.org/2001/04/xmlenc#',
                            'EncryptionMethod': {
                                '@Algorithm': 'http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256'
                            },
                            'KeyInfo': {
                                '@xmlns': 'http://www.w3.org/2000/09/xmldsig#',
                                'KeyName': 'WMRMServer'
                            },
                            'CipherData': {
                                'CipherValue': wmrm_cipher
                            }
                        }
                    },
                    'CipherData': {
                        'CipherValue': cert_cipher
                    }
                }
            }
        }

    @staticmethod
    def _build_signed_info(digest_value: str) -> dict:
        return {
            'SignedInfo': {
                '@xmlns': 'http://www.w3.org/2000/09/xmldsig#',
                'CanonicalizationMethod': {
                    '@Algorithm': 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
                },
                'SignatureMethod': {
                    '@Algorithm': 'http://schemas.microsoft.com/DRM/2007/03/protocols#ecdsa-sha256'
                },
                'Reference': {
                    '@URI': '#SignedData',
                    'DigestMethod': {
                        '@Algorithm': 'http://schemas.microsoft.com/DRM/2007/03/protocols#sha256'
                    },
                    'DigestValue': digest_value
                }
            }
        }

    def get_license_challenge(self, session_id: bytes, wrm_header: Union[WRMHeader, str]) -> str:
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id.hex()} is invalid.")

        if isinstance(wrm_header, str):
            wrm_header = WRMHeader(wrm_header)
        if not isinstance(wrm_header, WRMHeader):
            raise ValueError(f"Expected WRMHeader to be a {str} or {WRMHeader} not {wrm_header!r}")

        match wrm_header.version:
            case WRMHeader.Version.VERSION_4_3_0_0:
                protocol_version = 5
            case WRMHeader.Version.VERSION_4_2_0_0:
                protocol_version = 4
            case _:
                protocol_version = 1

        session.signing_key = self.signing_key
        session.encryption_key = self.encryption_key

        la_content = self._build_digest_content(
            wrm_header=wrm_header.dumps(),
            nonce=base64.b64encode(get_random_bytes(16)).decode(),
            wmrm_cipher=base64.b64encode(self._get_key_data(session)).decode(),
            cert_cipher=base64.b64encode(self._get_cipher_data(session)).decode(),
            protocol_version=protocol_version
        )
        la_content_xml = xmltodict.unparse(la_content, full_document=False)

        la_hash_obj = SHA256.new()
        la_hash_obj.update(la_content_xml.encode())
        la_hash = la_hash_obj.digest()

        signed_info = self._build_signed_info(base64.b64encode(la_hash).decode())
        signed_info_xml = xmltodict.unparse(signed_info, full_document=False)

        signature = self.__crypto.ecc256_sign(session.signing_key, signed_info_xml.encode())
        b64_signature = base64.b64encode(signature).decode()

        b64_public_singing_key = base64.b64encode(session.signing_key.public_bytes()).decode()

        return xmltodict.unparse(self._build_main_body(la_content, signed_info, b64_signature, b64_public_singing_key)).replace('\n', '')

    @staticmethod
    def _verify_encryption_key(session: Session, licence: XMRLicense) -> bool:
        ecc_keys = list(licence.get_object(XMRObjectTypes.ECC_DEVICE_KEY_OBJECT))
        if not ecc_keys:
            raise InvalidLicense("No ECC public key in license")

        return ecc_keys[0].key == session.encryption_key.public_bytes()

    def parse_license(self, session_id: bytes, licence: str) -> None:
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id.hex()} is invalid.")

        if not licence:
            raise InvalidLicense("Cannot parse an empty licence message")
        if not isinstance(licence, str):
            raise InvalidLicense(f"Expected licence message to be a {str}, not {licence!r}")
        if not session.encryption_key or not session.signing_key:
            raise InvalidSession("Cannot parse a license message without first making a license request")

        try:
            root = ET.fromstring(licence)
            faults = root.findall(".//{http://schemas.xmlsoap.org/soap/envelope/}Fault")

            for fault in faults:
                status_codes = fault.findall(".//StatusCode")
                for status_code in status_codes:
                    code = DRMResult.from_code(status_code.text)
                    raise ServerException(f"[{status_code.text}] ({code.name}) {code.message}")

            license_elements = root.findall(".//{http://schemas.microsoft.com/DRM/2007/03/protocols}License")

            for license_element in license_elements:
                parsed_licence = XMRLicense.loads(license_element.text)

                if not self._verify_encryption_key(session, parsed_licence):
                    raise InvalidLicense("Public encryption key does not match")

                is_scalable = bool(next(parsed_licence.get_object(XMRObjectTypes.AUX_KEY_OBJECT), None))

                for content_key in parsed_licence.get_content_keys():
                    cipher_type = Key.CipherType(content_key.cipher_type)

                    if cipher_type not in (Key.CipherType.ECC_256, Key.CipherType.ECC_256_WITH_KZ, Key.CipherType.ECC_256_VIA_SYMMETRIC):
                        raise InvalidLicense(f"Invalid cipher type {cipher_type}")

                    via_symmetric = Key.CipherType(content_key.cipher_type) == Key.CipherType.ECC_256_VIA_SYMMETRIC

                    decrypted = self.__crypto.ecc256_decrypt(
                        private_key=session.encryption_key,
                        ciphertext=content_key.encrypted_key
                    )
                    ci, ck = decrypted[:16], decrypted[16:]

                    if is_scalable:
                        ci, ck = decrypted[::2][:16], decrypted[1::2][:16]

                        if via_symmetric:
                            embedded_root_license = content_key.encrypted_key[:144]
                            embedded_leaf_license = content_key.encrypted_key[144:]

                            rgb_key = strxor(ck, self.rgbMagicConstantZero)
                            content_key_prime = AES.new(ck, AES.MODE_ECB).encrypt(rgb_key)

                            aux_key = next(parsed_licence.get_object(XMRObjectTypes.AUX_KEY_OBJECT))["auxiliary_keys"][0]["key"]

                            uplink_x_key = AES.new(content_key_prime, AES.MODE_ECB).encrypt(aux_key)
                            secondary_key = AES.new(ck, AES.MODE_ECB).encrypt(embedded_root_license[128:])

                            embedded_leaf_license = AES.new(uplink_x_key, AES.MODE_ECB).encrypt(embedded_leaf_license)
                            embedded_leaf_license = AES.new(secondary_key, AES.MODE_ECB).encrypt(embedded_leaf_license)

                            ci, ck = embedded_leaf_license[:16], embedded_leaf_license[16:]

                    if not parsed_licence.check_signature(ci):
                        raise InvalidLicense("License integrity signature does not match")

                    session.keys.append(Key(
                        key_id=UUID(bytes_le=content_key.key_id),
                        key_type=content_key.key_type,
                        cipher_type=content_key.cipher_type,
                        key_length=content_key.key_length,
                        key=ck
                    ))
        except Exception as e:
            raise InvalidLicense(f"Unable to parse license: {e}")

    def get_keys(self, session_id: bytes) -> List[Key]:
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession(f"Session identifier {session_id.hex()} is invalid.")

        return session.keys
