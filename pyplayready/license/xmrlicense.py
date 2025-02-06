from __future__ import annotations

import base64
from enum import IntEnum
from typing import Union

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from construct import Const, GreedyRange, Struct, Int32ub, Bytes, Int16ub, this, Switch, LazyBound, Array, Container


class XMRObjectTypes(IntEnum):
    INVALID = 0x0000
    OUTER_CONTAINER = 0x0001
    GLOBAL_POLICY_CONTAINER = 0x0002
    MINIMUM_ENVIRONMENT_OBJECT = 0x0003
    PLAYBACK_POLICY_CONTAINER = 0x0004
    OUTPUT_PROTECTION_OBJECT = 0x0005
    UPLINK_KID_OBJECT = 0x0006
    EXPLICIT_ANALOG_VIDEO_OUTPUT_PROTECTION_CONTAINER = 0x0007
    ANALOG_VIDEO_OUTPUT_CONFIGURATION_OBJECT = 0x0008
    KEY_MATERIAL_CONTAINER = 0x0009
    CONTENT_KEY_OBJECT = 0x000A
    SIGNATURE_OBJECT = 0x000B
    SERIAL_NUMBER_OBJECT = 0x000C
    SETTINGS_OBJECT = 0x000D
    COPY_POLICY_CONTAINER = 0x000E
    ALLOW_PLAYLISTBURN_POLICY_CONTAINER = 0x000F
    INCLUSION_LIST_OBJECT = 0x0010
    PRIORITY_OBJECT = 0x0011
    EXPIRATION_OBJECT = 0x0012
    ISSUEDATE_OBJECT = 0x0013
    EXPIRATION_AFTER_FIRSTUSE_OBJECT = 0x0014
    EXPIRATION_AFTER_FIRSTSTORE_OBJECT = 0x0015
    METERING_OBJECT = 0x0016
    PLAYCOUNT_OBJECT = 0x0017
    GRACE_PERIOD_OBJECT = 0x001A
    COPYCOUNT_OBJECT = 0x001B
    COPY_PROTECTION_OBJECT = 0x001C
    PLAYLISTBURN_COUNT_OBJECT = 0x001F
    REVOCATION_INFORMATION_VERSION_OBJECT = 0x0020
    RSA_DEVICE_KEY_OBJECT = 0x0021
    SOURCEID_OBJECT = 0x0022
    REVOCATION_CONTAINER = 0x0025
    RSA_LICENSE_GRANTER_KEY_OBJECT = 0x0026
    USERID_OBJECT = 0x0027
    RESTRICTED_SOURCEID_OBJECT = 0x0028
    DOMAIN_ID_OBJECT = 0x0029
    ECC_DEVICE_KEY_OBJECT = 0x002A
    GENERATION_NUMBER_OBJECT = 0x002B
    POLICY_METADATA_OBJECT = 0x002C
    OPTIMIZED_CONTENT_KEY_OBJECT = 0x002D
    EXPLICIT_DIGITAL_AUDIO_OUTPUT_PROTECTION_CONTAINER = 0x002E
    RINGTONE_POLICY_CONTAINER = 0x002F
    EXPIRATION_AFTER_FIRSTPLAY_OBJECT = 0x0030
    DIGITAL_AUDIO_OUTPUT_CONFIGURATION_OBJECT = 0x0031
    REVOCATION_INFORMATION_VERSION_2_OBJECT = 0x0032
    EMBEDDING_BEHAVIOR_OBJECT = 0x0033
    SECURITY_LEVEL = 0x0034
    COPY_TO_PC_CONTAINER = 0x0035
    PLAY_ENABLER_CONTAINER = 0x0036
    MOVE_ENABLER_OBJECT = 0x0037
    COPY_ENABLER_CONTAINER = 0x0038
    PLAY_ENABLER_OBJECT = 0x0039
    COPY_ENABLER_OBJECT = 0x003A
    UPLINK_KID_2_OBJECT = 0x003B
    COPY_POLICY_2_CONTAINER = 0x003C
    COPYCOUNT_2_OBJECT = 0x003D
    RINGTONE_ENABLER_OBJECT = 0x003E
    EXECUTE_POLICY_CONTAINER = 0x003F
    EXECUTE_POLICY_OBJECT = 0x0040
    READ_POLICY_CONTAINER = 0x0041
    EXTENSIBLE_POLICY_RESERVED_42 = 0x0042
    EXTENSIBLE_POLICY_RESERVED_43 = 0x0043
    EXTENSIBLE_POLICY_RESERVED_44 = 0x0044
    EXTENSIBLE_POLICY_RESERVED_45 = 0x0045
    EXTENSIBLE_POLICY_RESERVED_46 = 0x0046
    EXTENSIBLE_POLICY_RESERVED_47 = 0x0047
    EXTENSIBLE_POLICY_RESERVED_48 = 0x0048
    EXTENSIBLE_POLICY_RESERVED_49 = 0x0049
    EXTENSIBLE_POLICY_RESERVED_4A = 0x004A
    EXTENSIBLE_POLICY_RESERVED_4B = 0x004B
    EXTENSIBLE_POLICY_RESERVED_4C = 0x004C
    EXTENSIBLE_POLICY_RESERVED_4D = 0x004D
    EXTENSIBLE_POLICY_RESERVED_4E = 0x004E
    EXTENSIBLE_POLICY_RESERVED_4F = 0x004F
    REMOVAL_DATE_OBJECT = 0x0050
    AUX_KEY_OBJECT = 0x0051
    UPLINKX_OBJECT = 0x0052
    INVALID_RESERVED_53 = 0x0053
    APPLICATION_ID_LIST = 0x0054
    REAL_TIME_EXPIRATION = 0x0055
    ND_TX_AUTH_CONTAINER = 0x0056
    ND_TX_AUTH_OBJECT = 0x0057
    EXPLICIT_DIGITAL_VIDEO_PROTECTION = 0x0058
    DIGITAL_VIDEO_OPL = 0x0059
    SECURESTOP = 0x005A
    SECURESTOP2 = 0x005C
    OPTIMIZED_CONTENT_KEY2 = 0x005D
    COPY_UNKNOWN_OBJECT = 0xFFFD
    PLAYBACK_UNKNOWN_OBJECT = 0xFFFD
    GLOBAL_POLICY_UNKNOWN_OBJECT = 0xFFFD
    COPY_UNKNOWN_CONTAINER = 0xFFFE
    PLAYBACK_UNKNOWN_CONTAINER = 0xFFFE
    UNKNOWN_CONTAINERS = 0xFFFE


class _XMRLicenseStructs:
    PlayEnablerType = Struct(
        "player_enabler_type" / Bytes(16)
    )

    DomainRestrictionObject = Struct(
        "account_id" / Bytes(16),
        "revision" / Int32ub
    )

    IssueDateObject = Struct(
        "issue_date" / Int32ub
    )

    RevInfoVersionObject = Struct(
        "sequence" / Int32ub
    )

    SecurityLevelObject = Struct(
        "minimum_security_level" / Int16ub
    )

    EmbeddedLicenseSettingsObject = Struct(
        "indicator" / Int16ub
    )

    ECCKeyObject = Struct(
        "curve_type" / Int16ub,
        "key_length" / Int16ub,
        "key" / Bytes(this.key_length)
    )

    SignatureObject = Struct(
        "signature_type" / Int16ub,
        "signature_data_length" / Int16ub,
        "signature_data" / Bytes(this.signature_data_length)
    )

    ContentKeyObject = Struct(
        "key_id" / Bytes(16),
        "key_type" / Int16ub,
        "cipher_type" / Int16ub,
        "key_length" / Int16ub,
        "encrypted_key" / Bytes(this.key_length)
    )

    RightsSettingsObject = Struct(
        "rights" / Int16ub
    )

    OutputProtectionLevelRestrictionObject = Struct(
        "minimum_compressed_digital_video_opl" / Int16ub,
        "minimum_uncompressed_digital_video_opl" / Int16ub,
        "minimum_analog_video_opl" / Int16ub,
        "minimum_digital_compressed_audio_opl" / Int16ub,
        "minimum_digital_uncompressed_audio_opl" / Int16ub,
    )

    ExpirationRestrictionObject = Struct(
        "begin_date" / Int32ub,
        "end_date" / Int32ub
    )

    RemovalDateObject = Struct(
        "removal_date" / Int32ub
    )

    UplinkKIDObject = Struct(
        "uplink_kid" / Bytes(16),
        "chained_checksum_type" / Int16ub,
        "chained_checksum_length" / Int16ub,
        "chained_checksum" / Bytes(this.chained_checksum_length)
    )

    AnalogVideoOutputConfigurationRestriction = Struct(
        "video_output_protection_id" / Bytes(16),
        "binary_configuration_data" / Bytes(this._.length - 24)
    )

    DigitalVideoOutputRestrictionObject = Struct(
        "video_output_protection_id" / Bytes(16),
        "binary_configuration_data" / Bytes(this._.length - 24)
    )

    DigitalAudioOutputRestrictionObject = Struct(
        "audio_output_protection_id" / Bytes(16),
        "binary_configuration_data" / Bytes(this._.length - 24)
    )

    PolicyMetadataObject = Struct(
        "metadata_type" / Bytes(16),
        "policy_data" / Bytes(this._.length - 24)
    )

    SecureStopRestrictionObject = Struct(
        "metering_id" / Bytes(16)
    )

    MeteringRestrictionObject = Struct(
        "metering_id" / Bytes(16)
    )

    ExpirationAfterFirstPlayRestrictionObject = Struct(
        "seconds" / Int32ub
    )

    GracePeriodObject = Struct(
        "grace_period" / Int32ub
    )

    SourceIdObject = Struct(
        "source_id" / Int32ub
    )

    AuxiliaryKey = Struct(
        "location" / Int32ub,
        "key" / Bytes(16)
    )

    AuxiliaryKeysObject = Struct(
        "count" / Int16ub,
        "auxiliary_keys" / Array(this.count, AuxiliaryKey)
    )

    UplinkKeyObject3 = Struct(
        "uplink_key_id" / Bytes(16),
        "chained_length" / Int16ub,
        "checksum" / Bytes(this.chained_length),
        "count" / Int16ub,
        "entries" / Array(this.count, Int32ub)
    )

    CopyEnablerObject = Struct(
        "copy_enabler_type" / Bytes(16)
    )

    CopyCountRestrictionObject = Struct(
        "count" / Int32ub
    )

    MoveObject = Struct(
        "minimum_move_protection_level" / Int32ub
    )

    XmrObject = Struct(
        "flags" / Int16ub,
        "type" / Int16ub,
        "length" / Int32ub,
        "data" / Switch(
            lambda ctx: ctx.type,
            {
                XMRObjectTypes.OUTPUT_PROTECTION_OBJECT: OutputProtectionLevelRestrictionObject,
                XMRObjectTypes.ANALOG_VIDEO_OUTPUT_CONFIGURATION_OBJECT: AnalogVideoOutputConfigurationRestriction,
                XMRObjectTypes.CONTENT_KEY_OBJECT: ContentKeyObject,
                XMRObjectTypes.SIGNATURE_OBJECT: SignatureObject,
                XMRObjectTypes.SETTINGS_OBJECT: RightsSettingsObject,
                XMRObjectTypes.EXPIRATION_OBJECT: ExpirationRestrictionObject,
                XMRObjectTypes.ISSUEDATE_OBJECT: IssueDateObject,
                XMRObjectTypes.METERING_OBJECT: MeteringRestrictionObject,
                XMRObjectTypes.GRACE_PERIOD_OBJECT: GracePeriodObject,
                XMRObjectTypes.SOURCEID_OBJECT: SourceIdObject,
                XMRObjectTypes.ECC_DEVICE_KEY_OBJECT: ECCKeyObject,
                XMRObjectTypes.DOMAIN_ID_OBJECT: DomainRestrictionObject,
                XMRObjectTypes.POLICY_METADATA_OBJECT: PolicyMetadataObject,
                XMRObjectTypes.EXPIRATION_AFTER_FIRSTPLAY_OBJECT: ExpirationAfterFirstPlayRestrictionObject,
                XMRObjectTypes.DIGITAL_AUDIO_OUTPUT_CONFIGURATION_OBJECT: DigitalAudioOutputRestrictionObject,
                XMRObjectTypes.REVOCATION_INFORMATION_VERSION_2_OBJECT: RevInfoVersionObject,
                XMRObjectTypes.EMBEDDING_BEHAVIOR_OBJECT: EmbeddedLicenseSettingsObject,
                XMRObjectTypes.SECURITY_LEVEL: SecurityLevelObject,
                XMRObjectTypes.MOVE_ENABLER_OBJECT: MoveObject,
                XMRObjectTypes.PLAY_ENABLER_OBJECT: PlayEnablerType,
                XMRObjectTypes.COPY_ENABLER_OBJECT: CopyEnablerObject,
                XMRObjectTypes.UPLINK_KID_2_OBJECT: UplinkKIDObject,
                XMRObjectTypes.COPYCOUNT_2_OBJECT: CopyCountRestrictionObject,
                XMRObjectTypes.REMOVAL_DATE_OBJECT: RemovalDateObject,
                XMRObjectTypes.AUX_KEY_OBJECT: AuxiliaryKeysObject,
                XMRObjectTypes.UPLINKX_OBJECT: UplinkKeyObject3,
                XMRObjectTypes.DIGITAL_VIDEO_OPL: DigitalVideoOutputRestrictionObject,
                XMRObjectTypes.SECURESTOP: SecureStopRestrictionObject,
            },
            default=LazyBound(lambda ctx: _XMRLicenseStructs.XmrObject)
        )
    )

    XmrLicense = Struct(
        "signature" / Const(b"XMR\x00"),
        "xmr_version" / Int32ub,
        "rights_id" / Bytes(16),
        "containers" / GreedyRange(XmrObject)
    )


class XMRLicense(_XMRLicenseStructs):
    """Represents an XMRLicense"""

    def __init__(
            self,
            parsed_license: Container,
            license_obj: _XMRLicenseStructs.XmrLicense = _XMRLicenseStructs.XmrLicense
    ):
        self.parsed = parsed_license
        self._license_obj = license_obj

    @classmethod
    def loads(cls, data: Union[str, bytes]) -> XMRLicense:
        if isinstance(data, str):
            data = base64.b64decode(data)
        if not isinstance(data, bytes):
            raise ValueError(f"Expecting Bytes or Base64 input, got {data!r}")

        licence = _XMRLicenseStructs.XmrLicense
        return cls(
            parsed_license=licence.parse(data),
            license_obj=licence
        )

    def dumps(self) -> bytes:
        return self._license_obj.build(self.parsed)

    def _locate(self, container: Container):
        if container.flags == 2 or container.flags == 3:
            return self._locate(container.data)
        else:
            return container

    def get_object(self, type_: int):
        for obj in self.parsed.containers:
            container = self._locate(obj)
            if container.type == type_:
                yield container.data

    def get_content_keys(self):
        yield from self.get_object(XMRObjectTypes.CONTENT_KEY_OBJECT)

    def check_signature(self, integrity_key: bytes) -> bool:
        cmac = CMAC.new(integrity_key, ciphermod=AES)

        signature_data = next(self.get_object(XMRObjectTypes.SIGNATURE_OBJECT))
        cmac.update(self.dumps()[:-(signature_data.signature_data_length + 12)])

        return signature_data.signature_data == cmac.digest()
