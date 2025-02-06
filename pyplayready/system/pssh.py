import base64
from typing import Union, List
from uuid import UUID

from construct import Struct, Int32ul, Int16ul, this, Bytes, Switch, Int8ub, Int24ub, Int32ub, Const, Container, \
    ConstructError, Rebuild, Default, If, PrefixedArray, Prefixed, GreedyBytes

from pyplayready.exceptions import InvalidPssh
from pyplayready.system.wrmheader import WRMHeader


class _PlayreadyPSSHStructs:
    PSSHBox = Struct(
        "length" / Int32ub,
        "pssh" / Const(b"pssh"),
        "version" / Rebuild(Int8ub, lambda ctx: 1 if (hasattr(ctx, "key_ids") and ctx.key_ids) else 0),
        "flags" / Const(Int24ub, 0),
        "system_id" / Bytes(16),
        "key_ids" / Default(If(this.version == 1, PrefixedArray(Int32ub, Bytes(16))), None),
        "data" / Prefixed(Int32ub, GreedyBytes)
    )

    PlayreadyObject = Struct(
        "type" / Int16ul,
        "length" / Int16ul,
        "data" / Switch(
            this.type,
            {
                1: Bytes(this.length)
            },
            default=Bytes(this.length)
        )
    )

    PlayreadyHeader = Struct(
        "length" / Int32ul,
        "records" / PrefixedArray(Int16ul, PlayreadyObject)
    )


class PSSH(_PlayreadyPSSHStructs):
    """Represents a PlayReady PSSH"""

    SYSTEM_ID = UUID(hex="9a04f07998404286ab92e65be0885f95")

    def __init__(self, data: Union[str, bytes]):
        """Load a PSSH Box, PlayReady Header or PlayReady Object"""

        if not data:
            raise InvalidPssh("Data must not be empty")

        if isinstance(data, str):
            try:
                data = base64.b64decode(data)
            except Exception as e:
                raise InvalidPssh(f"Could not decode data as Base64, {e}")

        self.wrm_headers: List[WRMHeader]
        try:
            # PSSH Box -> PlayReady Header
            box = self.PSSHBox.parse(data)
            if self._is_utf_16_le(box.data):
                self.wrm_headers = [WRMHeader(box.data)]
            else:
                prh = self.PlayreadyHeader.parse(box.data)
                self.wrm_headers = self._read_playready_objects(prh)
        except ConstructError:
            if int.from_bytes(data[:2], byteorder="little") > 3:
                try:
                    # PlayReady Header
                    prh = self.PlayreadyHeader.parse(data)
                    self.wrm_headers = self._read_playready_objects(prh)
                except ConstructError:
                    raise InvalidPssh("Could not parse data as a PSSH Box nor a PlayReady Header")
            else:
                try:
                    # PlayReady Object
                    pro = self.PlayreadyObject.parse(data)
                    self.wrm_headers = [WRMHeader(pro.data)]
                except ConstructError:
                    raise InvalidPssh("Could not parse data as a PSSH Box nor a PlayReady Object")


    @staticmethod
    def _is_utf_16_le(data: bytes) -> bool:
        if len(data) % 2 != 0:
            return False

        try:
            decoded = data.decode('utf-16-le')
        except UnicodeDecodeError:
            return False

        for char in decoded:
            if not (0x20 <= ord(char) <= 0x7E):
                return False

        return True

    @staticmethod
    def _read_playready_objects(header: Container) -> List[WRMHeader]:
        return list(map(
            lambda pro: WRMHeader(pro.data),
            filter(
                lambda pro: pro.type == 1,
                header.records
            )
        ))
