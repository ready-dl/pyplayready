from __future__ import annotations

import logging
from typing import Union

import requests

from pyplayready import InvalidLicense
from pyplayready.cdm import Cdm
from pyplayready.device import Device
from pyplayready.license.key import Key

from pyplayready.exceptions import (DeviceMismatch, InvalidInitData)
from pyplayready.system.wrmheader import WRMHeader


class RemoteCdm(Cdm):
    """Remote Accessible CDM using pyplayready's serve schema."""

    def __init__(
        self,
        security_level: int,
        host: str,
        secret: str,
        device_name: str
    ):
        """Initialize a Playready Content Decryption Module (CDM)."""
        if not security_level:
            raise ValueError("Security Level must be provided")
        if not isinstance(security_level, int):
            raise TypeError(f"Expected security_level to be a {int} not {security_level!r}")

        if not host:
            raise ValueError("API Host must be provided")
        if not isinstance(host, str):
            raise TypeError(f"Expected host to be a {str} not {host!r}")

        if not secret:
            raise ValueError("API Secret must be provided")
        if not isinstance(secret, str):
            raise TypeError(f"Expected secret to be a {str} not {secret!r}")

        if not device_name:
            raise ValueError("API Device name must be provided")
        if not isinstance(device_name, str):
            raise TypeError(f"Expected device_name to be a {str} not {device_name!r}")

        self.security_level = security_level
        self.host = host
        self.device_name = device_name

        # spoof certificate_chain and ecc_key just so we can construct via super call
        super().__init__(security_level, None, None, None)

        self._logger = logging.getLogger()

        self.__session = requests.Session()
        self.__session.headers.update({
            "X-Secret-Key": secret
        })

        response = requests.head(self.host)

        if response.status_code != 200:
            self._logger.warning(f"Could not test Remote API version [{response.status_code}]")

        server = response.headers.get("Server")
        if not server or "playready serve" not in server.lower():
            self._logger.warning(f"This Remote CDM API does not seem to be a playready serve API ({server}).")

    @classmethod
    def from_device(cls, device: Device) -> RemoteCdm:
        raise NotImplementedError("You cannot load a RemoteCdm from a local Device file.")

    def open(self) -> bytes:
        response = self.__session.get(
            url=f"{self.host}/{self.device_name}/open"
        )
        response_json = response.json()

        if response.status_code != 200:
            raise ValueError(f"Cannot Open CDM Session, {response_json['message']} [{response.status_code}]")

        if int(response_json["data"]["device"]["security_level"]) != self.security_level:
            raise DeviceMismatch("The Security Level specified does not match the one specified in the API response.")

        return bytes.fromhex(response_json["data"]["session_id"])

    def close(self, session_id: bytes) -> None:
        response = self.__session.get(
            url=f"{self.host}/{self.device_name}/close/{session_id.hex()}"
        )
        response_json = response.json()

        if response.status_code != 200:
            raise ValueError(f"Cannot Close CDM Session, {response_json['message']} [{response.status_code}]")

    def get_license_challenge(self, session_id: bytes, wrm_header: Union[WRMHeader, str]) -> str:
        if not wrm_header:
            raise InvalidInitData("A wrm_header must be provided.")
        if isinstance(wrm_header, WRMHeader):
            wrm_header = wrm_header.dumps()
        if not isinstance(wrm_header, str):
            raise ValueError(f"Expected WRMHeader to be a {str} or {WRMHeader} not {wrm_header!r}")

        response = self.__session.post(
            url=f"{self.host}/{self.device_name}/get_license_challenge",
            json={
                "session_id": session_id.hex(),
                "init_data": wrm_header
            }
        )
        response_json = response.json()

        if response.status_code != 200:
            raise ValueError(f"Cannot get Challenge, {response_json['message']} [{response.status_code}]")

        return response_json["data"]["challenge"]

    def parse_license(self, session_id: bytes, license_message: str) -> None:
        if not license_message:
            raise InvalidLicense("Cannot parse an empty license_message")

        if not isinstance(license_message, str):
            raise InvalidLicense(f"Expected license_message to be a {str}, not {license_message!r}")

        response = self.__session.post(
            url=f"{self.host}/{self.device_name}/parse_license",
            json={
                "session_id": session_id.hex(),
                "license_message": license_message
            }
        )
        response_json = response.json()

        if response.status_code != 200:
            raise ValueError(f"Cannot parse License, {response_json['message']} [{response.status_code}]")

    def get_keys(self, session_id: bytes) -> list[Key]:
        response = self.__session.post(
            url=f"{self.host}/{self.device_name}/get_keys",
            json={
                "session_id": session_id.hex()
            }
        )
        response_json = response.json()

        if response.status_code != 200:
            raise ValueError(f"Could not get Keys, {response_json['message']} [{response.status_code}]")

        return [
            Key(
                key_type=key["type"],
                key_id=Key.kid_to_uuid(bytes.fromhex(key["key_id"])),
                key=bytes.fromhex(key["key"]),
                cipher_type=key["cipher_type"],
                key_length=key["key_length"]
            )
            for key in response_json["data"]["keys"]
        ]


__all__ = ("RemoteCdm",)
