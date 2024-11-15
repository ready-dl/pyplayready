class PyPlayreadyException(Exception):
    """Exceptions used by pyplayready."""


class TooManySessions(PyPlayreadyException):
    """Too many Sessions are open."""


class InvalidSession(PyPlayreadyException):
    """No Session is open with the specified identifier."""


class InvalidInitData(PyPlayreadyException):
    """The Playready Cenc Header Data is invalid or empty."""


class DeviceMismatch(PyPlayreadyException):
    """The Remote CDMs Device information and the APIs Device information did not match."""


class InvalidLicense(PyPlayreadyException):
    """Unable to parse XMR License."""
