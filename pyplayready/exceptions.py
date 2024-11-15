class PyPlayredyException(Exception):
    """Exceptions used by pyplayready."""


class TooManySessions(PyPlayredyException):
    """Too many Sessions are open."""


class InvalidSession(PyPlayredyException):
    """No Session is open with the specified identifier."""


class InvalidInitData(PyPlayredyException):
    """The Playready Cenc Header Data is invalid or empty."""


class DeviceMismatch(PyPlayredyException):
    """The Remote CDMs Device information and the APIs Device information did not match."""