"""Expected, fail-closed validation errors."""
class CustodyError(ValueError):
    """The input or operation is not authorized by this implementation."""

class UnsupportedProfile(CustodyError):
    """No approved implementation exists for the requested operation."""
