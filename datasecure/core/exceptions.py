"""Custom exceptions for DataSecure."""


class DataSecureError(Exception):
    """Base exception for all DataSecure errors."""
    pass


class ConfigurationError(DataSecureError):
    """Raised when there is an issue loading or validating configuration."""
    pass


class ScanExecutionError(DataSecureError):
    """Raised when a scanner fails unexpectedly during execution."""
    pass


class InvalidTargetError(DataSecureError):
    """Raised when the specified scan target path is invalid or inaccessible."""
    pass

