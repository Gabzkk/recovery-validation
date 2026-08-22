class RecoveryValidationError(Exception):
    """Base class for expected recovery-validation failures."""


class ConfigurationError(RecoveryValidationError):
    """Configuration is missing, invalid, or unsafe."""


class ContainmentError(RecoveryValidationError):
    """The requested exercise violates a filesystem safety boundary."""


class IntegrityError(RecoveryValidationError):
    """Key, source, container, or restored content has invalid integrity."""


class DecryptionError(IntegrityError):
    """Authenticated decryption failed."""


class AuditForwardError(RecoveryValidationError):
    """The compliance report could not be delivered to the audit endpoint."""
