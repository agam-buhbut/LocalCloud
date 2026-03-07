# LocalCloud - Custom Exceptions
#
# All exceptions used across the system. Generic error messages
# to avoid information leakage.


class LocalCloudError(Exception):
    """Base exception for all LocalCloud errors."""
    pass


# ──────────────────────────── Crypto Errors ────────────────────────────

class CryptoError(LocalCloudError):
    """Cryptographic operation failed. Deliberately generic."""
    pass


class DecryptionError(CryptoError):
    """Decryption or authentication tag verification failed."""
    pass


class SignatureError(CryptoError):
    """Signature verification failed."""
    pass


class MerkleVerificationError(CryptoError):
    """Merkle tree / proof verification failed."""
    pass


class NonceReuseError(CryptoError):
    """Nonce reuse detected — critical security violation."""
    pass


# ──────────────────────────── Auth Errors ────────────────────────────

class AuthError(LocalCloudError):
    """Authentication or authorization failed. Deliberately generic."""
    pass


class RateLimitError(AuthError):
    """Rate limit exceeded."""
    pass


class SessionExpiredError(AuthError):
    """Session token expired or invalid."""
    pass


# ──────────────────────────── Storage Errors ────────────────────────────

class StorageError(LocalCloudError):
    """Storage operation failed."""
    pass


class QuotaExceededError(StorageError):
    """User storage quota exceeded."""
    pass


class UploadError(StorageError):
    """Upload integrity check or staging error."""
    pass


class FileNotFoundError_(StorageError):
    """Requested file does not exist. Named with underscore to avoid
    shadowing the builtin FileNotFoundError."""
    pass


# ──────────────────────────── Protocol Errors ────────────────────────────

class ProtocolError(LocalCloudError):
    """Wire format or protocol version mismatch."""
    pass


class MalformedRequestError(ProtocolError):
    """Request could not be parsed or is structurally invalid."""
    pass
