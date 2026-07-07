"""
Detection engine for identifying hash types and cipher formats.

This module provides regex-based and entropy-based detection for:
- Hash types (MD5, SHA1, SHA256, SHA512, etc.)
- Cipher formats (Base64, Rot13, Hex, etc.)
"""

import re
from enum import Enum
from typing import Optional, NamedTuple


class HashType(Enum):
    """Enumeration of supported hash types."""
    MD5 = "md5"
    SHA1 = "sha1"
    SHA224 = "sha224"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    BLAKE2B = "blake2b"
    BLAKE2S = "blake2s"


class CipherType(Enum):
    """Enumeration of supported cipher types."""
    BASE64 = "base64"
    ROT13 = "rot13"
    HEX = "hex"
    ROT47 = "rot47"


class DetectionResult(NamedTuple):
    """Result of detection analysis."""
    detected_type: str
    category: str  # 'hash', 'cipher', or 'unknown'
    confidence: float  # 0.0 to 1.0
    algorithm: Optional[str] = None


class DetectionError(Exception):
    """Errors raised by the detection engine."""
    pass


class HashDetector:
    """Detector for hash types using regex patterns and heuristics."""

    # Define hash patterns with their hex lengths
    HASH_PATTERNS = {
        HashType.MD5: (r"^[a-fA-F0-9]{32}$", 32),
        HashType.SHA1: (r"^[a-fA-F0-9]{40}$", 40),
        HashType.SHA224: (r"^[a-fA-F0-9]{56}$", 56),
        HashType.SHA256: (r"^[a-fA-F0-9]{64}$", 64),
        HashType.SHA384: (r"^[a-fA-F0-9]{96}$", 96),
        HashType.SHA512: (r"^[a-fA-F0-9]{128}$", 128),
        HashType.BLAKE2B: (r"^[a-fA-F0-9]{128}$", 128),
        HashType.BLAKE2S: (r"^[a-fA-F0-9]{64}$", 64),
    }

    @staticmethod
    def _is_unix_crypt(data: str) -> bool:
        # Typical format: $id$salt$hash
        return data.startswith("$") and data.count("$") >= 2

    @staticmethod
    def _hex_to_bytes(s: str) -> Optional[bytes]:
        try:
            return bytes.fromhex(s)
        except Exception:
            return None

    @classmethod
    def detect(cls, data: str) -> Optional[DetectionResult]:
        """
        Detect hash type from a string with support for salted paths and
        basic nested/composite heuristics.
        """
        data = data.strip()

        # Detect unix-style salted crypt entries
        if cls._is_unix_crypt(data):
            return DetectionResult(
                detected_type="unix-crypt",
                category="hash",
                confidence=0.9,
                algorithm="UNIX-Crypt",
            )

        # Direct regex-based matches (hex hashes)
        for hash_type, (pattern, length) in cls.HASH_PATTERNS.items():
            if re.match(pattern, data):
                return DetectionResult(
                    detected_type=hash_type.value,
                    category="hash",
                    confidence=0.95,
                    algorithm=hash_type.value.upper(),
                )

        # Heuristic: try to decode base64 and see if decoded payload looks like a hash
        try:
            import base64
            decoded = base64.b64decode(data, validate=False)
            decoded_str = decoded.hex()
            for hash_type, (pattern, length) in cls.HASH_PATTERNS.items():
                if re.match(rf"^[0-9a-fA-F]{{{length}}}$", decoded_str):
                    # composite: base64 -> hex-hash
                    return DetectionResult(
                        detected_type=f"base64+{hash_type.value}",
                        category="hash",
                        confidence=0.88,
                        algorithm=f"Base64->{hash_type.value.upper()}",
                    )
        except Exception:
            pass

        # Heuristic: input is hex string that when decoded produces another hex string
        bytes_inner = cls._hex_to_bytes(data) if re.match(r"^[0-9a-fA-F]+$", data) else None
        if bytes_inner:
            inner_hex = bytes_inner.hex()
            for hash_type, (pattern, length) in cls.HASH_PATTERNS.items():
                if re.match(rf"^[0-9a-fA-F]{{{length}}}$", inner_hex):
                    # composite hex encoding
                    return DetectionResult(
                        detected_type=f"hex+{hash_type.value}",
                        category="hash",
                        confidence=0.85,
                        algorithm=f"Hex->{hash_type.value.upper()}",
                    )

        return None


class CipherDetector:
    """Detector for cipher types using pattern matching and heuristics.

    Adds entropy-based heuristics to flag potential custom ciphers or high-entropy
    encodings that may require specialized analysis.
    """

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        from collections import Counter
        import math
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        ent = -sum((c/length) * math.log2(c/length) for c in counts.values())
        return ent

    @staticmethod
    def is_valid_base64(data: str) -> bool:
        """Check if string is valid Base64."""
        if len(data) % 4 != 0:
            return False
        try:
            import base64
            base64.b64decode(data, validate=True)
            return True
        except Exception:
            return False

    @staticmethod
    def is_rot13(data: str) -> bool:
        """Check if string looks like ROT13 (simple heuristic)."""
        if not data.isalpha():
            return False
        return len(data) > 4

    @staticmethod
    def is_hex(data: str) -> bool:
        """Check if string is valid hexadecimal."""
        return bool(re.match(r"^[a-fA-F0-9]+$", data)) and len(data) % 2 == 0

    @staticmethod
    def is_rot47(data: str) -> bool:
        """Check if string is potentially ROT47 encoded."""
        return all(33 <= ord(c) <= 126 for c in data) and len(data) > 4

    @classmethod
    def detect(cls, data: str) -> Optional[DetectionResult]:
        """
        Detect cipher type from a string.

        Args:
            data: The potential cipher string

        Returns:
            DetectionResult if cipher is detected, None otherwise
        """
        data = data.strip()

        # High-confidence Base64
        if cls.is_valid_base64(data):
            # Also check for nested encodings (e.g., base64 of hex/hash)
            try:
                import base64
                decoded = base64.b64decode(data, validate=False)
                decoded_text = decoded.decode('utf-8', errors='ignore')
                # If decoded text looks like hex/hash, return composite
                if re.match(r"^[0-9a-fA-F]{32,128}$", decoded_text):
                    return DetectionResult(
                        detected_type=f"base64+hex",
                        category="cipher",
                        confidence=0.85,
                        algorithm="Base64->Hex",
                    )
            except Exception:
                pass

            return DetectionResult(
                detected_type=CipherType.BASE64.value,
                category="cipher",
                confidence=0.85,
                algorithm="Base64",
            )

        # Hex
        if cls.is_hex(data):
            # If hex decodes to readable plaintext, favor cipher
            try:
                decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
                if decoded and any(c.isalpha() for c in decoded):
                    return DetectionResult(
                        detected_type=CipherType.HEX.value,
                        category="cipher",
                        confidence=0.82,
                        algorithm="Hex",
                    )
            except Exception:
                pass
            return DetectionResult(
                detected_type=CipherType.HEX.value,
                category="cipher",
                confidence=0.80,
                algorithm="Hex",
            )

        # ROT47
        if cls.is_rot47(data) and not data.isalnum():
            return DetectionResult(
                detected_type=CipherType.ROT47.value,
                category="cipher",
                confidence=0.70,
                algorithm="ROT47",
            )

        # ROT13
        if cls.is_rot13(data):
            return DetectionResult(
                detected_type=CipherType.ROT13.value,
                category="cipher",
                confidence=0.60,
                algorithm="ROT13",
            )

        # Entropy-based heuristic: very high entropy suggests custom cipher or binary blob
        entropy = cls._shannon_entropy(data)
        if entropy > 4.0:
            return DetectionResult(
                detected_type="high-entropy",
                category="cipher",
                confidence=0.50,
                algorithm=None,
            )

        return None


class Detector:
    """Main detector orchestrating hash and cipher detection."""

    @staticmethod
    def detect(data: str) -> DetectionResult:
        """
        Detect what type of encoded/hashed data we have.

        Args:
            data: The string to analyze

        Returns:
            DetectionResult with detected type, category, and confidence
        """
        # Try hash detection first (more specific)
        hash_result = HashDetector.detect(data)
        if hash_result:
            return hash_result

        # Try cipher detection
        cipher_result = CipherDetector.detect(data)
        if cipher_result:
            return cipher_result

        # Unknown
        return DetectionResult(
            detected_type="unknown",
            category="unknown",
            confidence=0.0,
            algorithm=None,
        )
