"""
Cracking engines for hashes and ciphers.

Provides implementations for:
- Hash cracking (dictionary-based wordlist attack with multiprocessing)
- Cipher decryption (ROT13, ROT47, Base64, Hex)
"""

import hashlib
import base64
import binascii
from abc import ABC, abstractmethod
from typing import Optional, Callable, List
import logging

logger = logging.getLogger(__name__)


class CrackerError(Exception):
    """Base exception for all cracker-related errors."""
    pass



class BaseCracker(ABC):
    """Abstract base class for all crackers."""

    @abstractmethod
    def crack(self, data: str, **kwargs) -> Optional[str]:
        """
        Attempt to crack the given data.

        Args:
            data: The encoded/hashed data to crack
            **kwargs: Additional arguments specific to cracker type

        Returns:
            Decrypted/cracked plaintext if successful, None otherwise
        """
        raise NotImplementedError()


class CipherCracker(BaseCracker):
    """Cracker for common cipher types."""

    @staticmethod
    def rot13(data: str) -> str:
        """Decrypt ROT13."""
        def _rot13_char(c: str) -> str:
            if 'a' <= c <= 'z':
                return chr((ord(c) - ord('a') + 13) % 26 + ord('a'))
            if 'A' <= c <= 'Z':
                return chr((ord(c) - ord('A') + 13) % 26 + ord('A'))
            return c
        return ''.join(_rot13_char(c) for c in data)

    @staticmethod
    def rot47(data: str) -> str:
        """Decrypt ROT47."""
        return ''.join(
            chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
            for c in data
        )

    @staticmethod
    def base64_decode(data: str) -> Optional[str]:
        """Decode Base64."""
        try:
            decoded = base64.b64decode(data)
            return decoded.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug("Base64 decode failed: %s", e)
            return None

    @staticmethod
    def hex_decode(data: str) -> Optional[str]:
        """Decode hexadecimal."""
        try:
            decoded = binascii.unhexlify(data)
            return decoded.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug("Hex decode failed: %s", e)
            return None

    def crack(self, data: str, cipher_type: str = None, **kwargs) -> Optional[str]:
        """
        Crack a cipher by attempting known decryption methods.

        Args:
            data: The cipher text
            cipher_type: Specific cipher type to use ('rot13', 'rot47', 'base64', 'hex')
            **kwargs: Additional arguments

        Returns:
            Decrypted plaintext or None if decryption fails
        """
        methods = [
            ("base64", self.base64_decode),
            ("hex", self.hex_decode),
            ("rot13", self.rot13),
            ("rot47", self.rot47),
        ]

        if cipher_type:
            method = dict(methods).get(cipher_type)
            if method:
                try:
                    return method(data)
                except Exception as e:
                    logger.error("Failed to crack %s: %s", cipher_type, e)
            return None

        # Try all methods in order
        for name, method in methods:
            try:
                result = method(data)
                if result and len(result.strip()) > 0:
                    logger.debug("Cipher %s produced output", name)
                    return result
            except Exception:
                logger.debug("Cipher method %s failed", name, exc_info=True)
        return None


class HashCracker(BaseCracker):
    """Cracker for hash types using dictionary/wordlist attacks.

    Uses a producer-consumer multiprocessing pattern to stream words from large
    wordlists without loading the entire file into memory. Workers consume
    words from an input_queue and write any successful plaintext into a
    result_queue. An Event is used to signal early termination.
    """

    # Map of hash algorithm names to hashlib functions
    HASH_ALGORITHMS = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "blake2b": hashlib.blake2b,
        "blake2s": hashlib.blake2s,
    }

    class CrackerError(Exception):
        """Base exception for hash cracker errors."""

    @staticmethod
    def hash_word(word: str, algorithm: str) -> str:
        """
        Hash a word using the specified algorithm.
        """
        hasher = HashCracker.HASH_ALGORITHMS[algorithm.lower()]()
        hasher.update(word.encode('utf-8', errors='ignore'))
        return hasher.hexdigest()

    @staticmethod
    def _worker_loop(
        input_queue: 'multiprocessing.queues.Queue',
        result_queue: 'multiprocessing.queues.Queue',
        stop_event: 'multiprocessing.synchronize.Event',
        target_hash: str,
        algorithm: str,
    ) -> None:
        """Worker process main loop: read words and test them."""
        while not stop_event.is_set():
            try:
                word = input_queue.get(timeout=0.5)
            except Exception:
                # timeout or empty — loop and check stop_event
                continue
            if word is None:
                # Sentinel received — requeue sentinel for other workers and exit
                input_queue.put(None)
                break
            word = word.strip()
            if not word:
                continue
            try:
                if HashCracker.hash_word(word, algorithm).lower() == target_hash.lower():
                    # Put result and signal others to stop
                    result_queue.put(word)
                    stop_event.set()
                    break
            except Exception:
                logger.debug("Error hashing word during worker loop", exc_info=True)

    def crack(
        self,
        data: str,
        hash_type: str = "md5",
        wordlist_path: str = None,
        num_workers: int = 4,
        chunk_size: int = 1000,
        **kwargs,
    ) -> Optional[str]:
        """
        Crack a hash using a streaming dictionary attack with multiprocessing.

        Streaming reduces memory overhead for very large wordlists.
        """
        if not wordlist_path:
            raise HashCracker.CrackerError("Wordlist path is required for hash cracking")

        algorithm = (hash_type or "md5").lower()
        if algorithm not in self.HASH_ALGORITHMS:
            raise HashCracker.CrackerError(
                f"Unsupported hash type: {hash_type}. Supported: {', '.join(self.HASH_ALGORITHMS.keys())}"
            )

        # Try to open the file lazily; avoid reading whole file
        try:
            wordfile = open(wordlist_path, 'r', encoding='utf-8', errors='ignore')
        except FileNotFoundError:
            raise HashCracker.CrackerError(f"Wordlist file not found: {wordlist_path}")

        logger.info("Starting hash crack: %s (streaming using %d workers)", algorithm.upper(), num_workers)

        # Multiprocessing primitives
        from multiprocessing import Process, Queue, Event

        input_queue: 'multiprocessing.queues.Queue' = Queue(maxsize=max(1000, num_workers * 2))
        result_queue: 'multiprocessing.queues.Queue' = Queue()
        stop_event: 'multiprocessing.synchronize.Event' = Event()

        # Start worker processes
        workers = []
        for _ in range(max(1, num_workers)):
            p = Process(
                target=HashCracker._worker_loop,
                args=(input_queue, result_queue, stop_event, data, algorithm),
            )
            p.daemon = True
            p.start()
            workers.append(p)

        # Producer: put words into input_queue
        try:
            count = 0
            for line in wordfile:
                if stop_event.is_set():
                    break
                word = line.rstrip('\n')
                # Block when queue is full to apply backpressure
                input_queue.put(word)
                count += 1
            # Signal workers to stop by putting sentinel
            input_queue.put(None)
        finally:
            wordfile.close()

        # Wait for a result or for workers to finish
        found: Optional[str] = None
        try:
            while True:
                if not result_queue.empty():
                    found = result_queue.get()
                    break
                # If all workers have exited, break
                if all(not p.is_alive() for p in workers):
                    break
                # small sleep to avoid busy loop
                import time
                time.sleep(0.1)
        finally:
            # Clean up worker processes
            stop_event.set()
            for p in workers:
                if p.is_alive():
                    p.terminate()
                p.join(timeout=1.0)

        if found:
            logger.info("Hash cracked! Plaintext: %s", found)
            return found

        logger.warning("Hash could not be cracked with provided wordlist")
        return None


class CrackerFactory:
    """Factory for creating appropriate cracker instances.

    Uses a decorator-based registration for extensibility. Classes can be
    registered for categories or specific algorithm names with @register_cracker.
    get_cracker will attempt to resolve a specific algorithm first and fall
    back to category names ('hash' / 'cipher').
    """

    _registry: dict = {
        "hash": HashCracker,
        "cipher": CipherCracker,
    }

    @classmethod
    def register_cracker(cls, key: str) -> Callable[[type], type]:
        """Decorator to register a cracker class under `key`.

        Usage:
            @CrackerFactory.register_cracker('md5')
            class MD5Cracker(HashCracker):
                ...
        """
        def _decorator(cracker_cls: type) -> type:
            if not issubclass(cracker_cls, BaseCracker):
                raise TypeError("Registered cracker must inherit from BaseCracker")
            cls._registry[key] = cracker_cls
            logger.debug("Registered cracker '%s' -> %s", key, cracker_cls)
            return cracker_cls

        return _decorator

    @classmethod
    def get_cracker(cls, key: str) -> BaseCracker:
        """Resolve a cracker by specific key (algorithm) or category.

        If key matches a registered algorithm (e.g., 'md5') that cracker is
        returned; otherwise the key is treated as a category ('hash'/'cipher').
        """
        cracker_cls = cls._registry.get(key.lower()) or cls._registry.get(key)
        if not cracker_cls:
            raise TypeError(
                f"No cracker registered for: {key}. Available: {', '.join(cls._registry.keys())}"
            )
        return cracker_cls()

# Provide decorator at module level for convenient usage
register_cracker = CrackerFactory.register_cracker

# Example usage (register existing classes for specific keys)
register_cracker('hash')(HashCracker)
register_cracker('cipher')(CipherCracker)
