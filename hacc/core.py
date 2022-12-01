import secrets
from typing import Optional, Tuple
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Crypt:
    def __init__(self, level: int = 1) -> None:
        self.reset(level=level)

    # Private Methods

    def __init_data(self) -> None:
        self.__key: Optional[str] = None
        self.__message: Optional[str] = None

    def __init_backend(self) -> None:
        self.__backend = default_backend()

    def __init_state(self) -> None:
        self.__locked: bool = False
        self.__loaded: bool = False

    def __init_level(self, level: int) -> None:
        self.__iterations: int = 2**level

    def __init_salt(self) -> None:
        self.__salt: bytes = secrets.token_bytes(16)

    def __assert(
        self, loaded: Optional[bool] = None, locked: Optional[bool] = None
    ) -> None:
        if loaded is not None:
            assert loaded == self.__loaded, f"ERROR: `loaded` must be {loaded}"
        if locked is not None:
            assert locked == self.__locked, f"ERROR: `locked` must be {locked}"

    def __set(
        self, loaded: Optional[bool] = None, locked: Optional[bool] = None
    ) -> None:
        if loaded is not None:
            self.__loaded = loaded
        if locked is not None:
            self.__locked = locked

    # Hidden Methods

    # ! INTENTIONAL VULNERABILITY
    def _compare(self, A: str, B: str) -> bool:
        al, bl = len(A), len(B)
        for i in range(min(al, bl)):
            if A[i] != B[i]:
                return False
        if len(A) != len(B):
            return False
        return True

    def _derive(self, key: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.__salt,
            iterations=self.__iterations,
            backend=self.__backend,
        )
        return b64e(kdf.derive(key.encode()))

    def _encrypt(self, key: str, message: str) -> str:
        key = self._derive(key.encode(), self.__salt, self.__iterations)
        return b64e(
            b"%b%b%b"
            % (
                self.__salt,
                self.__iterations.to_bytes(4, "big"),
                b64d(Fernet(key).encrypt(message)),
            )
        )

    def _decrypt(self, key: str, message: str) -> str:
        message = b64d(message)
        salt, iterations, message = message[:16], message[16:20], b64e(message[20:])
        iterations = int.from_bytes(iterations, "big")
        key = self.derive(key.encode(), salt, iterations)
        return Fernet(key).decrypt(message)

    # Public Methods

    def reset(self, level: int = 1):
        self.__init_data()
        self.__init_backend()
        self.__init_state()
        self.__init_level(level=level)
        self.__init_salt()

    def load(self, path: str) -> bool:
        self.__assert(loaded=False, locked=False)
        self.__set(loaded=True, locked=True)

    def save(self, path: str) -> bool:
        self.__assert(loaded=True, locked=True)

    def put(self, message: str) -> bool:
        self.__assert(loaded=False, locked=False)
        self.__set(loaded=True, locked=False)

    def lock(self, key: str, iterations: int = 100) -> bool:
        self.__assert(loaded=True, locked=False)
        self.__set(loaded=True, locked=True)

    def unlock(self, key: str, iterations: int = 100) -> bool:
        self.__assert(loaded=True, locked=True)
        if not self._verify(key, self.__key):
            return None
        self.__text = self._decrypt(key, self.__code)

    # Properties

    @property
    def key(self) -> Tuple[bool, str]:
        self.__assert(loaded=True, locked=False)
        return self.__key

    @property
    def iterations(self) -> int:
        self.__assert(loaded=True, locked=True)
        return self.__iterations

    @property
    def message(self) -> Tuple[bool, str]:
        self.__assert(loaded=True, locked=False)
        return self.__locked

    @property
    def state(self) -> bool:
        return dict(loaded=self.__loaded, locked=self.__locked)
