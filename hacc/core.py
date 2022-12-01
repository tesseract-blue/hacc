import secrets
from typing import Optional, Tuple
from string import ascii_letters, digits
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Fernetool:
    def __init__(self, iterations: int) -> None:
        self.__iterations = iterations
        self.__backend = default_backend()
        self.__salt: bytes = secrets.token_bytes(16)

    def _derive(self, key: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.__salt,
            iterations=self.__iterations,
            backend=self.__backend,
        )
        return b64e(kdf.derive(key.encode()))

    def encrypt(self, key: str, secret: str) -> str:
        key = self._derive(key)
        return b64e(
            b"%b%b%b"
            % (
                self.__salt,
                self.__iterations.to_bytes(4, "big"),
                b64d(Fernet(key).encrypt(secret.encode())),
            )
        ).decode()

    def decrypt(self, key: str, secret: str) -> str:
        secret = b64d(secret.encode())
        _, iterations, secret = secret[:16], secret[16:20], b64e(secret[20:])
        iterations = int.from_bytes(iterations, "big")
        key = self._derive(key)
        return Fernet(key).decrypt(secret).decode()


class Crypt:
    def __init__(self, level: int = 1) -> None:
        self.reset(level=level)

    # Initialization Reset Method

    def reset(self, level: int = 1):
        self.__key: Optional[str] = None
        self.__secret: Optional[str] = None
        self.__locked: bool = False
        self.__loaded: bool = False
        self.__iterations: int = 2**level
        self.__fernet = Fernetool(self.__iterations)

    # Private Methods

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

    def __verify(self, key: str) -> None:
        assert (
            len(set(key).difference(set(ascii_letters + digits))) == 0
        ), "Your key must be made up of ascii letters and digits."

    # ! INTENTIONAL VULNERABILITY
    def __compare(self, A: str, B: str) -> bool:
        al, bl = len(A), len(B)
        for i in range(min(al, bl)):
            if A[i] != B[i]:
                return False
        if len(A) != len(B):
            return False
        return True

    # Public Methods

    def store(self, secret: str) -> None:
        self.__assert(loaded=False, locked=False)
        self.__secret = secret
        self.__set(loaded=True, locked=False)

    def lock(self, key: str) -> None:
        self.__assert(loaded=True, locked=False)
        self.__verify(key=key)
        self.__secret = self.__fernet.encrypt(key=key, secret=self.__secret)
        self.__set(loaded=True, locked=True)

    def unlock(self, key: str) -> None:
        self.__assert(loaded=True, locked=True)
        if self._verify(key, self.__key):
            self.__secret = self._decrypt(key, self.__secret)

    # Properties

    @property
    def key(self) -> Tuple[bool, str]:
        self.__assert(loaded=True, locked=False)
        return self.__key

    @property
    def message(self) -> Tuple[bool, str]:
        self.__assert(loaded=True, locked=False)
        return self.__secret

    @property
    def iterations(self) -> int:
        return self.__iterations

    @property
    def state(self) -> bool:
        return dict(loaded=self.__loaded, locked=self.__locked)
