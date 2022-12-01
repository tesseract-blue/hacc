import secrets
from typing import Optional, Tuple, Dict
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
    def __init__(
        self, key: str = None, secret: str = None, level: int = 20, access: bool = False
    ) -> None:
        self.reset(key=key, secret=secret, level=level, access=access)

    # Initialization Reset Method

    def reset(
        self, key: str = None, secret: str = None, level: int = 20, access: bool = False
    ):
        self.__iterations: int = 2**level
        self.__access = access
        self.__key: Optional[str] = None
        self.__secret: Optional[str] = None
        self.__locked: bool = False
        self.__loaded: bool = False
        self.__fernet = Fernetool(self.__iterations)
        if secret is not None:
            self.store(secret)
        if key is not None:
            self.lock(key)

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

    def store(self, secret: Optional[str]) -> bool:
        self.__assert(loaded=False, locked=False)
        if secret is None:
            assert self.__secret is not None
        else:
            self.__secret = secret
        self.__set(loaded=True, locked=False)
        return True

    def lock(self, key: Optional[str] = None) -> bool:
        self.__assert(loaded=True, locked=False)
        if key is None:
            assert self.__key is not None
        else:
            self.__verify(key=key)
            self.__key = key
        self.__secret = self.__fernet.encrypt(key=self.__key, secret=self.__secret)
        self.__set(locked=True)
        return True

    def unlock(self, key: str) -> bool:
        self.__assert(loaded=True, locked=True)
        if self.__locked:
            if self.__compare(key, self.__key):
                self.__secret = self.__fernet.decrypt(key, self.__secret)
                self.__set(locked=False)
                return True
            else:
                return False

    # Properties

    @property
    def key(self) -> str:
        self.__assert(loaded=True)
        if not self.__access:
            self.__assert(locked=False)
        return self.__key

    @property
    def secret(self) -> str:
        self.__assert(loaded=True)
        return self.__secret

    @property
    def iterations(self) -> int:
        return self.__iterations

    @property
    def loaded(self) -> bool:
        return self.__loaded

    @property
    def locked(self) -> bool:
        return self.__locked
