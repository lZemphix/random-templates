import hashlib
import os

def hash_password(password: str) -> tuple[str, str]:
    salt = os.urandom(32)
    hashed_password = hashlib.sha256(salt + password.encode()).hexdigest()
    return hashed_password, salt.hex()


def authorization(password: str, salt: str, hashed_password: str) -> bool:
    result = hashlib.sha256(bytes.fromhex(salt) + password.encode()).hexdigest()
    if result == hashed_password:
        print('Correct password!')
        return True
    else:
        print('Incorrect password')
        return False

password = "some_password"
password_hash, salt = hash_password(password)

authorization(password, salt, password_hash)

