import os
from pathlib import Path
import random

from hashlib import sha256

rd = random.Random()

HOME_PATH = Path.home()
DATABASE_PATH = os.path.join(HOME_PATH, "passwords_idir_houari_msdsi")

for exercice in ["", "sha_256\\", "bcrypt\\"]:
    if not os.path.exists(DATABASE_PATH):
        os.makedirs(DATABASE_PATH+exercice)

CLEAR_PASSWORDS_PATH = os.path.join(DATABASE_PATH, "clear_passwords.json")

SHA_256_PATH = os.path.join(DATABASE_PATH, "SHA_256.json")

SHA_256_SALT_PATH = os.path.join(DATABASE_PATH, "SHA_256_salt.json")

SHA_256_INDIVIDUAL_SALT_PATH = os.path.join(DATABASE_PATH, "SHA_256_individual_salt.json")
SHA_256_INDIVIDUAL_SALT_DB_PATH = os.path.join(DATABASE_PATH, "SHA_256_individual_salt_db.json")

SHA_256_INDIVIDUAL_SALT_AES_PATH = os.path.join(DATABASE_PATH, "SHA_256_individual_salt_aes.json")
SHA_256_INDIVIDUAL_SALT_AES_DB_PATH = os.path.join(DATABASE_PATH, "SHA_256_individual_salt_aes_db.json")

BCRYPT_PATH = os.path.join(DATABASE_PATH, "bcrypt.json")

BCRYPT_SALT_PATH = os.path.join(DATABASE_PATH, "bcrypt_salt.json")

BCRYPT_INDIVIDUAL_SALT_PATH = os.path.join(DATABASE_PATH, "bcrypt_individual_salt.json")
BCRYPT_INDIVIDUAL_SALT_DB_PATH = os.path.join(DATABASE_PATH, "bcrypt_individual_salt_db.json")

SALT_SEQUENCE_SHA_256 = "9309d9b6-f0c4-f8c1-de5f-9df0fdbd5425"
SALT_SEQUENCE_BCRYPT = b'$2b$12$L3xeUQn.SVU0gbfrjZMNf.'

AES_SECRET_KEY = b'\x8f!\x9d)\xfaT\xc7\xbc\xe6\xd3kF\x84\xa9\x02\x84rn\xb74\xba\xac\x11\xdf\xd2\x16\x02\xd1\r{\nF'
