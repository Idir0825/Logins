import os
import uuid
from hashlib import sha256
import base64
from Crypto.Cipher import AES
from Crypto import Random

from constants import SHA_256_INDIVIDUAL_SALT_AES_PATH, SHA_256_INDIVIDUAL_SALT_AES_DB_PATH, AES_SECRET_KEY
from db_handler import load_db, save_db

if os.path.exists(SHA_256_INDIVIDUAL_SALT_AES_PATH):
    LOGINS = load_db(SHA_256_INDIVIDUAL_SALT_AES_PATH)
else:
    LOGINS = {}

if os.path.exists(SHA_256_INDIVIDUAL_SALT_AES_DB_PATH):
    SALTS = load_db(SHA_256_INDIVIDUAL_SALT_AES_DB_PATH)
else:
    SALTS = {}

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
# Divise le message en block de 16 bytes et ajoute des 0 à la fin s'il en manque
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


def encrypt(raw):
    private_key = AES_SECRET_KEY
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    encrypted = base64.b64encode(iv + cipher.encrypt(raw.encode())).decode()
    return encrypted

print("Nikoumouk")
print("flo")


def decrypt(enc):
    private_key = AES_SECRET_KEY
    enc = enc.encode()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    unpadded = unpad(cipher.decrypt(enc[16:]))
    decrypted = bytes.decode(unpadded)
    return decrypted


def hash_password(pw: str, salt=None):
    """
    Hashing function for a password using a random unique salt.
    """
    if not salt:
        salt = str(uuid.uuid4())

    hashed_password = sha256(salt.encode() + pw.encode()).hexdigest() + ':' + salt
    return hashed_password, salt


def register_sha_256_ind_salt_aes(user=None, pw=None):
    user_id = user if user else input("Please enter your new user id: ")
    while user_id in LOGINS.keys():
        print("This user id is already used, please select another one...")
        user_id = input("Please enter your new user id: ")

    password_one = pw if pw else input("Create your password: ")
    password_two = pw if pw else input("Confirm your password: ")
    while password_two != password_one:
        print(f"{user_id} your passwords should be the same, please retry.")
        password_one = input("Enter your password: ")
        password_two = input("Confirm your password: ")

    hashed_password, salt = hash_password(password_two)
    encrypted_pw = encrypt(hashed_password)

    LOGINS[user_id] = encrypted_pw
    SALTS[user_id] = salt

    save_db(SHA_256_INDIVIDUAL_SALT_AES_PATH, LOGINS)
    save_db(SHA_256_INDIVIDUAL_SALT_AES_DB_PATH, SALTS)
    print(f"New user {user_id} saved successfully !")


def login_sha_256_ind_salt_aes(user=None, pw=None):
    user_exists = False
    user_id = user if user else input("Please enter your user id: ")

    if user_id in LOGINS.keys():
        user_exists = True

    while not user_exists:
        user_id = input("Your user id does not exist, please enter a valid one: ")
        if user_id in LOGINS.keys():
            user_exists = True

    tries = 2
    password = pw if pw else input("Password: ")
    hashed_password, salt = hash_password(password, SALTS[user_id])
    crypted_user_pw = LOGINS[user_id]
    
    while hashed_password != decrypt(crypted_user_pw):
        print(f"Stored pw : {decrypt(LOGINS[user_id])}")
        print(f"Hashed pw : {hashed_password}")
        tries -= 1
        if tries == 0:
            raise Exception("Too many tries, this device will autodestroy in 3, 2, 1 ... boom")
        print(f"Wrong password ! You have {tries} tries left, please retry.")
        password = input("Password: ")
        hashed_password, salt = hash_password(password, SALTS[user_id])

    print(f"Logged in successfully, welcome back {user_id} !")


if __name__ == '__main__':

    if not LOGINS:
        print("No users registered yet, you are the first one !")
        register_sha_256_ind_salt_aes()
    else:
        login_or_register = input("Do you want to register (press 1) or login (press 2) ? (press q to quit)")
        if login_or_register == "q":
            exit()

        while login_or_register not in ["1", "2"]:
            print("Your answer should be either 1 or 2 !")
            login_or_register = input("Do you want to register (press 1) or login (press 2) ? (press q to quit)")
            if login_or_register == "q":
                exit()

        if login_or_register == "1":
            register_sha_256_ind_salt_aes()

        if login_or_register == "2":
            login_sha_256_ind_salt_aes()

    print(f"All users can be found in folder : {SHA_256_INDIVIDUAL_SALT_AES_PATH}")
