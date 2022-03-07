import os
from hashlib import sha256

from constants import SHA_256_SALT_PATH, SALT_SEQUENCE_SHA_256
from db_handler import load_db, save_db


if os.path.exists(SHA_256_SALT_PATH):
    LOGINS = load_db(SHA_256_SALT_PATH)
else:
    LOGINS = {}


def hash_password(pw):
    """
        Basic hashing function for a text using random unique salt.
    """
    return sha256(SALT_SEQUENCE_SHA_256.encode() + pw.encode()).hexdigest() + ':' + SALT_SEQUENCE_SHA_256


def register_sha_256_salt(user=None, pw=None):
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

    LOGINS[user_id] = hash_password(password_two)
    save_db(SHA_256_SALT_PATH, LOGINS)
    print(f"New user {user_id} saved successfully !")


def login_sha_256_salt(user=None, pw=None):
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
    password_hashed = hash_password(password)
    while password_hashed not in LOGINS[user_id]:
        tries -= 1
        if tries == 0:
            raise Exception("Too many tries, this device will autodestroy in 3, 2, 1 ... boom")
        print(f"Wrong password ! You have {tries} tries left, please retry.")
        password = input("Password: ")
        password_hashed = hash_password(password)

    print(f"Logged in successfully, welcome back {user_id} !")


if __name__ == '__main__':

    if not LOGINS:
        print("No users registered yet, you are the first one !")
        register_sha_256_salt()
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
            register_sha_256_salt()

        if login_or_register == "2":
            login_sha_256_salt()


    print(f"All users can be found in folder : {SHA_256_SALT_PATH}")
