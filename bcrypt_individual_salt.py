import os
import bcrypt

from constants import BCRYPT_INDIVIDUAL_SALT_PATH, BCRYPT_INDIVIDUAL_SALT_DB_PATH
from db_handler import load_db, save_db

if os.path.exists(BCRYPT_INDIVIDUAL_SALT_PATH):
    LOGINS = load_db(BCRYPT_INDIVIDUAL_SALT_PATH)
else:
    LOGINS = {}

if os.path.exists(BCRYPT_INDIVIDUAL_SALT_DB_PATH):
    SALTS = load_db(BCRYPT_INDIVIDUAL_SALT_DB_PATH)
else:
    SALTS = {}


def hash_password(pw: str, salt=None):
    """
    Hashing function for a password using a random unique salt.
    """
    if not salt:
        salt = bcrypt.gensalt()
    else:
        salt = salt.encode()

    hashed_password = str(bcrypt.hashpw(pw.encode(), salt))
    return hashed_password, salt.decode()


def register_bcrypt_individual_salt(user=None, pw=None):
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

    LOGINS[user_id] = hashed_password
    SALTS[user_id] = salt

    save_db(BCRYPT_INDIVIDUAL_SALT_PATH, LOGINS)
    save_db(BCRYPT_INDIVIDUAL_SALT_DB_PATH, SALTS)
    print(f"New user {user_id} saved successfully !")


def login_bcrypt_individual_salt(user=None, pw=None):
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
    password_hashed, _ = hash_password(password, SALTS[user_id])
    while password_hashed not in LOGINS[user_id]:
        tries -= 1
        if tries == 0:
            raise Exception("Too many tries, this device will autodestroy in 3, 2, 1 ... boom")
        print(f"Wrong password ! You have {tries} tries left, please retry.")
        password = input("Password: ")
        password_hashed, _ = hash_password(password, SALTS[user_id])

    print(f"Logged in successfully, welcome back {user_id} !")


if __name__ == '__main__':
        
    if not LOGINS:
        print("No users registered yet, you are the first one !")
        register_bcrypt_individual_salt()
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
            register_bcrypt_individual_salt()
    
        if login_or_register == "2":
            login_bcrypt_individual_salt()
    
    
    print(f"All users can be found in folder : {BCRYPT_INDIVIDUAL_SALT_PATH}")
