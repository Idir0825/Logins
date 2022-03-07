"""
To time the functions the databases need to be empty as some users are created systematically by this file
"""
import uuid
import time
import matplotlib.pyplot as plt

from clear_passwords import login_clear as clear_login
from sha_256 import login_sha_256 as sha_256_login
from sha_256_salt import login_sha_256_salt as sha_256_salt_login
from sha_256_individual_salt import login_sha_256_ind_salt as sha_256_individual_salt_login
from sha_256_individual_salt_aes import login_sha_256_ind_salt_aes as sha_256_individual_salt_aes_login
from bcrypt_salt import login_bcrypt_salt as bcrypt_salt_login
from bcrypt_individual_salt import login_bcrypt_individual_salt as bcrypt_individual_salt_login

from clear_passwords import register_clear as clear_register
from sha_256 import register_sha_256 as sha_256_register
from sha_256_salt import register_sha_256_salt as sha_256_salt_register
from sha_256_individual_salt import register_sha_256_ind_salt as sha_256_individual_salt_register
from sha_256_individual_salt_aes import register_sha_256_ind_salt_aes as sha_256_individual_salt_aes_register
from bcrypt_salt import register_bcrypt_salt as bcrypt_salt_register
from bcrypt_individual_salt import register_bcrypt_individual_salt as bcrypt_individual_salt_register


LOGINS_TO_TEST = [clear_login,
                  sha_256_login,
                  sha_256_salt_login,
                  sha_256_individual_salt_login,
                  sha_256_individual_salt_aes_login,
                  bcrypt_salt_login,
                  bcrypt_individual_salt_login]

REGISTERS_TO_TEST = [clear_register,
                     sha_256_register,
                     sha_256_salt_register,
                     sha_256_individual_salt_register,
                     sha_256_individual_salt_aes_register,
                     bcrypt_salt_register,
                     bcrypt_individual_salt_register]

ALGORITHMS_NAMES = ["clear",
                    "sha_256",
                    "sha_256_salt",
                    "sha_256_ind_salt",
                    "shat_256_ind_salt_aes",
                    "bcrypt_salt",
                    "brcypt_ind_salt"]

LOGINS_TIMES = []

REGISTERS_TIMES = []


def time_function(func, nb_pw, user, pw):
    """
    Calculates the time it takes to use the function

    :param func: the function to test
    :param nb_pw: the number of passwords to test
    :param user: the user to save/load
    :param pw: the password of the user
    :return: the time it took to use the function on all the passwords
    """
    start_time = time.perf_counter()

    for n in range(0, nb_pw):
        print(f"Starting {func.__name__}")
        func(user + f"{n}", pw + f"{n}")
        print()

    end_time = time.perf_counter()
    total_time = end_time - start_time
    return total_time


def time_all_functions(number_of_passwords_to_test):
    """
    Times all the function on with different numbers of passwords

    :param number_of_passwords_to_test: (int) The maximum number of passwords to test
    """
    for reg, log in zip(REGISTERS_TO_TEST[:-2], LOGINS_TO_TEST[:-2]):
        reg_times = []
        log_times = []
        for nb_passwords in range(1, number_of_passwords_to_test+1):
            user = str(uuid.uuid4())
            pw = str(uuid.uuid4())
            reg_time = time_function(reg, nb_passwords, user, pw)
            reg_times.append(reg_time)
            log_time = time_function(log, nb_passwords, user, pw)
            log_times.append(log_time)
        REGISTERS_TIMES.append(reg_times)
        LOGINS_TIMES.append(log_times)


number_of_passwords = 30
time_all_functions(number_of_passwords)

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 10))

for r_time in REGISTERS_TIMES:
    ax1.plot(range(1, number_of_passwords+1), r_time)
ax1.legend(ALGORITHMS_NAMES[:-2])
ax1.set_xlabel("Number of passwords")
ax1.set_ylabel("Time to perform operations (s)")
ax1.set_title("Performance of each algorithm to register")
#ax1.set_yscale("log")


for l_time in LOGINS_TIMES:
    ax2.plot(range(1, number_of_passwords+1), l_time)
ax2.legend(ALGORITHMS_NAMES[:-2])
ax2.set_xlabel("Number of passwords")
ax2.set_ylabel("Time to perform operations (s)")
ax2.set_title("Performance of each algorithm to login ")
#ax2.set_yscale("log")

plt.show()
fig.tight_layout()
