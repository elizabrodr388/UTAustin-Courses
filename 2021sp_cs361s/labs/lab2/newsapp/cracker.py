import sys
import sqlite3
import pandas as pd
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib

# if there is no arguments
if len(sys.argv) == 1:

    # indices for user_info value (password)
    ui_algorithm = 0
    ui_iterations = 1
    ui_salt = 2
    ui_hash = 3

    # open the sqllite3 database
    con = sqlite3.connect('db.sqlite3')
    cur = con.cursor()

    # extract all of the stored passwords hashes from db into dict
    user_info = {}
    for row in cur.execute('SELECT * from auth_user;'):
        user_info[row[4]] = row[1].split("$")

    con.close()

    # list of common passwords
    com_pwd = [
    "123456",
    "123456789",
    "qwerty",
    "password",
    "1234567",
    "12345678",
    "12345",
    "iloveyou",
    "111111",
    "123123",
    "abc123",
    "qwerty123",
    "1q2w3e4r",
    "admin",
    "qwertyuiop",
    "654321",
    "555555",
    "lovely",
    "7777777",
    "welcome",
    "888888",
    "princess",
    "dragon",
    "password1",
    "123qwe"]
    
    # check to see if cracked password
    for common in com_pwd:
        for username in user_info:

            full_password = user_info[username]

            algo = full_password[ui_algorithm]
            iters = int(full_password[ui_iterations])
            salt = str.encode(full_password[ui_salt])
            h = str.encode(full_password[ui_hash])
            
            if algo == "pbkdf2_sha256":
                kdf = PBKDF2HMAC (
                    algorithm = hashes.SHA256(),
                    length = 32,
                    salt = salt,
                    iterations = iters,
                )

                b_key = kdf.derive(str.encode(common)) # bytes
                key = base64.b64encode(b_key)

                if h == key:
                    print(str(username) + "," + str(common))

                # print("COMMON PASSWORD HASH  : " + str(key))
                # print("USER PASSWORD HASH    : " + str(h))
                # print("\n")