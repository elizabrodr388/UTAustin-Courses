import sys
import sqlite3
import pandas as pd
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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

    # take each splashdata password
    with open('splashdata.txt', 'r') as f:
        com_pwd = []
        for line in f:
            print(line)
            com_pwd.append(line)
    
    # check to see if cracked password
    for common in com_pwd:
        for username in user_info:

            full_password = user_info[username]

            algo = full_password[ui_algorithm]
            iters = full_password[ui_iterations]
            salt = full_password[ui_salt]
            
            kdf = PBKDF2HMAC (
                algorithm = algo,
                length = 32,
                salt = salt,
                iterations = iters,
            )