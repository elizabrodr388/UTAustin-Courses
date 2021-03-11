import sys
import sqlite3
import pandas as pd
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib

# indices for user_info value (password)
ui_algorithm = 0
ui_iterations = 1
ui_salt = 2
ui_hash = 3

def main ():
    # if there is no arguments
    if len(sys.argv) == 1:

        #print("in top")

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

    elif len(sys.argv) > 1:
        
        full_password = (sys.argv[1]).split("$")
        algo = full_password[ui_algorithm]
        iters = int(full_password[ui_iterations])
        salt = str.encode(full_password[ui_salt])
        h = str.encode(full_password[ui_hash])

        if iters != 1:
            print("Cannot brute-force password in time.")

        else:
            alpha = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 
            'm', 'n', 'o', 'p' 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

            cont = True
            for a1 in alpha:
                if not cont: break
                c1 = a1
                cont = checkPassword(c1, algo, iters, salt, h)

                for a2 in alpha:
                    if not cont: break
                    c2 = c1 + a2
                    cont = checkPassword(c2, algo, iters, salt, h)

                    for a3 in alpha:
                        if not cont: break
                        c3 = c2 + a3
                        cont = checkPassword(c3, algo, iters, salt, h)

                        for a4 in alpha:
                            if not cont: break
                            c4 = c3 + a4
                            cont = checkPassword(c4, algo, iters, salt, h)

def checkPassword (my_str, algo, iters, salt, h):
    
    if algo == "pbkdf2_sha256":

        kdf = PBKDF2HMAC (
            algorithm = hashes.SHA256(),
            length = 32,
            salt = salt,
            iterations = iters,
        )

        b_key = kdf.derive(str.encode(my_str))
        key = base64.b64encode(b_key)

        # print(str(h))
        # print(str(key))

        if h == key:
            print("Password cracked: \'" + my_str + "\'")
            return False

        return True

main ()