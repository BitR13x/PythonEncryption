#!/usr/bin/python3
import base64
import sys
from os import system
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from getpass import getpass

def get_key(password):
    salt = password.encode("utf8")
    kdf = PBKDF2(password, salt, 64, 1000)
    key = kdf[:32]
    return key

def encrypt_func(plain_text, password):
   #encode salt
    BLOCK_SIZE = 32
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
    key = get_key(password)

    plain_text = pad(plain_text)
    IV = Random.new().read(AES.block_size)
    mode = AES.MODE_CBC
    cipher = AES.new(key, mode, IV=IV)

    return base64.b64encode(IV + cipher.encrypt(plain_text.encode("utf8")))


if __name__ == "__main__":
    #USAGE FOR FUNCTIONS:
    #passwd = encrypt_func("hello", "anon")
    #print("PASSWORD:",passwd)
    #print("DECRYPTED:",decrypt_func(passwd, "anon").decode("utf8"))

    # encrypt
    if sys.argv[1]:
        file_path = sys.argv[1]
        passwd = getpass("Password: ")
        passwd2 = getpass("Repeat password: ")
        if passwd != passwd2:
            print("Passwords not match")
            exit()

        with open( str(file_path), "r") as temp:
            source = temp.read()

        if "/" in file_path:
            filename = file_path.split("/").pop()
            filename = filename.split(".")[0] + "_e." + filename.split(".")[1]
            file_location = file_path.split("/")
            file_location[-1] = ""
            file_location = "/".join(file_location) + filename
        else:
            try:
                file_location = file_path.split(".")[0] + "_e." + file_path.split(".")[1]
            except IndexError:
                file_location = file_path.split(".")[0] + "_e"
                
        # filename = /path/path/gweagw.py
        with open(file_location, "w") as en_file:
            en_file.write( encrypt_func(source, passwd ).decode("utf8") )

        print("Saved as %s" % (file_location))
        system(f"rm {sys.argv[1]}")

    else:
        print("Usage: " + str(__file__) + " <file/file_path>")
        print("File not specified")
