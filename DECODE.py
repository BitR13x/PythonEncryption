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

def decrypt_func(ENCRYPTED, password):
    BLOCK_SIZE = 32
    unpad = lambda s: s[:-ord(s[len(s) - 1:])]

    ENCRYPTED = base64.b64decode(ENCRYPTED)
    iv = ENCRYPTED[:16]
    key = get_key(password)

    mode = AES.MODE_CBC
    cipher = AES.new(key, mode, iv)

    return unpad(cipher.decrypt(ENCRYPTED[16:]))

if __name__ == "__main__":
    if sys.argv[1]:
        passwd = getpass("Password: ")

        filename = sys.argv[1]
        with open(filename, "r") as temp:
            source = temp.read()
        system(f"rm {filename}")

        filename = filename.split("_e")[0] + filename.split("_e")[1]
        with open(filename, "w") as de_file:
            de_file.write(decrypt_func(source, passwd).decode("utf8"))
    else:
        print("File not specified")
