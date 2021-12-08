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
        
        file_path = sys.argv[1]
        with open(file_path, "r") as temp:
            source = temp.read()

        if "/" in file_path:
            filename = file_path.split("/").pop()
            filename = filename.split("_e")[0] + filename.split("_e")[1]
            file_location = file_path.split("/")
            file_location[-1] = ""
            file_location = "/".join(file_location) + filename
        else:
            file_location = file_path.split("_e")[0] + file_path.split("_e")[1]
            
        with open(file_location, "w") as de_file:
            if len(decrypt_func(source, passwd).decode("utf8")) == 0:
                print("Wrong password")
            else:
                print("\nExtracting[*]")
                de_file.write(decrypt_func(source, passwd).decode("utf8"))
                system(f"rm {sys.argv[1]}")
                print("Extracted in %s" % (file_location))
    else:
        print("Usage: " + str(__file__) + " <file/file_path>")
        print("File not specified")
