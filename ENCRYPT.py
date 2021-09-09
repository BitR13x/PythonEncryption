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
    #passwd = encrypt_func("hello", "anon")
    #print("PASSWORD:",passwd)
    #print("DECRYPTED:",decrypt_func(passwd, "anon").decode("utf8"))

    # encrypt
    if sys.argv[1]:
        filename = sys.argv[1]
        passwd = getpass("Password: ")
        with open( str(filename), "r") as temp:
            source = temp.read()
        system(f"rm {filename}")

        try:
            filename = filename.split(".")[0] + "_e." + filename.split(".")[1]
        except IndexError:
            filename = filename.split(".")[0] + "_e"

        with open(filename, "w") as en_file:
            en_file.write( encrypt_func(source, passwd ).decode("utf8") )
    else:
        print("File not specified")
