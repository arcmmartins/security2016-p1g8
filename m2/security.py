import base64

from Crypto.Random import random, new
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
import pyscrypt
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC
from utils import *
from termcolor import colored
import copy



class AESCipher(object):
    @staticmethod
    def pad(s):
        return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

    @staticmethod
    def unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    @staticmethod
    def encrypt(key, raw):
        raw = AESCipher.pad(raw)
        iv = new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    @staticmethod
    def decrypt(key, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return AESCipher.unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')


class RSACipher:
    @staticmethod
    def cipher(public_key, message):
        h = SHA256.new(message)
        cipher = PKCS1_v1_5.new(public_key)
        ciphertext = cipher.encrypt(message + h.digest())
        return base64.b64encode(ciphertext)

    @staticmethod
    def decipher(private, cipherb64):
        ciphertext = base64.b64decode(cipherb64)
        dsize = SHA256.digest_size
        sentinel = new().read(15 + dsize)
        cipher = PKCS1_v1_5.new(private)
        message = cipher.decrypt(ciphertext, sentinel)
        digest = SHA256.new(message[:-dsize]).digest()
        return message[:-dsize]


class Utils:

    @staticmethod
    def attach_HMAC(req, cipher, diffie_shared):
        obj = copy.deepcopy(req)
        if cipher == "NONE":
            return obj
        jsonfied = json.dumps(obj, sort_keys=True)
        (key_agr, asym, sym, hashm) = cipher.split("_")
        obj['sa_data'] ={
                "hmac": "",
                "salt": ""
        }
        mode = SHA256
        if hashm == 'SHA512':
            mode = SHA512

        salt = random.getrandbits(64)
        hashed = pyscrypt.hash(password=str(diffie_shared),
                                   salt=str(salt),
                                   N=1024,
                                   r=1,
                                   p=1,
                                   dkLen=32)
        obj['sa_data']['hmac'] = HMAC.new(key=str(hashed.encode('hex')), msg=jsonfied,
                                           digestmod=mode).hexdigest()
        obj['sa_data']['salt'] = salt
        return obj

    @staticmethod
    def validate_HMAC(obj, cipher, sa_data, diffie_shared):

        if cipher == "NONE":
            return obj
        jsonfied = json.dumps(obj, sort_keys=True)
        (key_agr, asym, sym, hashm) = cipher.split("_")
        mode = SHA256
        if hashm == 'SHA512':
            mode = SHA512
        hashed = pyscrypt.hash(password=str(diffie_shared),
                                   salt=str(sa_data['salt']),
                                   N=1024,
                                   r=1,
                                   p=1,
                                   dkLen=32)
        hmac = HMAC.new(key=str(hashed.encode('hex')), msg=jsonfied,
                            digestmod=mode).hexdigest()
        if hmac == sa_data["hmac"]:
            return True
        return False

    @staticmethod
    def cipher(cipher, pub_sym, diffie_shared, message):
        if cipher == "NONE":
            return message
        msg = {
            "aes": "",
            "key": ""
        }
        (key_agr, asym, sym, hashm) = cipher.split("_")

        leng = 8
        if sym == "AES256":
            leng = 16

        salt = random.getrandbits(64)
        hashed = pyscrypt.hash(password=str(random.getrandbits(32)),
                               salt=str(salt),
                               N=1024,
                               r=1,
                               p=1,
                               dkLen=leng)
        msg['aes'] = AESCipher.encrypt(key=str(hashed.encode('hex')), raw=json.dumps(message))
        if asym == "RSA":
            msg['key'] = RSACipher.cipher(RSA.importKey(pub_sym), str(hashed.encode('hex')))
        return json.dumps(msg)

    @staticmethod
    def decipher(cipher, priv_sym, diffie_shared, ciphered_json):
        jsn = json_loads_byteified(ciphered_json)
        if type(jsn) == str:  # va se la saber porque
            jsn = json_loads_byteified(jsn)
        if cipher == "NONE":
            return jsn
        (key_agr, asym, sym, hashm) = cipher.split("_")
        if asym == "RSA":
            aes_key = RSACipher.decipher(RSA.importKey(priv_sym), jsn['key'])
            aes = AESCipher.decrypt(aes_key, jsn['aes'])
            ret = json_loads_byteified(aes)
            if type(ret) is str:
                ret = json_loads_byteified(ret)
            return ret
