import base64

from Crypto.Random import random, new
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
import pyscrypt
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC
from utils import *





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
    def cipher(cipher, pub_sym, diffie_shared, message):
        if cipher == "NONE":
            return message
        msg = {
            "aes": "",
            "key": "",
            "hmac_key": {
                "hmac": "",
                "salt": ""
            },
            "hmac_aes": {
                "hmac": "",
                "salt": ""
            }
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
        msg['aes'] = AESCipher.encrypt(key=str(hashed.encode('hex')), raw=message)
        if asym == "RSA":
            msg['key'] = RSACipher.cipher(RSA.importKey(pub_sym), str(hashed.encode('hex')))
        mode = SHA256
        if hashm == 'SHA512':
            mode = SHA512

        salt_key = random.getrandbits(64)
        hashed_key = pyscrypt.hash(password=str(diffie_shared),
                                   salt=str(salt_key),
                                   N=1024,
                                   r=1,
                                   p=1,
                                   dkLen=32)
        msg['hmac_key']['hmac'] = HMAC.new(key=str(hashed_key.encode('hex')), msg=msg['key'],
                                           digestmod=mode).hexdigest()
        msg['hmac_key']['salt'] = salt_key

        salt_aes = random.getrandbits(64)
        hashed_aes = pyscrypt.hash(password=str(diffie_shared),
                                   salt=str(salt_aes),
                                   N=1024,
                                   r=1,
                                   p=1,
                                   dkLen=32)
        msg['hmac_aes']['hmac'] = HMAC.new(key=str(hashed_aes.encode('hex')), msg=msg['aes'],
                                           digestmod=mode).hexdigest()
        msg['hmac_aes']['salt'] = salt_aes
        return json.dumps(msg)

    @staticmethod
    def decipher(cipher, priv_sym, diffie_shared, ciphered_json):
        jsn = json_loads_byteified(ciphered_json)
        if type(jsn) == str:  # va se la saber porque
            jsn = json_loads_byteified(jsn)

        if cipher == "NONE":
            return jsn
        (key_agr, asym, sym, hashm) = cipher.split("_")
        mode = SHA256
        if hashm == 'SHA512':
            mode = SHA512

        hashed_aes = pyscrypt.hash(password=str(diffie_shared),
                                   salt=str(jsn['hmac_aes']['salt']),
                                   N=1024,
                                   r=1,
                                   p=1,
                                   dkLen=32)


        hmac_aes = HMAC.new(key=str(hashed_aes.encode('hex')), msg=jsn['aes'],
                            digestmod=mode).hexdigest()

        hashed_key = pyscrypt.hash(password=str(diffie_shared),
                                   salt=str(jsn['hmac_key']['salt']),
                                   N=1024,
                                   r=1,
                                   p=1,
                                   dkLen=32)
        hmac_key = HMAC.new(key=str(hashed_key.encode('hex')), msg=jsn['key'],
                            digestmod=mode).hexdigest()
        if asym == "RSA":
            if hmac_aes == jsn['hmac_aes']['hmac'] and hmac_key == jsn['hmac_key']['hmac']:
                aes_key = RSACipher.decipher(RSA.importKey(priv_sym), jsn['key'])
                aes = AESCipher.decrypt(aes_key, jsn['aes'])
                return json_loads_byteified(aes)
