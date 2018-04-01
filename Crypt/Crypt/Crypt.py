from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import logging

MAX_MSG_LEN = 214 # determined manually for RSA2048 key, padding with PKCS1_OAEP
KEY_SIZE = 2048

class Crypt(object):

    def __init__(self, private_key=None, public_key=None):
        self._public_key = public_key
        self._private_key = private_key

    def generate_key(self):
        return RSA.generate(KEY_SIZE)

    def available(self):
        return not (self._public_key is None or self._private_key is None)

    def setPublicKey(self, publicKey):
        self._public_key = publicKey

    def sign_and_encrypt(self, data):
        cipher = PKCS1_OAEP.new(self._public_key)
        logging.debug("Signing with key %s" % self._private_key.publickey().exportKey(format="DER").encode('hex')[64:72])
        logging.debug("Encrypting with key %s" % self._public_key.exportKey(format="DER").encode('hex')[64:72])
        signature = pss.new(self._private_key).sign(SHA256.new(data))
        data = signature + data

        message = ""
        i = 0
        while i * MAX_MSG_LEN < len(data):
            message += cipher.encrypt(data[i * MAX_MSG_LEN : (i + 1) * MAX_MSG_LEN])
            i += 1

        return message

    # raises error if verification fails
    def decrypt_and_auth(self, message):
        logging.debug("Checking signature with key %s" % self._public_key.exportKey(format="DER").encode('hex')[64:72])
        logging.debug("Decrypting with key %s" % self._private_key.publickey().exportKey(format="DER").encode('hex')[64:72])

        cipher = PKCS1_OAEP.new(self._private_key)
        verifier = pss.new(self._public_key)
        chunk_size = KEY_SIZE / 8
        data = ""
        i = 0

        while chunk_size * i < len(message):
            chunk = message[i * chunk_size : (i + 1) * chunk_size]
            data += cipher.decrypt(chunk)
            i += 1

        verifier.verify(SHA256.new(data[256:]), data[:256])
        return data[256:]

def test():
    key1 = Crypt().generate_key()
    key2 = Crypt().generate_key()
    crypt1 = Crypt(key1, key2.publickey())
    crypt2 = Crypt(key2, key1.publickey())
    message = "this is a test"
    data = crypt1.sign_and_encrypt(message)
    if crypt2.decrypt_and_auth(data) == message:
        print "Test pass"
    else:
        raise TypeError('TEST DID NOT PASS')

if __name__ == '__main__':
    test()
