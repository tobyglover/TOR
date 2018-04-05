from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import struct
import logging

MAX_MSG_LEN = 214 # determined manually for RSA2048 key, padding with PKCS1_OAEP
KEY_SIZE = 2048

class Crypt(object):

    def __init__(self, private_key=None, public_key=None, name='', debug=False):
        self._public_key = public_key
        self._private_key = private_key
        self._name = name
        self._debug = debug

    def log(self, message):
        if self._debug:
            logging.debug(message)

    def generate_key(self):
        return RSA.generate(KEY_SIZE)

    def available(self):
        return not (self._public_key is None or self._private_key is None)

    def setPublicKey(self, publicKey):
        self._public_key = publicKey

    def sign_and_encrypt(self, data):
        cipher = PKCS1_OAEP.new(self._public_key)
        self.log("Signing with own key %s" % self._private_key.publickey().exportKey(format="DER").encode('hex')[66:74])
        self.log("Encrypting with %s's key %s" % (self._name, self._public_key.exportKey(format="DER").encode('hex')[66:74]))
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
        self.log("Checking signature with %s's key %s" % (self._name, self._public_key.exportKey(format="DER").encode('hex')[66:74]))
        self.log("Decrypting with own key %s" % self._private_key.publickey().exportKey(format="DER").encode('hex')[66:74])

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


class BadSID(Exception):
    pass


class MACMismatch(Exception):
    pass


class Symmetric(object):
    CRYPT_HEADER_LEN = 16 * 5
    STATUS_OK = "OKOK"
    STATUS_EXIT = "EXIT"

    def __init__(self, key, sid="\00"*8):
        self.raw_key = key
        self.sid = sid
        self.key = None
        self.salt = None
        self.head_nonce = None
        self.head_tag = None
        self.body_nonce = None
        self.body_tag = None

    def absorb_crypto_header(self, header):
        """Absorbs the cryptographic information in the crypto header

        Args:
            header (str): 80B cryptographic header
        """
        self.salt, self.head_tag, self.head_nonce, self.body_tag, self.body_nonce \
            = [header[i:i+16] for i in range(0, 16 * 5, 16)]

    def decrypt_header(self, header):
        """Decrypts and authenticates the packet header

        Args:
            header (str): 16B header

        Returns:
            (int, str): number of 16B chunks to come and status message

        Raises:
            MACMismatch: data authentication failed
            BadSID: SID doesn't match
        """
        key = PBKDF2(self.raw_key, self.salt)
        cipher = AES.new(key, AES.MODE_GCM, self.head_nonce)

        cipher.update(self.sid)
        try:
            header = cipher.decrypt_and_verify(header, self.head_tag)
        except ValueError:
            raise MACMismatch
        num_chunks, status, sid = struct.unpack("!L4s8s", header)

        if self.sid != sid:
            raise BadSID

        return num_chunks, status

    def decrypt_body(self, data):
        """Decrypts and authenticates the packet header

        Args:
            data (str): data (multiple of 16B)

        Returns:
            str: decrypted and authenticated data

        Raises:
            MACMismatch: data authentication failed
        """
        key = PBKDF2(self.raw_key, self.salt)
        cipher = AES.new(key, AES.MODE_GCM, self.body_nonce)

        cipher.update(self.sid)
        try:
            return cipher.decrypt_and_verify(data, self.body_tag)
        except ValueError:
            raise MACMismatch

    def encrypt_payload(self, data, status):
        """Encrypts and data and formats into packet

        Args:
            data (str): data to encrypt
            status (str): 4B status string

        Returns:
            str: encrypted data
        """
        # encrypt body
        salt = get_random_bytes(16)
        key = PBKDF2(self.raw_key, salt)
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.update(self.sid)
        ct, body_tag = cipher.encrypt_and_digest(data)
        body_nonce = cipher.nonce

        # build header
        num_chuks = len(ct) / 16
        header = struct.pack("!L4s8s", num_chuks, status, self.sid)

        # encrypt header
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.update(self.sid)
        header, head_tag = cipher.encrypt_and_digest(header)
        head_nonce = cipher.nonce

        crypto_head = salt + head_tag + head_nonce + body_tag + body_nonce
        return crypto_head + header + ct


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


def test_sym():
    key = get_random_bytes(16)
    sid = "12345678"
    message = "This is the example message! " * 29
    status = "OKOK"
    c1 = Symmetric(key, sid)

    packet = c1.encrypt_payload(message, status)

    c2 = Symmetric(key, sid)
    c2.absorb_crypto_header(packet[:c2.CRYPT_HEADER_LEN])

    print c2.decrypt_header(packet[c2.CRYPT_HEADER_LEN:c2.CRYPT_HEADER_LEN+16])
    print c2.decrypt_body(packet[c2.CRYPT_HEADER_LEN+16:])


if __name__ == '__main__':
    test_sym()
