from Crypto.PublicKey import RSA
import sys
sys.path.append('../../shared')
from Crypt import KEY_SIZE

DER_KEY_SIZE = len(RSA.generate(KEY_SIZE).publickey().exportKey(format='DER'))

class MSG_TYPES(object):
    REGISTER_SERVER = chr(1)
    DEREGISTER_SERVER = chr(2)
    GET_ROUTE = chr(3)
    CLOSE = chr(4)
