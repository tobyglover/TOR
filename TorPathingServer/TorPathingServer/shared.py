from Crypt import Crypt

DER_KEY_SIZE = len(Crypt().generate_key().publickey().exportKey(format='DER'))

class MSG_TYPES(object):
    REGISTER_SERVER = chr(1)
    DEREGISTER_SERVER = chr(2)
    GET_ROUTE = chr(3)
    CLOSE = chr(4)
