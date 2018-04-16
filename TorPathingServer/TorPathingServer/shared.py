from Crypt import Crypt

DER_KEY_SIZE = len(Crypt().generate_key().publickey().exportKey(format='DER'))
ENC_PACKET_ROUTE_SIZE = 512
ROUTE_STRUCT_FMT = "!%ds4sI%ds8s16s" % (ENC_PACKET_ROUTE_SIZE, DER_KEY_SIZE)

class MSG_TYPES(object):
    REGISTER_SERVER = chr(1)
    DEREGISTER_SERVER = chr(2)
    GET_ROUTE = chr(3)
    CLOSE = chr(4)
