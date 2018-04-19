import uuid
from Crypt import Crypt

DER_KEY_SIZE = len(Crypt().generate_key().publickey().exportKey(format='DER'))
ENC_PACKET_ROUTE_SIZE = 512
ROUTE_STRUCT_FMT = "!%ds4sI%ds8s16s" % (ENC_PACKET_ROUTE_SIZE, DER_KEY_SIZE)
ROUTER_ID_SIZE = len(uuid.uuid4().bytes)
HEARTBEAT_INTERVAL_SEC = 10

class MSG_TYPES(object):
    REGISTER_SERVER = chr(1)
    DEREGISTER_SERVER = chr(2)
    GET_ROUTE = chr(3)
    CLOSE = chr(4)
    REGISTER_DAEMON = chr(5)
