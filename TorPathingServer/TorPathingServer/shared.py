import uuid
from Crypt import Crypt
from datetime import datetime

DER_KEY_SIZE = len(Crypt().generate_key().publickey().exportKey(format='DER'))
ROUTER_ID_SIZE = len(uuid.uuid4().bytes)
TIME_STR_SIZE = len(now_as_str())
ENC_PACKET_ROUTE_SIZE = 512

ROUTE_STRUCT_FMT = "!%ds4sI%ds8s16s" % (ENC_PACKET_ROUTE_SIZE, DER_KEY_SIZE)
HEARTBEAT_INTERVAL_SEC = 10

def now_as_str():
    return str(datetime.utcnow())

class MSG_TYPES(object):
    REGISTER_SERVER = chr(1)
    DEREGISTER_SERVER = chr(2)
    GET_ROUTE = chr(3)
    CLOSE = chr(4)
    REGISTER_DAEMON = chr(5)
    TEST_CONNECTION = chr(6)
    CONNECTION_TEST_RESULTS = chr(7)
