import uuid
from Crypt import Crypt
from datetime import datetime
import socket
from Crypto.PublicKey import RSA

def now_as_str():
    return str(datetime.utcnow())

def get_server_public_key():
    with open('public.pem','r') as f:
        return RSA.import_key(f.read())

DER_KEY_SIZE = len(Crypt().generate_key().publickey().exportKey(format='DER'))
ROUTER_ID_SIZE = len(uuid.uuid4().bytes)
TIME_STR_SIZE = len(now_as_str())
ENC_PACKET_ROUTE_SIZE = 512

ROUTE_STRUCT_FMT = "!%ds4sI%ds8s16s" % (ENC_PACKET_ROUTE_SIZE, DER_KEY_SIZE)
HEARTBEAT_INTERVAL_SEC = 10

class MSG_TYPES(object):
    REGISTER_SERVER = chr(1)
    DEREGISTER_SERVER = chr(2)
    GET_ROUTE = chr(3)
    CLOSE = chr(4)
    REGISTER_DAEMON = chr(5)
    TEST_CONNECTION = chr(6)
    CONNECTION_TEST_RESULTS = chr(7)


class Connection(object):
    def __init__(self, server_ip, server_port, private_key, server_pubkey=None):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((server_ip, server_port))
        if server_pubkey:
            self._crypt = Crypt(private_key, server_pubkey)
        else:
            self._crypt = Crypt(private_key, get_server_public_key())
        self._sendPublicKey(private_key)

    def __del__(self):
        self.close()

    def _sendPublicKey(self, private_key):
        self._socket.sendall(private_key.publickey().exportKey(format='DER'))

    def send(self, data):
        data = self._crypt.sign_and_encrypt(data)
        self._socket.sendall(data)

    def receive(self, size=1024):
        data = self._crypt.decrypt_and_auth(self._socket.recv(size))
        return data

    def close(self):
        if not self._socket is None:
            self.send(MSG_TYPES.CLOSE)
            self._socket.close()
            self._socket = None
