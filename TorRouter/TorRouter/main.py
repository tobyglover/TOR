"""
Allen Zhou, Ben Janis
COMP112
TOR router
3/19/18
"""
import socket
from socket import timeout
from SocketServer import TCPServer, BaseRequestHandler
import argparse
from Crypto.PublicKey import RSA
from TorPathingServer import TORPathingServer
from Crypt import Crypt
import logging
import sys
from CircuitDatabase import CircuitDatabase, CircuitNotFound, BadMethod
from Circuit import PFCircuit, ClientCircuit

router_logger = logging.getLogger("TorRouter")
router_logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
router_logger.addHandler(ch)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pip", help="IP address of Tor pathfinding server")
    parser.add_argument("pport", type=int, help="IP address of Tor pathfinding server")
    parser.add_argument("pubkey", help="Path to pathfinding server public key")
    parser.add_argument("--cdb", help="Path to the Circuit Database")
    parser.add_argument("--port", type=int, help="Port to bind to", default=0)
    args = parser.parse_args()
    return args.pip, args.pport, args.pubkey, args.cdb, args.port


class CustomTCPServer(TCPServer, object):
    def __init__(self, server_address, cdb, raw_pubkey, request_handler):
        router_logger.info("Setting up server...")
        super(CustomTCPServer, self).__init__(server_address, request_handler)
        self.key = Crypt().generate_key()
        self.crypt = Crypt(self.key, debug=True)
        self.cdb = CircuitDatabase(db_path=cdb, rid='\x00' * 8, raw_pubkey=raw_pubkey)
        router_logger.info("Server running")


class MyTCPHandler(BaseRequestHandler):
    CT_BLOCK_SIZE = 256
    HEADER_SIZE = CT_BLOCK_SIZE * 2
    DER_LEN = len(Crypt().generate_key().publickey().exportKey(format='DER'))

    def setup(self):
        router_logger.info("Setting up TCPHandler")
        self.exit = False
        self.next_sock = None
        self.client_crypt = None
        self.prev_crypt = None
        self.next_crypt = None

    def pull(self, sock, length):
        message = ''
        while len(message) < length:
            message += sock.recv(length - len(message))
        return message

    def handle(self):
        router_logger.info('handling connection from %s:%s' % self.client_address)

        router_logger.debug("Waiting for header...")
        header = self.pull(self.request, self.HEADER_SIZE)
        router_logger.debug("Pulled header (%dB) %s" %
                            (len(header), repr(header.encode('hex')[:8])))

        try:
            method, circ = self.server.cdb.get(header, self.server.crypt)
        except BadMethod:
            e = sys.exc_info()
            raise e[0], e[1], e[2]

        if method == self.server.cdb.ESTB:
            router_logger.info("Building circuit")
            circ.build_circuit(self.request)
            self.server.cdb.add(circ)
        else:
            router_logger.info("Handling request")
            circ.forward_payload(self.request)
            router_logger.info("Sucessfully returned request")

    def make_next_hop(self, next_hop, data):
        router_logger.info("Sending establishment circuit to next router")
        self.next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.next_sock.connect(next_hop)
        self.next_sock.sendall(data)

    def forward_payload(self):
        router_logger.info('Waiting for payload to forward...')
        header = self.pull(self.request, self.HEADER_SIZE)
        router_logger.info('Received header of payload (%dB)' % len(header))
        header = self.client_crypt.decrypt_and_auth(header)

        if self.exit:
            num_chunks, ip, port = header.split(":")
            if ip == "CLOSE":
                router_logger.info("Closing circuit")
                return False
            close = "OK"
            router_logger.info("Sending payload to %s:%s" % (ip, port))
            self.next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.next_sock.connect((ip, int(port)))
        else:
            num_chunks, close = header.split(":")

        data = self.pull(self.request, self.CT_BLOCK_SIZE * int(num_chunks))
        data = self.client_crypt.decrypt_and_auth(data)
        if close == "CLOSE":
            router_logger.info("Closing circuit")
            self.next_sock.sendall(data)
            return False
        router_logger.info("Forwarding payload (%dB)" % len(data))
        self.next_sock.sendall(data)
        return True

    def forward_response(self):
        if self.exit:
            router_logger.info("Getting response from website...")
            chunk = 'asdf'
            payload = ''
            self.next_sock.settimeout(1)
            while len(chunk) > 0:
                try:
                    chunk = self.next_sock.recv(1024)
                except timeout:
                    chunk = ''
                router_logger.debug("Received chunk from website (%dB)" % len(chunk))
                payload += chunk
            self.next_sock.settimeout(None)

            payload = self.client_crypt.sign_and_encrypt(payload)
        else:
            router_logger.info("Getting response from next router...")
            header = self.pull(self.next_sock, self.HEADER_SIZE)
            num_chunks = self.next_crypt.decrypt_and_auth(header)
            payload = self.pull(self.next_sock, int(num_chunks) * self.CT_BLOCK_SIZE)
            payload = self.client_crypt.sign_and_encrypt(payload)

        header = self.prev_crypt.sign_and_encrypt(str(len(payload) / self.CT_BLOCK_SIZE))

        router_logger.info("Forwarding payload")
        self.request.sendall(header + payload)


if __name__ == "__main__":
    pip, pport, pubkeyf, cdb, port = parse_args()
    # Create the server, binding to localhost on PORT
    with open(pubkeyf, "r") as f:
        raw_pubkey = f.read()
        pubkey = RSA.importKey(raw_pubkey)


    router_logger.info("Building server..")
    server = CustomTCPServer(("0.0.0.0", port), cdb, raw_pubkey, MyTCPHandler)

    # Send public key and port to pathing server
    pathing_server = TORPathingServer(pip, pport, pubkey)

    _, port = server.server_address
    router_logger.info("Registering self...")
    pathing_server.register(port, server.key)
    router_logger.info("Registered")

    try:
        router_logger.info("Starting server...")
        server.serve_forever()
    except:
        router_logger.info("Exiting and unregistering Tor router")
    pathing_server.unregister()
