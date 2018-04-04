"""
Allen Zhou
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

root = logging.getLogger()
root.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
root.addHandler(ch)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pip", help="IP address of Tor pathfinding server")
    parser.add_argument("pport", type=int, help="IP address of Tor pathfinding server")
    parser.add_argument("--port", type=int, help="Port to bind to", default=0)
    args = parser.parse_args()
    return args.pip, args.pport, args.port


class CustomTCPServer(TCPServer, object):
    def __init__(self, server_address, request_handler):
        super(CustomTCPServer, self).__init__(server_address, request_handler)
        self.key = Crypt().generate_key()


class MyTCPHandler(BaseRequestHandler):
    CT_BLOCK_SIZE = 256
    HEADER_SIZE = CT_BLOCK_SIZE * 2
    DER_LEN = len(Crypt().generate_key().publickey().exportKey(format='DER'))

    def setup(self):
        logging.info("connection received")
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
        logging.info('handling connection from %s:%s' % self.client_address)
        logging.info('Establishing circuit')
        self.read_circuit_establishment()

        logging.info('Forwarding payload')
        while self.forward_payload():
            logging.info('Forwarding response')
            self.forward_response()

            logging.info('Forwarding payload')

    def read_circuit_establishment(self):
        logging.debug("Waiting for pubkey...")
        client_pubkey = self.pull(self.request, self.DER_LEN)
        logging.debug("Got pubkey (%dB)" % len(client_pubkey))
        client_pubkey = RSA.importKey(client_pubkey)
        self.client_crypt = Crypt(public_key=client_pubkey,
                                  private_key=self.server.key,
                                  name="client")

        logging.debug("Waiting for header...")
        header = self.pull(self.request, self.HEADER_SIZE)
        num_chunks, self.next_ip, self.next_port = self.client_crypt.decrypt_and_auth(header).split(":")
        logging.debug("Received header (%dB) %s:%s:%s" % (len(header), num_chunks, self.next_ip, self.next_port))

        logging.debug("Waiting for body of %d blocks..." % (int(num_chunks)))
        data = self.pull(self.request, self.CT_BLOCK_SIZE * int(num_chunks))
        logging.debug("Received body (%dB)" % len(data))
        data = self.client_crypt.decrypt_and_auth(data)

        if self.next_ip == "EXIT":
            logging.info("is exit node")
            self.exit = True
            prev_pubkey, payload = data[:self.DER_LEN], data[self.DER_LEN:]
        else:
            prev_pubkey, next_pubkey, payload = data[:self.DER_LEN], data[self.DER_LEN:2*self.DER_LEN], \
                                                data[2*self.DER_LEN:]
            self.next_crypt = Crypt(public_key=RSA.importKey(next_pubkey),
                                    private_key=self.server.key,
                                    name="next_router")
            self.make_next_hop((self.next_ip, int(self.next_port)), payload)

        self.prev_crypt = Crypt(public_key=RSA.importKey(prev_pubkey),
                                private_key=self.server.key,
                                name="prev_router")

    def make_next_hop(self, next_hop, data):
        logging.info("Sending establishment circuit to next router")
        self.next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.next_sock.connect(next_hop)
        self.next_sock.sendall(data)

    def forward_payload(self):
        logging.info('Waiting for payload to forward...')
        header = self.pull(self.request, self.HEADER_SIZE)
        logging.info('Received header of payload (%dB)' % len(header))
        header = self.client_crypt.decrypt_and_auth(header)

        if self.exit:
            num_chunks, ip, port = header.split(":")
            if ip == "CLOSE":
                logging.info("Closing circuit")
                return False
            close = "OK"
            logging.info("Sending payload to %s:%s" % (ip, port))
            self.next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.next_sock.connect((ip, int(port)))
        else:
            num_chunks, close = header.split(":")

        data = self.pull(self.request, self.CT_BLOCK_SIZE * int(num_chunks))
        data = self.client_crypt.decrypt_and_auth(data)
        if close:
            logging.info("Closing circuit")
            self.next_sock.sendall(data)
            return False
        logging.info("Forwarding payload (%dB)" % len(data))
        self.next_sock.sendall(data)
        return True

    def forward_response(self):
        if self.exit:
            logging.info("Getting response from website...")
            chunk = 'asdf'
            payload = ''
            self.next_sock.settimeout(1)
            while len(chunk) > 0:
                try:
                    chunk = self.next_sock.recv(1024)
                except timeout:
                    chunk = ''
                logging.debug("Received chunk from website (%dB)" % len(chunk))
                payload += chunk
            self.next_sock.settimeout(None)

            payload = self.client_crypt.sign_and_encrypt(payload)
        else:
            logging.info("Getting response from next router...")
            header = self.pull(self.next_sock, self.HEADER_SIZE)
            num_chunks = self.next_crypt.decrypt_and_auth(header)
            payload = self.pull(self.next_sock, int(num_chunks) * self.CT_BLOCK_SIZE)
            payload = self.client_crypt.sign_and_encrypt(payload)

        header = self.prev_crypt.sign_and_encrypt(str(len(payload) / self.CT_BLOCK_SIZE))

        logging.info("Forwarding payload")
        self.request.sendall(header + payload)


if __name__ == "__main__":
    pip, pport, port= parse_args()
    # Create the server, binding to localhost on PORT
    server = CustomTCPServer(("0.0.0.0", port), MyTCPHandler)

    # Send public key and port to pathing server
    pathing_server = TORPathingServer(pip, pport)

    _, port = server.server_address
    logging.info("Registering self...")
    pathing_server.register(port, server.key.publickey())
    logging.info("Registered")
    try:
        logging.info("Starting server...")
        server.serve_forever()
    except:
        logging.info("Exiting and unregistering Tor router")
    pathing_server.unregister()
