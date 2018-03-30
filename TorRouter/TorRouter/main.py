"""
Allen Zhou
COMP112
TOR router
3/19/18
"""
import sys

import struct
import socket
from SocketServer import TCPServer, BaseRequestHandler
import argparse

from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
from TorPathingServer import TORPathingServer
from Crypt import Crypt


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
        self.crypt = Crypt(private_key=self.key, public_key=self.key.publickey())


class MyTCPHandler(BaseRequestHandler):
    CT_BLOCK_SIZE = 256
    HEADER_SIZE = CT_BLOCK_SIZE * 2
    DER_LEN = len(RSA.generate(2048).publickey().exportKey(format='DER'))

    def setup(self):
        print "connection received"
        self.next_sock = None
        self.exit = False
        self.client_crypt = None
        self.prev_crypt = None

    def handle(self):
        print 'handling connection from %s:%s' % self.client_address
        self.read_circuit_establishment()

        self.forward_payload()
        self.forward_response()
    
    def read_circuit_establishment(self):
        header = self.request.recv(self.HEADER_SIZE)
        num_chunks, self.next_ip, self.next_port = self.server.crypt.decrypt_and_auth(header).split(":")

        data = self.request.recv(self.CT_BLOCK_SIZE * int(num_chunks))
        data = self.server.crypt.decrypt_and_auth(data)
        prev_pubkey, client_pubkey, payload = data[:self.DER_LEN], data[self.DER_LEN: 2*self.DER_LEN], \
                                              data[2*self.DER_LEN:]

        self.prev_crypt = Crypt(public_key=RSA.importKey(prev_pubkey))
        self.client_crypt = Crypt(public_key=RSA.importKey(client_pubkey))

        if self.next_ip == "EXIT":
            print "---I am the exit router---"
            self.exit = True
        else:
            self.make_next_hop((self.next_ip, self.next_port), payload)

    def make_next_hop(self, next_hop, data):
        print "---sending establishment circuit to next router---"
        self.next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.next_sock.connect(next_hop)
        self.next_sock.sendall(data)

    def forward_payload(self):
        header = self.request.recv(self.HEADER_SIZE)
        header = self.server.crypt.decrypt_and_auth(header)

        if self.exit:
            num_chunks, ip, port = header.split(":")
            self.next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.next_sock.connect((ip, int(port)))
        else:
            num_chunks = header

        data = self.request.recv(self.CT_BLOCK_SIZE * int(num_chunks))
        data = self.server.crypt.decrypt_and_auth(data)
        self.next_sock.sendall(data)

    def forward_response(self):
        if self.exit:
            chunk = 'asdf'
            payload = ''
            while len(chunk) > 0:
                chunk = self.next_sock.recv(1024)
                payload += chunk

            payload = self.client_crypt.sign_and_encrypt(payload)
            header = self.prev_crypt.sign_and_encrypt(str(len(payload) / self.CT_BLOCK_SIZE))
        else:
            header = self.next_sock.recv(self.HEADER_SIZE)
            num_chunks = self.server.crypt.decrypt_and_auth(header)
            payload = self.next_sock.recv(num_chunks * self.CT_BLOCK_SIZE)
            payload = self.client_crypt.sign_and_encrypt(payload)

        self.request.sendall(header + payload)


if __name__ == "__main__":
    pip, pport, port= parse_args()
    # Create the server, binding to localhost on PORT
    server = CustomTCPServer(("0.0.0.0", port), MyTCPHandler)

    # Send public key and port to pathing server
    pathing_server = TORPathingServer(pip, pport)

    _, port = server.server_address
    pathing_server.register(port, server.key)
    try:
        server.serve_forever()
    except:
        print "Exiting and unregistering Tor router"
    pathing_server.unregister()
