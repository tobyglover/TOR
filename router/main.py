"""
Allen Zhou
COMP112
TOR router
3/19/18
"""
import sys

import struct
import socket
import SocketServer
import argparse

from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
from TorPathingServer import TORPathingServer
from Crypt import Crypt

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("pip", help="IP address of Tor pathfinding server")
    parser.add_argument("pport", type=int, help="IP address of Tor pathfinding server")
    args = parser.parse_args()
    return args.pip, args.pport

class MyTCPHandler(SocketServer.BaseRequestHandler):
    PT_BLOCK_SIZE = 128
    CT_BLOCK_SIZE = 256
    def setup(self):
        print "connection received"
        self.sock = None
        self.data = None
        self.num_chunks = 0
        self.next_hop = None
        self.exit = False
        self.tor_crypt = None
        self.client_crypt = None
    def handle(self):
        print 'handling connection...'
        # set up socket to send to next router
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.read_circuit_establishment()
        self.make_next_hop(self.next_hop, self.data)

        self.read_payload()
        self.send_payload(self.data)
        if self.exit == True:
            payload = self.read_http_res()
        else:
            payload = self.read_router_res()
        self.request.sendall(payload)
    
    def read_circuit_establishment(self):
        self.data = self.request.recv(self.CT_BLOCK_SIZE)

        self.num_chunks = self.encryptor.decrypt_and_auth(self.data)

        print "---number of chunks:",
        print self.num_chunks

        self.data = self.request.recv(self.CT_BLOCK_SIZE)
        self.next_hop = self.encryptor.decrypt_and_auth(self.data)
        
        if self.next_hop == "EXIT":
            print "---I am the exit router---"
            self.exit = True

        self.data = self.request.recv(self.CT_BLOCK_SIZE)
        
        decrypted_data = self.encryptor.decrypt_and_auth(self.data)
        self.tor_crypt = Crypt(None, RSA.importKey(decrypted_data))

        self.data = self.request.recv(self.CT_BLOCK_SIZE)
        decrypted_data = self.encryptor.decrypt_and_auth(self.data)  
         
        self.client_crypt = Crypt(None, RSA.importKey(decrypted_data))
        self.num_chunks -= 3
        self.data = None

        while (self.num_chunks > 0):
            self.num_chunks -= 1
            self.data += self.request.recv(self.CT_BLOCK_SIZE)
        self.data = self.encryptor.decrypt_and_auth(self.data)

    def make_next_hop(self, next_hop, data):
        if self.exit == True:
            return
        print "---sending establishment circuit to next router---"
        host, port = next_hop.split(":")
        self.sock.connect((host, port))
        self.sock.sendall(data)

    def read_payload(self):
        self.data = self.request.recv(self.CT_BLOCK_SIZE)
        self.num_chunks = self.encryptor.decrypt_and_auth(self.data)
        if self.exit == True:
            self.read_http_req(self)
            return
        self.data = None
        while (self.num_chunks > 0):
            self.num_chunks -= 1
            self.data += self.request.recv(self.CT_BLOCK_SIZE)
        self.data = self.encryptor.decrypt_and_auth(self.data)

    def send_payload(self, data):
        if self.exit != True:
            self.sock.sendall(data)

    def read_http_req(self):
        self.data = self.request.recv(self.CT_BLOCK_SIZE)
        
        self.next_hop = self.encryptor.decrypt_and_auth(self.data)
        host, port = self.next_hop.split(":")

        self.num_chunks -= 1
        while (self.num_chunks > 0):
            self.num_chunks -= 1
            self.data += self.request.recv(self.CT_BLOCK_SIZE)

        self.data = self.encryptor.decrypt_and_auth(self.data)
        self.sock.connect((host, port))
        self.sock.sendall(self.data)

    def read_http_res(self):
        # INSECURE! POSSIBLE BUFFER OVERFLOW
        nbytes = self.sock.recvfrom_into(self.data)
        print "---read nbytes: ",
        print nbytes
        data_segs = self.segment_ct(self.data)
        self.num_chunks = len(data_segs)

        payload_segs = self.client_crypt.sign_and_encrypt(data_segs)
        num_chunks_encrypted = self.tor_crypt.sign_and_encrypt(self.num_chunks)
        return [str(num_chunks_encrypted)] + payload_segs
        
    def read_router_res(self):
        self.num_chunks = self.request.recv(self.CT_BLOCK_SIZE)
        nbytes = self.sock.recvfrom_into(self.data)
        print "---read nbytes: ",
        print nbytes
        self.num_chunks = self.encryptor.decrypt_and_auth(self.num_chunks)
        num_chunks_encrypted = self.tor_crypt.sign_and_encrypt(self.num_chunks)
        payload_segs = self.client_crypt.sign_and_encrypt(self.data)
        return [str(num_chunks_encrypted)] + payload_segs

    def segment_pt(self, data):
        return [data[i:i + self.PT_BLOCK_SIZE] for i in range(0, len(data), self.PT_BLOCK_SIZE)]
    def segment_ct(self, data):
        return [data[i:i + self.CT_BLOCK_SIZE] for i in range(0, len(data), self.CT_BLOCK_SIZE)]


if __name__ == "__main__":
    pip, pport= parse_args()
    # Create the server, binding to localhost on PORT
    server = SocketServer.TCPServer(("0.0.0.0", 0), MyTCPHandler)

    server.private_key = Crypt().generate_key()
    server.public_key = server.private_key.publickey()
    server.encryptor = Crypt(server.private_key, server.public_key)

    # Send public key and port to pathing server
    pathing_server = TORPathingServer(pip, pport)

    _, port = server.server_address
    pathing_server.register(port, server.public_key)
    try:
        server.serve_forever()
    except:
        print "Exiting and unregistering Tor router"
    pathing_server.unregister()
