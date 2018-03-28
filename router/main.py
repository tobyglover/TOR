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

# from Crypto.PublicKey import RSA
# from Crypto.Cipher import PKCS1_OAEP
sys.path.append('../')
from TorPathingServer.TORPathingServer import client_interface
from TorPathingServer.TORPathingServer import crypt

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('port', help="Port number to listen on Tor router", type=int)
    parser.add_argument("pip", help="IP address of Tor pathfinding server")
    parser.add_argument("pport", type=int, help="IP address of Tor pathfinding server")
    args = parser.parse_args()
    return args.port, args.pip, args.pport

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
        self.tor_key = None
        self.tor_encryptor = None
        self.tor_crypt = None
        self.client_crypt = None
        self.client_key = None
        self.client_encryptor = None
    def handle(self):
        # set up socket to send to next router
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        read_circuit_establishment(self)
        make_next_hop(self, self.next_hop, self.data)

        read_payload(self)
        send_payload(self, self.data)
        if self.exit == True:
            payload = read_http_res()
        else:
            payload = read_router_res()
        self.request.sendall(payload)
    
    def read_circuit_establishment(self):
        self.data = self.request.recv(CT_BLOCK_SIZE)

        self.num_chunks = self.encryptor.decrypt_and_auth(self.data)

        print "---number of chunks:",
        print num_chunks

        # Ugly code for now, will fix to read all at once
        self.data = self.request.recv(CT_BLOCK_SIZE)

        self.next_hop = self.encryptor.decrypt_and_auth(self.data)
        
        if self.next_hop == "EXIT":
            print "---I am the exit router---"
            self.exit = True

        self.data = self.request.recv(CT_BLOCK_SIZE)
        
        self.tor_key = self.encryptor.decrypt_and_auth(self.data)

        self.tor_crypt = Crypt(None, RSA.importKey(self.tor_key))

        self.data = self.request.recv(CT_BLOCK_SIZE)
        self.client_key = self.encryptor.decrypt_and_auth(self.data)  
         
        self.client_crypt = Crypt(None, RSA.importKey(self.client_key))
        num_chunks -= 3
        self.data = None
        while (num_chunks > 0):
            num_chunks -= 1
            self.data += self.request.recv(CT_BLOCK_SIZE) 
        self.data = self.encryptor.decrypt_and_auth(self.data)

    def make_next_hop(self, next_hop, data):
        if self.exit == True:
            return
        print "---sending establishment circuit to next router---"
        host, port = next_hop.split(":")
        self.sock.connect((host, port))
        self.sock.sendall(data)

    def read_payload(self):
        self.data = self.request.recv(CT_BLOCK_SIZE)
        self.num_chunks = self.encryptor.decrypt_and_auth(self.data)
        if self.exit == True:
            read_http_req(self)
            return
        self.data = None
        while (num_chunks > 0):
            num_chunks -= 1
            self.data += self.request.recv(CT_BLOCK_SIZE)
        self.data = self.encryptor.decrypt_and_auth(self.data)

    def send_payload(self, data):
        self.sock.sendall(data)

    def read_http_req(self):
        self.data = self.request.recv(CT_BLOCK_SIZE)
        
        self.next_hop = self.encryptor.decrypt_and_auth(self.data)
        
        # actual http get request
        self.data = self.request.recv(CT_BLOCK_SIZE)
        
        self.data = self.encryptor.decrypt_and_auth(self.data)
    def read_http_res(self):
        # INSECURE! POSSIBLE BUFFER OVERFLOW
        nbytes = self.sock.recvfrom_into(self.data)
        data_segs = self.segment_ct(self.data)
        self.num_chunks = len(data_segs)

        payload_segs = self.client_crypt.sign_and_encrypt(data_segs)
        num_chunks_encrypted = self.tor_crypt.sign_and_encrypt(self.num_chunks)

        return [str(num_chunks_encrypted)] + payload_segs
    def read_router_res(self):
        self.num_chunks = self.request.recv(CT_BLOCK_SIZE)
        nbytes = self.sock.recvfrom_into(self.data)

        self.num_chunks = self.encryptor.decrypt_and_auth(self.num_chunks)
        num_chunks_encrypted = self.tor_crypt.sign_and_encrypt(self.num_chunks)
        payload_segs = self.client_crypt.sign_and_encrypt(self.data)
        return [str(num_chunks_encrypted)] + payload_segs

    def segment_pt(self, data):
        return [data[i:i + self.PT_BLOCK_SIZE] for i in range(0, len(data), self.PT_BLOCK_SIZE)]
    def segment_ct(self, data):
        return [data[i:i + self.CT_BLOCK_SIZE] for i in range(0, len(data), self.CT_BLOCK_SIZE)]


if __name__ == "__main__":
    HOST = "localhost"
    port, pip, pport= parse_args()
    # Create the server, binding to localhost on PORT
    server = SocketServer.TCPServer((HOST, port), MyTCPHandler)

    server.private_key = Crypt().generate_key()
    server.public_key = server.private_key.public_key()
    server.encryptor = Crypt(server.private_key, server.public_key)

    # Send public key and port to pathing server
    pathing_server = TORPathingServer(pip, pport)

    pathing_server.register(port, server.public_key)
    server.serve_forever()
    pathing_server.unregister()
