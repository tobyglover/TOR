"""
Allen Zhou
COMP112
TOR router
3/19/18
"""
import sys
sys.path.append('../')
import struct
import socket
import SocketServer
import argparse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from TORPathingServer import TORPathingServer


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
        self.num_chunks = self.encryptor.decrypt(self.data)
        print "number of chunks:"
        print num_chunks

        # Ugly code for now, will fix to read all at once
        self.data = self.request.recv(CT_BLOCK_SIZE)
        self.next_hop = self.encryptor.decrypt(self.data)
        if self.next_hop == "EXIT":
            print "I am the exit router"
            self.exit = True

        self.data = self.request.recv(CT_BLOCK_SIZE)
        self.tor_key = self.encryptor.decrypt(self.data)
        key = RSA.importKey(self.tor_key)
        self.tor_encryptor = PKCS1_OAEP.new(key)  

        self.data = self.request.recv(CT_BLOCK_SIZE)
        self.client_key = self.encryptor.decrypt(self.data)   
        key = RSA.importKey(self.client_key)
        self.client_encryptor = PKCS1_OAEP.new(key) 

        num_chunks -= 3
        self.data = None
        while (num_chunks > 0):
            num_chunks -= 1
            self.data += self.request.recv(CT_BLOCK_SIZE)
        self.data = self.encryptor.decrypt(self.data)

    def make_next_hop(self, next_hop, data):
        if self.exit == True:
            return
        print "sending establishment circuit to next router"
        host, port = next_hop.split(":")
        self.sock.connect((host, port))
        self.sock.sendall(data)

    def read_payload(self):
        self.data = self.request.recv(CT_BLOCK_SIZE)
        self.num_chunks = self.encryptor.decrypt(self.data)
        if self.exit == True:
            read_http_req(self)
            return
        self.data = None
        while (num_chunks > 0):
            num_chunks -= 1
            self.data += self.request.recv(CT_BLOCK_SIZE)
        self.data = self.encryptor.decrypt(self.data)

    def send_payload(self, data):
        self.sock.sendall(data)

    def read_http_req(self):
        self.data = self.request.recv(CT_BLOCK_SIZE)
        self.next_hop = self.encryptor.decrypt(self.data)
        # actual http get request
        self.data = self.request.recv(CT_BLOCK_SIZE)
        self.data = self.encryptor.decrypt(self.data)
    def read_http_res(self):
        # INSECURE! POSSIBLE BUFFER OVERFLOW
        nbytes = self.sock.recvfrom_into(self.data)
        data_segs = self.segment_ct(self.data)
        self.num_chunks = len(data_segs)
        payload_segs = self.client_encryptor.encrypt_segs(data_segs)
        num_chunks_encrypted = self.tor_encryptor.encrypt(self.num_chunks)
        return [str(num_chunks_encrypted)] + payload_segs
    def read_router_res(self):
        self.num_chunks = self.request.recv(CT_BLOCK_SIZE)
        nbytes = self.sock.recvfrom_into(self.data)
        self.num_chunks = self.encryptor.decrypt(self.num_chunks)
        num_chunks_encrypted = self.tor_encryptor.encrypt(self.num_chunks)
        payload_segs = self.client_encryptor.encrypt(self.data)
        return [str(num_chunks_encrypted)] + payload_segs

    def segment_pt(self, data):
        return [data[i:i + self.PT_BLOCK_SIZE] for i in range(0, len(data), self.PT_BLOCK_SIZE)]
    def segment_ct(self, data):
        return [data[i:i + self.CT_BLOCK_SIZE] for i in range(0, len(data), self.CT_BLOCK_SIZE)]


class RSAEncryptor():
    def __init__(self):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        self.encryptor = PKCS1_OAEP.new(self.private_key)
    def encrypt(self, msg):
        encrypted_msg = self.encryptor.encrypt(msg)
        print msg
        print encrypted_msg
        return encrypted_msg
    def decrypt(self, msg):
        decrypted_msg = self.encryptor.decrypt(msg)
        print decrypted_msg
        return decrypted_msg
    def encrypt_segs(self, segs):
        return ''.join(map(self.own_encryptor.encrypt, segs))
    def decrypt_segs(self, segs):
        return ''.join(map(self.own_encryptor.decrypt, segs))


if __name__ == "__main__":
    HOST = "localhost"
    port, pip, pport= parse_args()
    # Create the server, binding to localhost on PORT
    server = SocketServer.TCPServer((HOST, port), MyTCPHandler)
    server.encryptor = RSAEncryptor()

    # Send public key and port to pathing server
    pathing_server = TORPathingServer(pip, pport)
    pathing_server.register(port, server.encryptor.public_key)
    server.serve_forever()
    pathing_server.unregister()


"""
def establish_circuit(self, last_pubkey=None):
        payload = self.next_relay.establish_circuit(self.own_pubkey)
        payload_segs = self.segment_pt(payload)

        if last_pubkey:
            self.last_pubkey = last_pubkey
            self.last_encryptor = PKCS1_OAEP.new(last_pubkey)
        okey = self.own_pubkey.exportKey()
        okey_segs = self.segment_pt(okey)

        ckey = self.client_key.publickey().exportKey()
        ckey_segs = self.segment_pt(ckey)

        num_chunks = len(payload_segs) + len(okey_segs) + len(ckey_segs) + 1
        pkt = [str(num_chunks), self.next_ipp] + okey_segs + ckey_segs + payload_segs
        return self.encrypt_segs(pkt)
        """