"""
Allen Zhou
COMP112
TOR router
3/19/18
"""
import SocketServer
from Crypto.PublicKey import RSA

RSACODE = "insertanystringhere"
HOST, PORT = "localhost", 9999

class MyTCPHandler(SocketServer.BaseRequestHandler):
    def setup(self):
        print "setup"
        # will run before handle function
    def handle(self):
        # read request from socket
        self.data = self.request.recv(1024).strip()
        print "{} wrote:".format(self.client_address[0])
        print self.data
        # just send back the same data, but upper-cased
        self.request.sendall(self.data.upper())

# Generates a RSA public/private pair
# Stores private key in rsa_key.bin file
# Returns public key
def generate_RSA():
    key = RSA.generate(2048)
    encrypted_key = key.exportKey(passphrase=RSACODE, pkcs=8,
                              protection="scryptAndAES128-CBC")
    file_out = open("rsa_key.bin", "wb")
    file_out.write(encrypted_key)
    return key.publickey().exportKey()
# Returns public key
def get_public():
    encoded_key = open("rsa_key.bin", "rb").read()
    key = RSA.import_key(encoded_key, passphrase=RSACODE)
    return key.publickey().exportKey()

def send_to_pathing_server(pub_key):
    print pub_key
    print "sending public key to pathing server"

if __name__ == "__main__":
    # Create the server, binding to localhost on port 9999
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)
    # Send public key to pathing server
    send_to_pathing_server(generate_RSA())

    server.serve_forever()