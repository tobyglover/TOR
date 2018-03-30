from Crypt import Crypt
from Crypto.PublicKey import RSA
import socket


class TorRouterInterface(object):

    PT_BLOCK_SIZE = 128
    CT_BLOCK_SIZE = 256

    def __init__(self, (ip, port, tor_pubkey), next_router=None, entry=False):
        self.tor_pubkey = tor_pubkey
        self.tor_crypt = Crypt(public_key=tor_pubkey)
        return_key = RSA.generate(2048)
        self.return_pubkey = return_key.publickey().exportKey(format='DER')
        self.return_crypt = Crypt(public_key=return_key.publickey(),
                                  private_key=return_key)
        self.next_router = next_router
        self.entry = entry
        self.ip = ip
        self.port = port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def establish_circuit(self):
        packet = self.tor_pubkey + self.return_pubkey

        if self.next_router:
            packet += self.next_router.establish_circuit()
            packet = self.tor_crypt.sign_and_encrypt(packet)
            header = "%d:%s:%d" % (len(packet) / self.CT_BLOCK_SIZE,
                                   self.next_router.ip, self.next_router.port)
            packet = self.tor_crypt.sign_and_encrypt(header) + packet
        else:
            packet = self.tor_crypt.sign_and_encrypt(packet)
            header = "%d:EXIT:" % (len(packet) / self.CT_BLOCK_SIZE)
            packet = self.tor_crypt.sign_and_encrypt(header) + packet

        if self.entry:
            self.s.connect((self.ip, self.port))
            self.s.send(packet)
        else:
            return packet

    def make_request(self, url, request):
        url_port = url.split(":")
        ip = socket.gethostbyname(url_port[0])
        port = url_port[1] if len(url_port) == 2 else 80

        if self.next_router:
            packet = self.next_router.make_request(ip, port, request)
            packet = self.tor_crypt.sign_and_encrypt(packet)
            header = str(len(packet) / self.CT_BLOCK_SIZE)
            packet = self.tor_crypt.sign_and_encrypt(header) + packet
        else:
            packet = self.tor_crypt.sign_and_encrypt(request)
            header = "%d:%s:%d" % (len(packet) / self.CT_BLOCK_SIZE, ip, port)
            packet = self.tor_crypt.sign_and_encrypt(header) + packet

        if self.entry:
            self.s.connect((self.ip, self.port))
            self.s.send(packet)
        else:
            return packet
