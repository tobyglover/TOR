from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import struct
import socket


class TorRelay(object):

    BLOCK_SIZE = 128

    def __init__(self, (ip, port, pubkey)):
        self.ip = ip
        self.port = port
        self.ipp = "%s:%s" % (ip, port)
        self.pubkey = pubkey
        self.encryptor = PKCS1_OAEP.new(pubkey)

    def encrypt(self, next_ipp, return_pubkey, data):
        body = next_ipp + return_pubkey.exportKey() + data
        body = struct.pack("!H%ds" % len(body), len(body) / self.BLOCK_SIZE, body)

        # segment data
        data_segs = [body[i:i + self.BLOCK_SIZE] for i in range(0, len(body), self.BLOCK_SIZE)]

        # encrypt data
        return [self.encryptor.encrypt(seg) for seg in data_segs]


class TorInterface(object):
    CHUNK_LEN = 256

    def __init__(self):
        self.key = RSA.generate(2048)
        self.decryptor = PKCS1_OAEP.new(self.key)
        self.tr1 = None
        self.tr2 = None
        self.tr3 = None

    def establish_path(self, tr1, tr2, tr3):
        self.tr1 = tr1
        self.tr2 = tr2
        self.tr3 = tr3

    def make_header(self, url):
        return "GET %s HTTP/1.1\nHost: %s\n\n" % (url, url.split("/")[2])

    def construct_onion(self, data, dest_ip):
        onion1 = self.tr1.encrypt(self.tr2.ipp, self.key.publickey(), "")
        onion2 = self.tr2.encrypt(self.tr3.ipp, self.key.publickey(), onion1)
        return self.tr3.encrypt(dest_ip, self.key.publickey(), onion2)

    def peel_onion(self, sock):
        # get first packet
        pkt = sock.recv(self.CHUNK_LEN)
        num_pkts, dat = struct.unpack("!Hd%ds" % self.CHUNK_LEN, self.decryptor.decrypt(pkt))

        num_pkts -= 1
        for i in range(0, num_pkts - 1):
            dat += self.decryptor.decrypt(sock.recv(self.CHUNK_LEN))

        return dat

    def do_get(self, url):
        dest_ip = socket.gethostbyname(url)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.tr1.ip, self.tr1.port))

        onion = self.construct_onion(self.make_header(url), dest_ip)

        # send request
        sock.send(onion)

        return self.peel_onion(sock)



