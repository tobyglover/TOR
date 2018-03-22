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

        self.tr_pubkey = pubkey
        self.tr_encryptor = PKCS1_OAEP.new(self.tr_pubkey)
        self.own_key = RSA.generate(2048)
        self.own_encryptor = PKCS1_OAEP.new(self.own_key)

    def segment(self, data):
        return [data[i:i + self.BLOCK_SIZE] for i in range(0, len(data), self.BLOCK_SIZE)]

    def encrypt_segs(self, segs):
        return map(self.tr_encryptor.encrypt, segs)



    def build_onion(self, data):
        if not self.next_relay:


        body = next_ipp + return_pubkey.exportKey() + data
        header_segs =
        body = struct.pack("!H%ds" % len(body), len(body) / self.BLOCK_SIZE, body)

        # segment data
        data_segs = [data[i:i + self.BLOCK_SIZE] for i in range(0, len(data), self.BLOCK_SIZE)]

        # encrypt data
        return [self.encryptor.encrypt(seg) for seg in data_segs]

    def peel_onion(self, ct):
        pass



class TorRelayMiddle(TorRelay):

    def __init__(self, info, next_relay):
        super(TorRelayMiddle, self).__init__(info)
        self.next_relay = next_relay
        self.next_ipp = next_relay.ipp

    def set_dest(self, ipp):
        self.next_relay.set_dest(ipp)

    def establish_circuit(self):
        payload = self.next_relay.establish_circuit()
        payload_segs = self.segment(payload)

        ownkey = self.own_key.publickey().exportKey()
        ownkey_segs = self.segment(ownkey)

        pkt = [str(len(payload_segs) + len(ownkey_segs) + 1), self.next_ipp]
        pkt = pkt.append(ownkey_segs)
        pkt = pkt.append(payload_segs)
        return self.encrypt_segs(pkt)


class TorRelayExit(TorRelay):

    def __init__(self, info):
        super(TorRelayExit, self).__init__(info)
        self.next_ipp = None

    def set_dest(self, ipp):
        self.next_ipp = ipp

    def establish_circuit(self):
        ownkey = self.own_key.publickey().exportKey()
        ownkey_segs = self.segment(ownkey)

        pkt = [str(len(ownkey_segs) + 1), self.next_ipp]
        pkt = pkt.append(ownkey_segs)
        return self.encrypt_segs(pkt)


class TorInterface(object):
    CHUNK_LEN = 256

    def __init__(self):
        self.key = RSA.generate(2048)
        self.decryptor = PKCS1_OAEP.new(self.key)
        self.entry_relay = None
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def establish_path(self, entry_relay):
        self.entry_relay = entry_relay
        self.s.close()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.entry_relay.ip, self.entry_relay.port))
        self.s.send(self.entry_relay.establish_circuit())

    def do_get(self, url_port, request):
        url_port = url_port.split(":")
        url = url_port[0]
        port = url_port[1] if len(url_port) == 2 else 80
        self.entry_relay.set_dest("%s:%d" % (url, port))




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

    def do_get(self, url_port, request):

        dest_ip = socket.gethostbyname(url)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.tr1.ip, self.tr1.port))

        onion = self.construct_onion(self.make_header(url), dest_ip)

        # send request
        sock.send(onion)

        return self.peel_onion(sock)



