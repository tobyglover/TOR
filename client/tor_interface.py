from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import socket


class TorRelay(object):

    PT_BLOCK_SIZE = 128
    CT_BLOCK_SIZE = 256

    def __init__(self, (ip, port, pubkey)):
        self.ip = ip
        self.port = port
        self.ipp = "%s:%s" % (ip, port)

        self.own_pubkey = pubkey
        self.own_encryptor = PKCS1_OAEP.new(self.own_pubkey)
        self.client_key = RSA.generate(2048)
        self.client_encryptor = PKCS1_OAEP.new(self.client_key)
        self.last_pubkey = self.client_key.publickey()
        self.last_encryptor = PKCS1_OAEP.new(self.last_pubkey)

    def segment_pt(self, data):
        return [data[i:i + self.PT_BLOCK_SIZE] for i in range(0, len(data), self.PT_BLOCK_SIZE)]

    def segment_ct(self, data):
        return [data[i:i + self.CT_BLOCK_SIZE] for i in range(0, len(data), self.CT_BLOCK_SIZE)]

    def encrypt_segs(self, segs):
        return ''.join(map(self.own_encryptor.encrypt, segs))

    def decrypt_segs(self, segs):
        return ''.join(map(self.own_encryptor.decrypt, segs))


class TorRelayMiddle(TorRelay):

    def __init__(self, info, next_relay):
        super(TorRelayMiddle, self).__init__(info)
        self.next_relay = next_relay
        self.next_ipp = next_relay.ipp

    def set_dest(self, ipp):
        self.next_relay.set_dest(ipp)

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

    def wrap_onion(self, pt):
        payload = self.next_relay.wrap_onion(pt)
        payload_segs = self.segment_pt(payload)

        pkt = [str(len(payload_segs))] + payload_segs
        return self.encrypt_segs(pkt)

    def num_chunks(self, header):
        return int(self.own_encryptor.decrypt(header))

    def peel_onion(self, ct):
        ct_segs = self.segment_ct(ct)
        pt = self.decrypt_segs(ct_segs)
        return self.next_relay.peel_onion(pt)


class TorRelayExit(TorRelay):

    def __init__(self, info):
        super(TorRelayExit, self).__init__(info)
        self.next_ipp = None

    def set_dest(self, ipp):
        self.next_ipp = ipp

    def establish_circuit(self, last_pubkey):
        self.last_pubkey = last_pubkey
        self.last_encryptor = PKCS1_OAEP.new(last_pubkey)
        okey = self.own_pubkey.exportKey()
        okey_segs = self.segment_pt(okey)

        ckey = self.client_key.publickey().exportKey()
        ckey_segs = self.segment_pt(ckey)

        num_chunks = len(okey_segs) + len(ckey_segs) + 1
        pkt = [str(num_chunks), self.next_ipp] + okey_segs + ckey_segs
        return self.encrypt_segs(pkt)

    def wrap_onion(self, pt):
        pt_segs = self.segment_pt(pt)

        pkt = [str(len(pt_segs) + 1), self.next_ipp] + pt_segs
        return self.encrypt_segs(pkt)

    def peel_onion(self, ct):
        ct_segs = self.segment_ct(ct)
        return self.decrypt_segs(ct_segs)


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

        self.s.send(self.entry_relay.wrap_onion(request))

        hdr = self.s.recv(self.entry_relay.CT_BLOCK_SIZE)
        chunks = self.entry_relay.num_chunks(hdr)
        pkt = ''.join([self.s.recv(self.entry_relay.CT_BLOCK_SIZE) for _ in range(chunks)])
        return self.entry_relay.peel_onion(pkt)
