from Crypt import Crypt, Symmetric
import logging
import socket


class TorRouterInterface(object):

    CT_BLOCK_SIZE = 256
    HEADER_SIZE = 2 * CT_BLOCK_SIZE

    def __init__(self, (ip, port, tor_pubkey), next_router=None, entry=False):
        client_key = Crypt().generate_key()
        self.client_pubkey = client_key.publickey()
        self.tor_pubkey = tor_pubkey
        self.crypt = Crypt(public_key=tor_pubkey,
                           private_key=client_key)
        self.prev_pubkey_der = None
        self.next_router = next_router
        self.entry = entry
        self.ip = ip
        self.port = port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logging.info("Initialized TorRouterInterface")

    def _pull(self, length):
        message = ''
        while len(message) < length:
            message += self.s.recv(length - len(message))
        return message

    def establish_circuit(self, prev_pubkey=None):
        logging.info("Establishing circuit")
        if self.entry:
            self.prev_pubkey_der = self.client_pubkey.exportKey(format='DER')
        else:
            self.prev_pubkey_der = prev_pubkey.exportKey(format='DER')

        pubkey = self.client_pubkey.exportKey(format='DER')

        packet = self.prev_pubkey_der
        if self.next_router:
            packet += self.next_router.tor_pubkey.exportKey(format='DER')
            packet += self.next_router.establish_circuit(prev_pubkey=self.tor_pubkey)
            packet = self.crypt.sign_and_encrypt(packet)
            header = "%d:%s:%d" % (len(packet) / self.CT_BLOCK_SIZE,
                                   self.next_router.ip, self.next_router.port)
            header = self.crypt.sign_and_encrypt(header)
        else:
            packet = self.crypt.sign_and_encrypt(packet)
            header = "%d:EXIT:" % (len(packet) / self.CT_BLOCK_SIZE)
            header = self.crypt.sign_and_encrypt(header)

        logging.debug("ppd: %d, h: %d, p: %d" % (len(self.prev_pubkey_der), len(header), len(packet)))
        packet = pubkey + header + packet

        if self.entry:
            self.s.connect((self.ip, self.port))
            logging.info("Entry TRI sending packet of len %d" % len(packet))
            self.s.sendall(packet)
        else:
            logging.info("Later TRI returning packet of len %d" % len(packet))
            return packet

    def peel_onion(self, onion):
        if self.next_router:
            onion = self.crypt.decrypt_and_auth(onion)
            return self.next_router.peel_onion(onion)
        return self.crypt.decrypt_and_auth(onion)

    def make_request(self, url, request):
        url_port = url.split(":")
        ip = socket.gethostbyname(url_port[0])
        port = int(url_port[1]) if len(url_port) == 2 else 80

        logging.info("Requesting %s:%d" % (ip, port))

        if self.next_router:
            packet = self.next_router.make_request(url, request)
            packet = self.crypt.sign_and_encrypt(packet)
            header = "%d:" % (len(packet) / self.CT_BLOCK_SIZE)
            packet = self.crypt.sign_and_encrypt(header) + packet
        else:
            packet = self.crypt.sign_and_encrypt(request)
            header = "%d:%s:%d" % (len(packet) / self.CT_BLOCK_SIZE, ip, port)
            packet = self.crypt.sign_and_encrypt(header) + packet

        if self.entry:
            logging.info("Sending packet")
            self.s.sendall(packet)
        else:
            return packet

        logging.info("Waiting for response...")
        header = self._pull(self.HEADER_SIZE)
        num_chunks = int(self.crypt.decrypt_and_auth(header))

        onion = self._pull(num_chunks * self.CT_BLOCK_SIZE)
        logging.info("Received response")
        return self.peel_onion(onion)

    def close_circuit(self):
        if self.next_router:
            packet = self.next_router.close_circuit()
            packet = self.crypt.sign_and_encrypt(packet)
            header = "%d:CLOSE" % (len(packet) / self.CT_BLOCK_SIZE)
            packet = self.crypt.sign_and_encrypt(header) + packet
        else:
            packet = "0:CLOSE:"
            packet = self.crypt.sign_and_encrypt(packet)

        if self.entry:
            logging.info("Closing circuit")
            self.s.sendall(packet)
        else:
            return packet


class TestTorRouterInterface(object):

    CT_BLOCK_SIZE = 256
    HEADER_SIZE = 2 * CT_BLOCK_SIZE

    def __init__(self, (pkt, ip, port, tor_pubkey, sid, symkey), next_router=None,
                 is_entry=False, is_exit=False, own_key=None, server_pubkey=None):
        self.pkt = pkt
        self.ipp = (ip, port)
        self.tor_pubkey = tor_pubkey
        self.sid = sid
        self.client_symkey = symkey
        self.next_symkey = None
        self.prev_symkey = None
        self.next_router = next_router
        self.is_entry = is_entry
        self.is_exit = is_exit
        self.router_key = own_key
        self.client_key = Crypt().generate_key()
        self.own_key = own_key
        self.server_pubkey = server_pubkey
        self.local_crypt = Crypt(public_key=own_key.publickey(), private_key=self.client_key)
        self.router_crypt = Crypt(public_key=self.client_key.publickey(), private_key=self.router_key)
        self.server_crypt = Crypt(public_key=server_pubkey, private_key=self.router_key)

    def _keep_alive(self):
        pass

    def _handle_establishment(self, payload):
        pkt, (crypt_header, header, body) = payload[:512], Symmetric().unpack_payload(payload[512:])
        data, hash = self.server_crypt.decrypt(pkt)
        # print "r%d: Decrypting with %s Signing with %s - %s...%s:%s...%s (%dB)" % (self.ipp[1], self.own_key.publickey().exportKey('DER').encode('hex')[70:86],
        #                                                               self.server_pubkey.exportKey('DER').encode('hex')[70:86],
        #                                                               pkt.encode('hex')[:16], pkt.encode('hex')[-16:],
        #                                                               data.encode('hex')[:16], data.encode('hex')[-16:], len(pkt))
        self.server_crypt.auth(data, hash)

        # print self.ipp[1], data.encode('hex')[:16], data.encode('hex')[-16:]
        # print self.ipp[1], len(payload[len(self.pkt):]), payload[len(self.pkt):].encode('hex')[:16], payload[len(self.pkt):].encode('hex')[-16:]

        # print "DATA", self.ipp[1], len(data), data.encode('hex')[:16], data.encode('hex')[-16:]
        method, rid, sid, symkey = data[:4], data[4:20], data[20:28], data[28:44]
        # print "SYMKEYH", self.ipp[1], symkey.encode('hex')
        # print "SID   H", self.ipp[1], sid.encode('hex')
        # print "CRYPTHH", self.ipp[1], crypt_header.encode('hex')
        # print "Method: " + method

        client_sym = Symmetric(symkey, sid)
        client_sym.absorb_crypto_header(crypt_header)
        l, status = client_sym.decrypt_header(header)
        logging.debug("HE - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))

        body = client_sym.decrypt_body(body)
        # print body.encode('hex')
        # payload += sym.encrypt_payload(self.router_key.exportKey("DER") + self.prev_symkey +
        #                                self.next_symkey + next_payload, "ESTB")
        DER_LEN = Crypt().PUB_DER_LEN
        self.raw_clientkey, self.recv_prev_symkey, self.recv_next_symkey, next_payload = \
            body[:DER_LEN], \
            body[DER_LEN:DER_LEN + 16], \
            body[DER_LEN + 16:DER_LEN + 32], \
            body[DER_LEN + 32:]

        print "2", self.ipp[1], self.recv_prev_symkey.encode('hex'), self.recv_next_symkey.encode('hex')

        if self.is_exit:
            response = ''
        else:
            response = self.next_router._handle_establishment(next_payload)
            print "4", self.ipp[1], self.recv_next_symkey.encode('hex')
            next_sym = Symmetric(self.recv_next_symkey)
            crypt_header, header, body = client_sym.unpack_payload(response)
            # print response
            next_sym.absorb_crypto_header(crypt_header)
            l, status = next_sym.decrypt_header(header)
            logging.debug("H2 - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))
            response = next_sym.decrypt_body(body)

        response = client_sym.encrypt_payload(response, "OKOK")

        print "3", self.ipp[1], self.recv_prev_symkey.encode('hex')
        ret = Symmetric(self.recv_prev_symkey).encrypt_payload(response, "OKOK")
        # print Symmetric().unpack_payload(ret)
        return ret

    def establish_circuit(self, prev_symkey=None):
        # print "SYMKEYE", self.ipp[1], self.client_symkey.encode('hex')
        # print "SID   E", self.ipp[1], self.sid.encode('hex')
        sym = Symmetric(self.client_symkey, self.sid)
        self.prev_symkey = prev_symkey or self.client_symkey

        if self.is_exit:
            payload = self.pkt
            payload += sym.encrypt_payload(self.client_key.publickey().exportKey("DER") + prev_symkey, "EXIT")
            # print self.ipp[1], len(payload[len(self.pkt):]), payload[len(self.pkt):].encode('hex')[:16], payload[len(self.pkt):].encode('hex')[-16:]
        else:
            payload = self.pkt

            self.next_symkey = sym.generate()
            next_payload = self.next_router.establish_circuit(self.next_symkey)
            print "1", self.ipp[1], self.prev_symkey.encode('hex'), self.next_symkey.encode('hex')
            payload += sym.encrypt_payload(self.client_key.publickey().exportKey("DER") + self.prev_symkey +
                                           self.next_symkey + next_payload, "ESTB")
            # print self.ipp[1], len(payload[len(self.pkt):]), payload[len(self.pkt):].encode('hex')[:16], payload[len(self.pkt):].encode('hex')[-16:]

        # print "CRYPTHE", self.ipp[1], payload[len(self.pkt):len(self.pkt) + 80].encode('hex')

        if not self.is_entry:
            return payload

        response = self._handle_establishment(payload)
        resp_sym = Symmetric(self.client_symkey)
        crypt_header, header, body = resp_sym.unpack_payload(response)

        print "5", self.ipp[1], self.client_symkey.encode('hex')
        resp_sym.absorb_crypto_header(crypt_header)
        l, status = resp_sym.decrypt_header(header)
        logging.debug("EC - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))
        body = resp_sym.decrypt_body(body)

        return self.peel_onion(body)

    def peel_onion(self, onion):
        sym = Symmetric(self.client_symkey, self.sid)
        crypt_header, header, body = sym.unpack_payload(onion)
        sym.absorb_crypto_header(crypt_header)
        l, status = sym.decrypt_header(header)
        logging.debug("PO - Status: %s, len: %d wanted, %d recvd" % (status, l, len(body)))
        body = sym.decrypt_body(body)

        if self.is_exit:
            return body
        return self.next_router.peel_onion(body)

    def make_request(self, url, request):
        pass

    def close_circuit(self):
        pass
