from Crypt import Crypt
import struct
import socket


class TorDNSInterface(object):

    def __init__(self, ip, port, pubkey):
        """TorDNSInterface

        Interface to the TorDNS service

        Args:
            ip (str): Unpacked IP address of live TorDNS server
            port (int): Port on live TorDNS server to connect to
            pubkey (Crypt-generated RSA key): Public key of the TorDNS server
        """
        self.ipp = (ip, port)
        self.prikey = Crypt().generate_key()
        self.crypt = Crypt(public_key=pubkey, private_key=self.prikey)

    def _pull(self, s, length):
        message = ''
        while len(message) < length:
            message += s.recv(length - len(message))
        return message

    def _send_recv(self, payload, length):
        sock = socket.socket()
        sock.connect(self.ipp)
        sock.sendall(payload)

        payload = self._pull(sock, length)  # TODO: GET RIGHT LENGTH
        return self.crypt.decrypt_and_auth(payload)

    def register(self, ip, port):
        """register

        Registers a new funion service to the TorDNS server

        Args:
            ip (str): Unpacked IP address to register
            port (int): Port to register

        Returns:
            (str, str): Two-tuple with new .funion URL service is registered to
                        and API key for future communications with TorDNS server
        """
        payload = struct.pack(">%ds4sL" % self.crypt.PUB_DER_LEN,
                              self.prikey.publickey().export("DER"),
                              socket.inet_aton(ip), port)
        payload = self.crypt.sign_and_encrypt(payload)

        resp = self._send_recv(payload, 10)  # TODO: GET RIGHT LENGTH
        resp = struct.unpack(">16s")




    def update(self, ip, port, apikey):
        """update

        Updates the IP and port of a funion service

        Args:
            ip (str): New, unpacked IP address to register
            port (int): New port to register
            apikey (str): API key of funion service

        Returns:
            bool: Whether or not update was successful
        """
        pass

    def deregister(self, apikey):
        """deregister

        Deregisters funion service from the TorDNS service

        Args:
            apikey (str): API key of funion service

        Returns:
            bool: Whether or not update was successful
        """
        pass

    def lookup(self, url):
        """lookup

        Looks up the IP and port of the funion service associated with a URL

        Args:
            url (str): url of funion service to lookup

        Returns:
            (str, int): Two-tuple of the IP and port of the funion service
        """
        pass
