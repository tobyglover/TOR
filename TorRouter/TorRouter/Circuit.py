
import sys
import logging
from Crypt import Crypt, Symmetric
from Crypto.PublicKey import RSA




class Circuit(object):

    def __init__(self, cid, is_pf, prev_symkey=None, payload=None, pubkey=None):
        self.cid = cid.encode('hex')
        self.pubkey = pubkey
        self.is_pf = is_pf

    def to_string(self):
        return "THIS IS THE STRING"

    def verify_header(self, header):
        pass

    def forward_payload(self):
        pass

    def forward_response(self):
        pass

    def auth_header(self, header, hsh, crypt):
        """auth_header

        Args:
            header (str): header to authenticate
            crypt (Crypt): Crypt object to authenticate with

        Raises:
            ValueError: if authentication fails
        """
        crypt.setPublicKey(self.pubkey)
        crypt.auth(header, hsh)


class PFCircuit(Circuit):

    def __init__(self, cid, from_string=None, pubkey=None):
        super(PFCircuit, self).__init__(cid, True)

        if from_string:
            self.pf_pubkey = RSA.importKey(from_string)
        else:
            self.pf_pubkey = pubkey


class ClientCircuit(Circuit):

    def __init__(self, cid, from_string=None, prev_symkey=None):
        super(ClientCircuit, self).__init__(cid, False)





