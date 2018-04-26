import sqlite3
from threading import Lock
from os import urandom, getcwd
import logging
import sys
from Circuit import ClientCircuit, PFCircuit, Circuit
from Crypt import Crypt


cdb_logger = logging.getLogger("CircuitDatabase")
cdb_logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
cdb_logger.addHandler(ch)


class CircuitNotFound(Exception):
    pass


class BadMethod(Exception):
    pass


class CircuitDatabase(object):
    ESTB = "ESTB"
    CLNT = "CLNT"

    def __init__(self, db_path=None, rid=None, raw_pubkey=None):
        """CircuitDatabase

        Asynchronous SQLite database for Circuit objects

        Args:
            db_path (str, optional): Path to existing circuit database
                                     will create new database if not included
            rid (str, optional): RID to initialize pathfinding server entry to
            raw_pubkey (str, optional): pubkey to initialize pathfinding server entry to
        """
        self.db_mutex = Lock()

        if not db_path:
            db_path = getcwd() + "/circuitdb_" + urandom(2).encode("hex") + ".db"
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.cur = self.db.cursor()
        try:
            self.cur.execute("CREATE TABLE pfs (id BLOB NOT NULL UNIQUE, pubkey text NOT NULL);")
            self.cur.execute("CREATE TABLE circuits (id BLOB NOT NULL UNIQUE, circuit BLOB NOT NULL);")
            self.cur.execute("INSERT INTO pfs(id, pubkey) VALUES (?,?);",
                             (rid.encode('hex'), raw_pubkey.encode('hex')))
            self.db.commit()
        except sqlite3.OperationalError:
            pass

        cdb_logger.info("Initialized database")

    def __del__(self):
        self.db.close()

    def lock_db(func):
        """function wrapper for functions that require db access"""

        def func_wrap(self, *args):
            """acquire and release dbMuted if available"""
            # if self.db_mutex:
            self.db_mutex.acquire()
            result = None
            e = None
            try:
                result = func(self, *args)
                self.db.commit()
            except:
                e = sys.exc_info()
                pass
            finally:
                self.db_mutex.release()
                if e:
                    raise e[0], e[1], e[2]
                return result

        return func_wrap

    @lock_db
    def add(self, circ):
        """add

        Adds a Circuit to the database

        Args:
            circ (Circuit): Circuit to add to the database

        Returns:
            bool: whether or not the circuit was successfully added
        """
        # try:
        if circ.is_pf:
            self.cur.execute("INSERT INTO pfs(id, pubkey) VALUES (?,?);", (circ.cid.encode('hex'),
                                                                           circ.export()).encode('hex'))
        else:
            self.cur.execute("INSERT INTO circuits(id, circuit) VALUES (?,?);", (circ.cid.encode('hex'),
                                                                                 circ.export().encode('hex')))

        self.db.commit()
        cdb_logger.info("Added circuit " + repr(circ.cid.encode('hex')))
        return True

    @lock_db
    def _do_get(self, command, cid):
        self.cur.execute(command, (cid.encode("hex"),))
        c = self.cur.fetchone()
        if c:
            cdb_logger.debug("Found circuit " + repr(cid.encode('hex')[:8]))
            return c[0].decode('hex')
        cdb_logger.error("Couldn't find circuit " + repr(cid.encode('hex')[:8]))
        raise CircuitNotFound

    def get(self, header, crypt):
        """get

        Fetches a Circuit object from the database

        Args:
            header (str): decrypted (but not authenticated) header
            hsh (str): signed hash of header
            crypt (Crypt): crypt object to authenticate header with

        Returns:
            ClientCircuit:

        Raises:
            CircuitNotFound: if requested circuit is not in database
            BadMethod: if method is not supported
            ValueError: if authentication fails
        """
        header, hsh = crypt.decrypt(header)
        method, cid, rest = header[:4], header[4:12], header[12:]

        if method == self.ESTB:
            cdb_logger.info("Creating new client")
            pf_raw = self._do_get("SELECT pubkey FROM pfs WHERE id = (?);", cid)
            pfc = PFCircuit(cid, pf_raw)
            pfc.auth_header(header, hsh, crypt)
            sid, symkey = rest[:8], rest[8:]
            return self.ESTB, ClientCircuit(sid, symkey, crypt)
        elif method == self.CLNT:
            cdb_logger.info("Finding old client")
            c_raw = self._do_get("SELECT circuit FROM circuits WHERE id = (?);", cid)
            circ = ClientCircuit(cid, rest, crypt, c_raw)
            circ.auth_header(header, hsh, crypt)
            return self.CLNT, circ
        else:
            cdb_logger.error("Bad method %s" % repr(method))
            raise BadMethod

    @lock_db
    def remove(self, circ):
        """remove

        Removed a circuit from the database

        Args:
            circ (Circuit): circuit to remove
        """
        cid = circ.cid.encode("hex")
        if circ.is_pf:
            self.cur.execute("DELETE FROM pfs WHERE id = (?);", (cid,))
        else:
            self.cur.execute("DELETE FROM circuits WHERE id = (?);", (cid,))
        cdb_logger.debug("Removed circuit " + repr(circ.name))


if __name__ == "__main__":
    cid = urandom(8)
    symkey = Crypt().generate_key()
    k1 = Crypt().generate_key()
    k2 = Crypt().generate_key()
    c_client = Crypt(public_key=k1.publickey(), private_key=k2)
    c_router = Crypt(public_key=k2.publickey(), private_key=k1)
    pkt = c_client.sign_and_encrypt("CLNT" + cid + symkey)
    data, hash = c_router.decrypt(pkt)

    cd = CircuitDatabase(db_path="circuitdb_1234.db")
    c = ClientCircuit(cid, cid, c_router)
    cd.add(c)
    # cd.get(data, hash, c_router)
    # cd.remove(c)
    # cd.remove(c)
    # try:
    #     cd.get('ABCD')
    #     print "BAD"
    # except:
    #     print "GOOD"
    # cd.add(c)
