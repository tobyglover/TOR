import sqlite3
from threading import Lock
from os import urandom, path, getcwd
import logging
import sys
from Circuit import ClientCircuit, PFCircuit, Circuit
from Crypt import Crypt


db_logger = logging.getLogger("CircuitDatabase")
db_logger.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
db_logger.addHandler(ch)


class CircuitNotFound(Exception):
    pass


class BadMethod(Exception):
    pass


class CircuitDatabase(object):

    def __init__(self, db_path=""):
        """CircuitDatabase

        Asynchronous SQLite database for Circuit objects

        Args:
            db_path (str, optional): Path to existing circuit database
                                     will create new database if not included
        """
        self.db_mutex = Lock()

        if db_path == '':
            db_path = getcwd() + "/circuitdb_" + urandom(2).encode("hex" + ".db")
        self.db = sqlite3.connect(db_path)
        self.cur = self.db.cursor()
        try:
            self.cur.execute("CREATE TABLE pfs (id text NOT NULL UNIQUE, pf text NOT NULL);")
            self.cur.execute("CREATE TABLE circuits (id text NOT NULL UNIQUE, circuit text NOT NULL);")
            self.db.commit()
        except sqlite3.OperationalError:
            pass

        db_logger.info("Initialized database")

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
            self.cur.execute("INSERT INTO pfs(id, pf) VALUES (?,?);", (circ.cid, circ.to_string()))
        else:
            self.cur.execute("INSERT INTO circuits(id, circuit) VALUES (?,?);", (circ.cid, circ.to_string()))

        self.db.commit()
        db_logger.info("Added ID: " + repr(circ.cid))
        return True
        # except sqlite3.IntegrityError:
        #     db_logger.info("Couldn't add ID: " + repr(circ.cid))
        #     return False

    @lock_db
    def _do_get(self, command, cid):
        self.cur.execute(command, (cid.encode('hex'),))
        c = self.cur.fetchone()
        if c:
            db_logger.info("Found circuit " + repr(cid))
            return c
        db_logger.error("Couldn't find circuit " + repr(cid))
        raise CircuitNotFound

    def get(self, header, hsh, crypt):
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
        method, cid, rest = header[:4], header[4:12], header[12:]

        if method == "ESTB":
            pf_raw = self._do_get("SELECT pf FROM pfs WHERE id = (?);", cid)
            pfc = PFCircuit(cid, pf_raw)
            pfc.auth_header(header, hsh, crypt)
            sid, symkey = rest[:8], rest[8:]
            return ClientCircuit(sid, prev_symkey=symkey)
        elif method == "CLNT":
            c_raw = self._do_get("SELECT circuit FROM circuits WHERE id = (?);", cid)
            circ = ClientCircuit(cid, c_raw, rest)
            circ.auth_header(header, hsh, crypt)
            return circ
        else:
            raise BadMethod

    @lock_db
    def remove(self, circ):
        """remove

        Removed a circuit from the database

        Args:
            circ (Circuit): circuit to remove
        """
        cid = circ.cid
        if circ.is_pf:
            self.cur.execute("DELETE FROM pfs WHERE id = (?);", (cid,))
        else:
            self.cur.execute("DELETE FROM circuits WHERE id = (?);", (cid,))
        db_logger.info("Removed circuit " + repr(cid))


if __name__ == "__main__":
    cd = CircuitDatabase(db_path="circuitdb_1234.db")
    cid = urandom(8)
    c = ClientCircuit(cid)
    cd.add(c)
    # cd.get('ABCD')
    cd.remove(c)
    cd.remove(c)
    # try:
    #     cd.get('ABCD')
    #     print "BAD"
    # except:
    #     print "GOOD"
    # cd.add(c)