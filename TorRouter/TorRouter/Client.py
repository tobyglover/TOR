import sqlite3
from threading import Lock
from os import urandom, path, getcwd
import sys
import logging

db_logger = logging.getLogger("CircuitDatabase")
db_logger.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
db_logger.addHandler(ch)


class Circuit(object):

    def __init__(self, from_string=None, is_pf=False):
        self.is_pf = is_pf
        self.id = "ABCD"

    def to_string(self):
        return "THIS IS THE STRING"


class CircuitNotFound(Exception):
    pass


class CircuitDatabase(object):

    def __init__(self, db_path=""):
        """CircuitDatabase

        Asynchronous SQLite database for Circuit objects

        Args:
            db_path (str, optional): Path to existing circuit databse
        """
        self.db_mutex = Lock()

        if db_path == '':
            db_path = getcwd() + "/circuitdb_" + urandom(2).encode("hex" + ".db")
        self.db = sqlite3.connect(db_path)
        self.cur = self.db.cursor()
        try:
            self.cur.execute("CREATE TABLE pfs (id text NOT NULL UNIQUE, pf text NOT NULL UNIQUE);")
            self.cur.execute("CREATE TABLE circuits (id text NOT NULL UNIQUE, circuit text NOT NULL UNIQUE);")
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
            try:
                result = func(self, *args)
                self.db.commit()
                e = None
            except Exception as e:
                pass
            finally:
                self.db_mutex.release()
                if e:
                    raise e
                return result

        return func_wrap

    @lock_db
    def add(self, circ):
        """add

        Args:
            circ (Circuit): Circuit to add to the database
        """
        try:
            if circ.is_pf:
                self.cur.execute("INSERT INTO pfs(id, pf) VALUES (?,?);", (circ.id, circ.to_string()))
            else:
                self.cur.execute("INSERT INTO circuits(id, circuit) VALUES (?,?);", (circ.id, circ.to_string()))

            self.db.commit()
            db_logger.info("Added ID: " + repr(circ.id.encode('hex')))
            return True
        except sqlite3.IntegrityError:
            db_logger.info("Couldn't add ID: " + repr(circ.id.encode('hex')))
            return False

    @lock_db
    def get(self, id, is_pf=False):
        if is_pf:
            self.cur.execute("SELECT pf FROM pfs WHERE id = (?);", (id,))
        else:
            self.cur.execute("SELECT circuit FROM circuits WHERE id = (?);", (id,))

        c = self.cur.fetchone()
        if c:
            db_logger.info("Found circuit " + repr(id.encode('hex')))
            return Circuit(from_string=c)
        db_logger.error("Couldn't find circuit " + repr(id.encode('hex')))
        raise CircuitNotFound

    @lock_db
    def remove(self, id, is_pf=False):
        if is_pf:
            self.cur.execute("DELETE FROM pfs WHERE id = (?);", (id,))
        else:
            self.cur.execute("DELETE FROM circuits WHERE id = (?);", (id,))
        db_logger.info("Removed circuit " + repr(id.encode('hex')))


cd = CircuitDatabase(db_path="circuitdb_1234")
c = Circuit()
cd.add(c)
cd.get('ABCD')
cd.remove('ABCD')
try:
    cd.get('ABCD')
    print "BAD"
except:
    print "GOOD"
# cd.add(c)
