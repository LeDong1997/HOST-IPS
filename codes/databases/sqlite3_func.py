import sqlite3
import os
from codes.systems.os_func import *

os_type = os_check()

# Define path of database
if os_type == WINDOWS_PLATFORM or os_type == UNKNOWN_PLATFORM:
    DB_PATH = os.path.dirname(os.path.abspath(__file__)) + "\\..\\..\\databases"
else:
    DB_PATH = os.path.dirname(os.path.abspath(__file__)) + "//..//..//databases"


# Return conn or None
def get_connect_db(path_db):
    conn = None
    try:
        conn = sqlite3.connect(path_db)
    except sqlite3.Error as e:
        print("Error %s: " % e.args[0])
    return conn


# Check version sqlite3
def sqlite3_version(path_db):
    try:
        conn = get_connect_db(path_db)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT SQLITE_VERSION()")

            data = cur.fetchone()
            print("SQLite version: %s" % data)
    except sqlite3.Error as e:
        print("Error %s: " % e.args[0])
