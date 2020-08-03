from codes.databases.sqlite3_func import *
from codes.systems.file_func import *


# Handle database
MONITOR_DB_PATH = DB_PATH + "//monitor.db"


# Create monitor database
def create_monitor_db():
    try:
        conn = get_connect_db(MONITOR_DB_PATH)
        with conn:
            cur = conn.cursor()

            # Create table storage list file check integrity
            # type : file [0] / dir [1]
            sql_query = "CREATE TABLE IF NOT EXISTS monitor_object(" \
                        + "id_object INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, " \
                        + "type INTEGER, " \
                        + "path TEXT(260)" \
                        + "identity TEXT(260))"
            cur.execute(sql_query)

            # Create table storage list integrity alert
            sql_query = "CREATE TABLE IF NOT EXISTS alert_monitor(" \
                        + "id_alert INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, " \
                        + "time TEXT, " \
                        + "user TEXT, " \
                        + "syscall TEXT, " \
                        + "resource TEXT(260), " \
                        + "process TEXT, " \
                        + "state TEXT)"
            cur.execute(sql_query)

            conn.commit()
            return SUCCESS_CODE
    except sqlite3.Error as e:
        print("Error %s: " % e.args[0])
        return ERROR_CODE

