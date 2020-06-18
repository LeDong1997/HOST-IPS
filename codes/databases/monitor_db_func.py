from .sqlite3_func import *
from codes.systems.file_func import *

MONITOR_DB_PATH = DB_PATH + "\\monitor.db"


# Create monitor database
def create_monitor_db():
    try:
        conn = get_connect_db(MONITOR_DB_PATH)
        with conn:
            cur = conn.cursor()

            # Create table storage list file check integrity
            # type : file [0] / dir [1]
            # state: new_add [0] / added [1]
            sql_query = "CREATE TABLE IF NOT EXISTS monitor_object(" \
                        + "id_object INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, " \
                        + "type INTEGER, " \
                        + "path TEXT(260))"
            cur.execute(sql_query)

            # Create table storage list integrity alert
            sql_query = "CREATE TABLE IF NOT EXISTS alert_monitor(" \
                        + "id_alert INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, " \
                        + "time TEXT, " \
                        + "user TEXT, " \
                        + "domain TEXT, " \
                        + "action TEXT, " \
                        + "resource TEXT(260), " \
                        + "note TEXT)"
            cur.execute(sql_query)

            conn.commit()
            return SUCCESS_CODE
    except sqlite3.Error as e:
        print("Error %s: " % e.args[0])
        return ERROR_CODE


# Insert or update sys_check_object to database
def insert_or_update_monitor_object(path_object, type_object):
    try:
        # Connect to database
        conn = get_connect_db(MONITOR_DB_PATH)
        with conn:
            cur = conn.cursor()
            # Search object in database
            cur.execute("SELECT * " +
                        "FROM monitor_object " +
                        "WHERE path = ? AND type = ?", (path_object, type_object))
            result = cur.fetchone()

            if result is None:
                cur.execute("INSERT INTO " + "monitor_object " +
                            "VALUES(?, ?, ?)", (None, type_object, path_object))
                conn.commit()
                print("Insert new monitor system object to database.")
            else:
                print("The monitor object exist in database.")
            return SUCCESS_CODE
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get list sys_check_object from database
def get_list_monitor_object():
    try:
        conn = get_connect_db(MONITOR_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM monitor_object")
            return cur.fetchall()
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Remove sys_check_object by path_object and type_object
def remove_monitor_object(path_object, type_object):
    try:
        conn = get_connect_db(MONITOR_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("DELETE " +
                        "FROM monitor_object " +
                        "WHERE path = ? AND type = ?", (path_object, type_object))
            if cur.rowcount > 0:
                print("Remove {} record(s)".format(cur.rowcount))
            else:
                print("The monitor_object don't exist in database.")
            conn.commit()
            return SUCCESS_CODE
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get list alert in 7 day ago
def get_list_alert_7day_ago(start_time):
    print(start_time)
    try:
        conn = get_connect_db(MONITOR_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM alert_monitor " +
                        "WHERE time > ? "
                        "ORDER BY time DESC " +
                        "LIMIT 1000", (start_time, ))
            return cur.fetchall()
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get list alert in start_time and end_time
def get_list_alert_at_time(start_time, end_time):
    try:
        conn = get_connect_db(MONITOR_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM alert_monitor " +
                        "WHERE time > ? AND time < ? "
                        "ORDER BY time DESC " +
                        "LIMIT 1000", (start_time, end_time))
            return cur.fetchall()
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Insert alert to monitor table
def insert_alert_monitor(alert_dict):
    try:
        conn = get_connect_db(MONITOR_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM alert_monitor " +
                        "WHERE time = ? AND resource = ?", (alert_dict['time'], alert_dict['resource'],))
            result = cur.fetchone()

            if result is None:
                cur.execute("INSERT INTO " +
                            "alert_monitor " +
                            "VALUES(?, ?, ?, ?, ?, ?, ?)",
                            (None, alert_dict['time'], alert_dict['user'], alert_dict['domain'], alert_dict['action'],
                             alert_dict['resource'], alert_dict['note']))
            conn.commit()
            return SUCCESS_CODE
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Remove all alert to monitor
def remove_all_alert_monitor():
    try:
        conn = get_connect_db(MONITOR_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("DROP TABLE " +
                        "IF EXISTS " +
                        "alert_monitor")
            conn.commit()
            return SUCCESS_CODE
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get 1000 list alert in database
def get_list_alert_limit_1000():
    try:
        conn = get_connect_db(MONITOR_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM alert_monitor " +
                        "ORDER BY time DESC " +
                        "LIMIT 1000")
            return cur.fetchall()
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE
