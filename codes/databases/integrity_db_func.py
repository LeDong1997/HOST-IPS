from .sqlite3_func import *
from codes.systems.file_func import *

if os_type == WINDOWS_PLATFORM or os_type == UNKNOWN_PLATFORM:
    INTEGRITY_DB_PATH = DB_PATH + "\\integrity.db"
else:
    INTEGRITY_DB_PATH = DB_PATH + "//integrity.db"


# Create integrity database
def create_integrity_db():
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()

            # Create table storage hash string for file
            sql_query = "CREATE TABLE IF NOT EXISTS hash_file(" \
                        + "id_file INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, " \
                        + "path_file TEXT(260), " \
                        + "hash_str TEXT(64))"
            cur.execute(sql_query)

            # Create table storage hash string for registry
            sql_query = "CREATE TABLE IF NOT EXISTS hash_registry(" \
                        + "id_registry INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, " \
                        + "path_registry TEXT(260), " \
                        + "hash_str TEXT(64), " \
                        + "last_change INTEGER)"
            cur.execute(sql_query)

            # Create table storage list file check integrity
            # type : file [0] / dir [1] / registry [2]
            # state: new_add [0] / added [1]
            sql_query = "CREATE TABLE IF NOT EXISTS sys_check_object(" \
                        + "id_object INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, " \
                        + "type INTEGER, " \
                        + "path TEXT(260), " \
                        + "state INTEGER DEFAULT 0, " \
                        + "ignore INTEGER DEFAULT 0)"
            cur.execute(sql_query)

            # Create table storage list integrity alert
            sql_query = "CREATE TABLE IF NOT EXISTS alert_integrity(" \
                        + "id_alert INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, " \
                        + "time TEXT, " \
                        + "state TEXT, " \
                        + "path TEXT(260))"
            cur.execute(sql_query)

            conn.commit()
            return SUCCESS_CODE
    except sqlite3.Error as e:
        print("Error %s: " % e.args[0])
        return ERROR_CODE


# Insert or update sys_check_object to database
def insert_or_update_sys_check_object(path_object, type_object):
    try:
        # Connect to database
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            # Search object in database
            cur.execute("SELECT * " +
                        "FROM sys_check_object " +
                        "WHERE path = ?", (path_object, ))
            result = cur.fetchone()

            if result is None:
                cur.execute("INSERT INTO " + "sys_check_object " +
                            "VALUES(?, ?, ?, ?, ?)", (None, type_object, path_object, SYS_CHECK_OBJECT_NEW, 0))
                conn.commit()
                print("Insert new integrity system object to database.")
            elif str(result[1]) != type_object:
                cur.execute("UPDATE sys_check_object " +
                            "SET type = ?, state = ? " +
                            "WHERE id_object = ?", (type_object, SYS_CHECK_OBJECT_NEW, result[0]))
                conn.commit()
                print("Update integrity system object to database.")
            return SUCCESS_CODE
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get list sys_check_object from database
def get_list_sys_check_object():
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM sys_check_object")
            return cur.fetchall()
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Remove sys_check_object by path_object and type_object
def remove_sys_check_object(path_object, type_object):
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("DELETE " +
                        "FROM sys_check_object " +
                        "WHERE path = ? AND type = ?", (path_object, type_object))
            if cur.rowcount > 0:
                print("Remove {} record(s)".format(cur.rowcount))
            else:
                print("The sys_check_object don't exist in database.")
            conn.commit()
            return SUCCESS_CODE
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get list alert have id gather than id_alert old
def get_list_last_alert_from_id(id_alert):
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM alert_integrity " +
                        "WHERE id > ? ORDER BY time DESC", (id_alert, ))
            return cur.fetchall()
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return []


# Get 1000 list alert in database
def get_list_alert_limit_1000():
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM alert_integrity " +
                        "ORDER BY time DESC " +
                        "LIMIT 1000")
            return cur.fetchall()
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get last alert_id from database
def get_last_alert_id_integrity():
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT id_alert " +
                        "FROM alert_integrity " +
                        "ORDER BY time DESC " +
                        "LIMIT 1")
            result = cur.fetchone()
            if result is None:
                return 0
            else:
                return result[0]
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get 1000 list hash_file in database
def get_list_hash_file_limit_1000():
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM hash_file " +
                        "LIMIT 1000")
            return cur.fetchall()
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get 1000 list hash_file in database
def get_list_hash_registry_limit_1000():
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM hash_registry " +
                        "LIMIT 1000")
            return cur.fetchall()
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Check sys_check_object exist in database
def is_sys_check_object_exist(path_object, type_object):
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM sys_check_object " +
                        "WHERE type = ? AND path = ?", (type_object, path_object))
            return cur.fetchone()
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get hash record from database
def get_hash_record_db(type_object, path_object):
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            if type_object == FILE_TYPE:
                cur.execute("SELECT id_file, path_file, hash_str " +
                            "FROM hash_file " +
                            "WHERE path_file = ?", (path_object,))
            if type_object == REGISTRY_TYPE:
                cur.execute("SELECT id_registry, path_registry, hash_str, last_change " +
                            "FROM hash_registry " +
                            "WHERE name_registry = ?", (path_object,))
            return cur.fetchone()
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Delete hash record by id
def del_hash_record_by_id(type_object, id_object):
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            if type_object == FILE_TYPE:
                cur.execute("DELETE " +
                            "FROM hash_file " +
                            "WHERE id_file = ?", (id_object,))
            if type_object == REGISTRY_TYPE:
                cur.execute("DELETE " +
                            "FROM hash_registry " +
                            "WHERE id_registry = ?", (id_object,))
            conn.commit()
            return SUCCESS_CODE
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Insert alert to alert_integrity
def insert_alert_integrity(current_time, state, path):
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO " + "alert_integrity " +
                        "VALUES(?, ?, ?, ?)", (None, current_time, state, path))
            conn.commit()
            return SUCCESS_CODE
    except sqlite3.Error as e:
        print(e)
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Insert hash record to database
def insert_hash_to_db(type_object, path_object, hash_str):
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            if type_object == FILE_TYPE:
                cur.execute("INSERT INTO " + "hash_file " +
                            "VALUES(?, ?, ?)", (None, path_object, hash_str))
                conn.commit()
            elif type_object == REGISTRY_TYPE:
                cur.execute("INSERT INTO " + "hash_registry " +
                            "VALUES(?, ?, ?)", (None, path_object, hash_str))
            return SUCCESS_CODE
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get information of sys_check_object
def get_info_sys_check_object(type_object, path_object):
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM sys_check_object " +
                        "WHERE type = ? AND path = ?", (type_object, path_object))
            return cur.fetchone()
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Change state of sys_check_object
def update_state_sys_check_object_by_id(id_object):
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("UPDATE sys_check_object " +
                        "SET state = ? "
                        "WHERE id_object = ?", (SYS_CHECK_OBJECT_OLD, id_object))
            conn.commit()
            print("Change state of sys_check_object.")
            return SUCCESS_CODE
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


def update_hash_record_by_id(type_object, id_object, hash_str):
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            if type_object == FILE_TYPE:
                cur.execute("UPDATE hash_file " +
                            "SET hash_str = ? " +
                            "WHERE id_file = ?", (hash_str, id_object))
            elif type_object == REGISTRY_TYPE:
                cur.execute("UPDATE hash_registry " +
                            "SET hash_str = ? " +
                            "WHERE id_registry = ?", (hash_str, id_object))
            conn.commit()
            return SUCCESS_CODE
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get list file in current diriectory
def get_list_file_from_current_dir_and_child(path_dir):
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM hash_file "
                        "WHERE path_file LIKE ? ", (path_dir + "\\%", ))
            return cur.fetchall()
    except sqlite3.Error as e:
        print(e)
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get list alert in 7 day ago
def get_list_alert_7day_ago(start_time):
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM alert_integrity " +
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
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * " +
                        "FROM alert_integrity " +
                        "WHERE time > ? AND time < ? "
                        "ORDER BY time DESC " +
                        "LIMIT 1000", (start_time, end_time))
            return cur.fetchall()
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE
