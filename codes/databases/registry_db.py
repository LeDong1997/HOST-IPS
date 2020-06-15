from .sqlite3_func import *
from codes.program_msg import *

INTEGRITY_DB_PATH = DB_PATH + "\\integrity.db"


# Get all registry record by keylist
def get_registry_by_key_list(keyList=[]):
    sql = "SELECT * " + "" \
          "FROM hash_registry "
    if len(keyList) > 0:
        sql = sql + "WHERE "
        i = 0
        while i < len(keyList) - 1:
            sql = sql + "path_registry like \"{}%\" OR ".format(keyList[i])
            i = i+1

        sql = sql + "path_registry like \"{}%\"".format(keyList[i])

    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute(sql)
            return cur.fetchall()
    except sqlite3.Error as e:
        print(e)
        return []


# if success return SUCCESS_CODE
# ekse return ERROR_CODE
def insert_registry_hash(name, hash_str, time, cur):
    res = ERROR_CODE
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO " + "registry_hash " +
                        "VALUES(?, ?, ?, ?, ?)", (None, name, hash_str, time, 0))
            conn.commit()
            res = SUCCESS_CODE
    except sqlite3.Error as e:
        print(e)
    return res


# insert many record by records to db
# Return ERROR_CODE if error, else return SUCCESS_CODE
def insert_many_registry_hash(records):
    res = ERROR_CODE
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.executemany("INSERT INTO " + "hash_registry " +
                            "VALUES(?, ?, ?, ?)", records)
            conn.commit()
            res = SUCCESS_CODE
    except sqlite3.Error as e:
        print(e)
    return res


# update many record by records to db
# Return ERROR_CODE if error, else return SUCCESS_CODE
def update_many_registry_hash(records):
    res = ERROR_CODE
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.executemany("UPDATE  " + "hash_registry " +
                            "SET hash_str = ?, last_change = ? WHERE id_registry = ?", records)
            conn.commit()
            res = SUCCESS_CODE
    except sqlite3.Error as e:
        print(e)
    return res


# delete many record by lis id records to db
# Return ERROR_CODE if error, else return SUCCESS_CODE
def delete_many_registry_hash(records):
    res = ERROR_CODE
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.executemany("DELETE FROM " + "hash_registry " +
                            "WHERE id_registry = ?", records)
            conn.commit()
            res = SUCCESS_CODE
    except sqlite3.Error as e:
        print(e)
    return res


def insert_many_registry_log(record):
    res = ERROR_CODE
    if len(record) == 0:
        return SUCCESS_CODE
    try:
        conn = get_connect_db(INTEGRITY_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.executemany("INSERT INTO " + "alert_integrity " +
                            "VALUES(?, ?, ?, ?)", record)
            conn.commit()
            res = SUCCESS_CODE
    except sqlite3.Error as e:
        print(e)
    return res
