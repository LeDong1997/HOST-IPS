import subprocess
from codes.databases.sqlite3_func import *
from codes.systems.file_func import *

# ----------------------------------- Handle Database -----------------------------------#

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
                        + "path TEXT(260), " \
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


# Insert or update sys_check_object to database
def insert_or_update_monitor_object(path_object, type_object, identity):
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
                            "VALUES(?, ?, ?, ?)", (None, type_object, path_object, identity))
                conn.commit()
                print("Insert new monitor system object to database.")
            else:
                print("The monitor object exist in database.")
            return SUCCESS_CODE
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
                conn.commit()
                return SUCCESS_CODE
            else:
                print("The monitor_object don't exist in database.")
                conn.commit()
                return ERROR_CODE
    except sqlite3.Error:
        print(QUERY_TABLE_DB_ERROR_MSG)
        return ERROR_CODE


# Get list sys_check_object from database
def get_list_monitor_object():
    try:
        conn = get_connect_db(MONITOR_DB_PATH)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT id_object, type, path, identity" +
                        "FROM monitor_object")
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


# ----------------------------------- Handle Audit Linux -----------------------------------#

# Add new audit rule for file / directory
def add_audit_rules(path_object, identity):
    try:
        with open(AUDIT_RULE_LINUX_PATH, 'r') as f_in:
            lines = f_in.readlines()
        with open(AUDIT_RULE_LINUX_PATH, 'w') as f_out:
            for line in lines:
                if line.strip("\n").find(path_object) == -1:
                    f_out.write(line)
                else:
                    if line.strip('\n')[0] == '#':
                        f_out.write(line)
            new_line = "-w " + path_object + " -p wa -k " + identity
            f_out.write(new_line)

        cmd = "service auditd restart"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        (output, err) = p.communicate()
        p.wait()
        result = str(output).find('error')
        if result != -1:
            print("Error in add audit permission for object.")
            return ERROR_CODE
        print("Done restart audit service")
        return SUCCESS_CODE
    except Exception as e:
        print(e)
        return ERROR_CODE


# Remove audit rule for file / directory
def remove_audit_rules(path_object):
    flag = False
    try:
        with open(AUDIT_RULE_LINUX_PATH, 'r') as f_in:
            lines = f_in.readlines()
        with open(AUDIT_RULE_LINUX_PATH, 'w') as f_out:
            for line in lines:
                if line.strip("\n").find(path_object) == -1:
                    f_out.write(line)
                else:
                    if line.strip('\n')[0] == '#':
                        f_out.write(line)
                    else:
                        flag = True
        if flag is False:
            print("Cannot find object in audit rule file.")
            return ERROR_CODE
        else:
            cmd = "service auditd restart"
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            (output, err) = p.communicate()
            p.wait()
            result = str(output).find('error')
            if result != -1:
                print("Error in add audit permission for object.")
                return ERROR_CODE
            print("Done restart audit service")
            return SUCCESS_CODE
    except Exception as e:
        print(e)
        return ERROR_CODE


def del_event(event_id):
    key_word = ":" + str(event_id) + "):"
    try:
        with open(PATH_AUDIT_LOG, 'r') as f_in:
            lines = f_in.readlines()
        with open(PATH_AUDIT_LOG, 'w') as f_out:
            for line in lines:
                if line.strip("\n").find(key_word) == -1:
                    f_out.write(line)
        return SUCCESS_CODE
    except Exception as e:
        print(e)
        return ERROR_CODE


def read_audit_log(path_file):
    print(path_file)
    # cmd = "ausearch -f " + path_file + " -ts today | aureport -i -f"
    cmd = "ausearch -f " + path_file + " -ts 01/08/2020 10:03:16 | aureport -i -f"
    print(cmd, 123)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    result = p.stdout.read().decode()
    print(result)
    print(1234)


def scan_audit_log_by_object(path_object, identity):
    print("\nHandle: " + path_object)
    cmd = "ausearch -f " + path_object + " -k " + identity + " | aureport -i -f"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    lines = p.stdout.read().decode()
    for line in lines:
        print(line)


# Scan all audit in windows event log
def scan_all_audit_log():
    check_list = get_list_monitor_object()
    msg = "Empty monitor object."
    if check_list is None:
        print(msg)
        return SUCCESS_CODE, msg
    elif check_list == ERROR_CODE:
        return ERROR_CODE, "Cannot connect database."

    try:
        for object_monitor in check_list:
            scan_audit_log_by_object(object_monitor[2], object_monitor[3])
        return SUCCESS_CODE, "Done analysis audit log."
    except Exception as e:
        print(e)
        return ERROR_CODE, "Cannot handle audit file"
