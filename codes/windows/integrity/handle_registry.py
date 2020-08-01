import winreg
import hashlib
from datetime import timedelta
from codes.databases.integrity_db_func import *
from codes.databases.registry_db import *

# Define registry key
DEF_WINREG = {
    'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
    'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
    'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
    'HKEY_CURRENT_CONFIG': winreg.HKEY_CURRENT_CONFIG,
    'HKEY_USERS': winreg.HKEY_USERS,
    'HKEY_DYN_DATA': winreg.HKEY_DYN_DATA,
    'HKEY_PERFORMANCE_DATA': winreg.HKEY_PERFORMANCE_DATA
}

# Global variable
current_registry = {}
database_registry = {}

read_key = 0
read_value = 0
unread_key = 0

res = {}


# return False if hash error
# else return hex string hash 1 result
def hash1Str(str_value):
    try:
        hash_alo = hashlib.sha256()
        hash_alo.update(str_value.encode())
    except Exception as e:
        print(e, 123)
        return ERROR_CODE
    return hash_alo.hexdigest()


# loopkup key store in currRegistry
def tryLookupKey(path, hkey):
    global read_value, unread_key, read_key, current_registry
    read_key = read_key + 1
    try:
        hkeyInfo = winreg.QueryInfoKey(hkey)
        current_registry[path] = (hash1Str(''), hkeyInfo[2], 0)
        # read value in key
        for i in range(hkeyInfo[1]):
            n, v, t = winreg.EnumValue(hkey, i)
            name = path + '->' + n

            # hash n+t+v as string
            strv = n + str(t) + str(v)
            ret = hash1Str(strv)
            if ret != ERROR_CODE:
                current_registry[name] = (ret, hkeyInfo[2])
            read_value = read_value + 1

        # lookup sub key
        for i in range(hkeyInfo[0]):
            subKeyName = winreg.EnumKey(hkey, i)
            try:
                subKey = winreg.OpenKey(hkey, subKeyName, access=winreg.KEY_READ | winreg.KEY_WOW64_32KEY)
            except Exception as e:
                print(e, "123a")
                try:
                    subKey = winreg.OpenKey(hkey, subKeyName, access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                except Exception as e:
                    print(e, "123b")
                    unread_key = unread_key + 1
                continue

            tryLookupKey(path + '\\' + subKeyName, subKey)
        return SUCCESS_CODE
    except EnvironmentError as e:
        print(e, "123c")
        return ERROR_CODE


# convert tuple to dictionary by use name as key
def fromTupeToDic(src):
    if src is None or len(src) == 0:
        return {}
    ret = {}
    for i in range(len(src)):
        tmp = src[i]
        key = tmp[1]
        value = (tmp[0], tmp[2], tmp[3])
        ret[key] = value
    return ret


# return rootHkey, pathToKey such as winreg.HKEY_LOCAL_MACHINE, bla bla  and path to key from rootHkey
# if not found return None, ''
def getHKeyRoot(hkeyStr):
    spl = hkeyStr.split("\\", 1)
    if spl is None or len(spl) == 0:
        return None, ''
    pathKey = ''
    if len(spl) == 2:
        pathKey = spl[1]
    rkey = spl[0]
    rHkey = None

    if rkey in DEF_WINREG:
        rHkey = DEF_WINREG[rkey]
    return rHkey, pathKey


# Do read with one keyPath, and all of key it contain
# Retun SUCCESS_CODE if not error
# Else retun ERROR_CODE
def doReadReg(keyPath):
    global read_key, read_value, unread_key
    rHkey, path = getHKeyRoot(keyPath)

    if rHkey is None:
        return ERROR_CODE
    try:
        hkey = winreg.OpenKey(rHkey, path)
        hkeyInfo = winreg.QueryInfoKey(hkey)
    except WindowsError as e:
        print(e, "123d")
        return ERROR_CODE
    tryLookupKey(keyPath, hkey)
    # db_print("All key: {}  All value {}  All unread {}".format(readedKey, readedValue, unreadKey))


# load registry to currRegistry
# Return list key config
def readRegistry(regKeyList):
    for key in regKeyList:
        doReadReg(key)


# load registry stored in db
# read registry from db to dbRegistry
def loadRegistry(listKey=None):
    global res, database_registry
    res = get_registry_by_key_list(listKey)
    if res == ERROR_CODE:
        res = []
    database_registry = fromTupeToDic(res)
    # db_print("Db reg: {}".format(len(dbRegistry)))


# check if is key or value
def isKey(s):
    return not ('->' in s)


def insert_log(delList, updateList, insert_list, scan_time):
    # db: id, time, status, path
    iList = []
    for reg in delList:
        if isKey(reg[1]):
            iList.append((None, scan_time) + (KEY_DEL, reg[1]))
        else:
            iList.append((None, scan_time) + (VALUE_DEL, reg[1]))

    insert_many_registry_log(iList)
    # if(ret == SUCCESS_CODE):
    #     # db_print("Insert log del success")
    # db_print(iList)

    del iList
    iList = []
    for reg in updateList:
        iList.append((None, scan_time, VALUE_CHANGE, reg[1]))
    insert_many_registry_log(iList)
    # if(ret == SUCCESS_CODE):
    #     db_print("Update log update success")
    # db_print(iList)

    del iList
    iList = []
    for reg in insert_list:
        if isKey(reg[1]):
            iList.append((None, scan_time, KEY_ADD, reg[1]))
        else:
            iList.append((None, scan_time, VALUE_ADD, reg[1]))

    insert_many_registry_log(iList)
    # if(ret == SUCCESS_CODE):
    #     db_print("Insert log insert success")
    # db_print(iList)


def getDateTimeReadable(timeDelta):
    timeDeltaMilisec = timeDelta / 10
    return datetime(1601, 1, 1) + timedelta(microseconds=timeDeltaMilisec)


def doCheck(time_scan, insert_alert=True):
    global read_key, unread_key, read_value
    insertList = []
    updateList = []
    reUpdateList = []
    delIdList = []
    global database_registry, current_registry
    # {name : (hash_str, last_change)}
    for curName in current_registry:
        curVal = current_registry[curName]
        if curName in database_registry:
            dbVal = database_registry[curName]
            dbCmpVal = (dbVal[1], dbVal[2])
            if dbCmpVal != curVal:

                if isKey(curName):
                    updateList.append((curVal[0], curVal[1], dbVal[0]))
                elif dbCmpVal[0] != curVal[0]:
                    # (hash_str, name_registry, last_change, id_registry)s
                    updateList.append((curVal[0], curVal[1], dbVal[0]))
                    reUpdateList.append((dbVal[0], curName, curVal[0], curVal[1]))
            del database_registry[curName]

        else:
            insertList.append((None, curName, curVal[0], curVal[1]))
    delList = []
    for dname in database_registry:
        dval = database_registry[dname]
        delIdList.append((dval[0],))

        delList.append((dval[0], dname) + dval[1:3])

    del database_registry

    dret = delete_many_registry_hash(delIdList)

    uret = update_many_registry_hash(updateList)

    iret = insert_many_registry_hash(insertList)

    del updateList
    updateList = reUpdateList
    if insert_alert:
        insert_log(delList, updateList, insertList, time_scan)
    # data read from windows system

    sumary = {
        "readed_key_num": read_key,
        "unread_key_num": unread_key,
        "readed_value_num": read_value,
        "update_num": len(updateList),
        "update_status": uret == SUCCESS_CODE,
        "insert_num": len(insertList),
        "insert_status": iret == SUCCESS_CODE,
        "delete_num": len(delIdList),
        "delete_status": dret == SUCCESS_CODE
    }
    # if len(updateList) > 10:
    #     updateList = updateList[:9]
    # if len(insertList) > 10:
    #     insertList = insertList[:9]
    # if len(delList) > 10:
    #     delList = delList[:9]
    # detail = {
    #         "update_list": updateList,
    #         "insert_list": insertList,
    #         "delete_list": delList
    #         }
    # res = {'sumary': sumary, 'detail': detail}
    return sumary


def doReset():
    global read_value, read_key, unread_key, current_registry, database_registry
    read_value = 0
    read_key = 0
    unread_key = 0
    current_registry = {}
    database_registry = {}


# Reset global variable
def reset_global_var():
    global read_key, read_value, unread_key, current_registry, database_registry
    current_registry = {}
    database_registry = {}

    read_key = 0
    read_value = 0
    unread_key = 0


# Scan integrity for registry key
def scan_registry_key(path_registry, current_time):
    print('### \nStarting check integrity for registry key ...')

    error_msg = 'The error connect to database.'
    info_sys_check = get_info_sys_check_object(REGISTRY_TYPE, path_registry)

    if info_sys_check == ERROR_CODE:
        return ERROR_CODE, error_msg

    if info_sys_check is None:
        error_msg = 'The registry is not in check list.'
        return ERROR_CODE, error_msg

    reset_global_var()
    insert_alert_flag = info_sys_check[3] != SYS_CHECK_OBJECT_NEW

    list_key = [path_registry]

    readRegistry(list_key)
    loadRegistry(list_key)

    ret = doCheck(current_time, insert_alert_flag)

    if ret != ERROR_CODE and insert_alert_flag is False:
        update_state_sys_check_object_by_id(info_sys_check[0])

    msg = 'Done check integrity for registry.'
    print(msg)
    return SUCCESS_CODE, msg


def scan(registry, path_key):
    try:
        raw_key = winreg.OpenKey(registry, path_key)
        sub_key_count, values_count, last_modified = winreg.QueryInfoKey(raw_key)
        sub_key = winreg.OpenKey(registry, path_key)
        print(path_key + "\\")
        for i in range(values_count):
            name, value, type_value = winreg.EnumValue(sub_key, i)
            print("So i = ", i, ' ;ten = ', name, ' ;Gia tri = ', value, ' ;Loai = ', type_value)
        winreg.CloseKey(sub_key)

        for i in range(sub_key_count):
            sub_key_name = winreg.EnumKey(raw_key, i)
            path_sub_key = path_key + "\\" + sub_key_name
            scan(registry, path_sub_key)
        winreg.CloseKey(raw_key)
    except WindowsError as e:
        if e.winerror == 5:
            print(ACCESS_DENIED_CODE)

        # Access denied = 5
        print(e.winerror)
        print('Loi')
        # winreg.CloseKey(raw_key)


def test_registry():
    # DEF_WINREG = {'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE}
    registry = winreg.ConnectRegistry(None, DEF_WINREG['HKEY_LOCAL_MACHINE'])
    path_key = r"SYSTEM\ActivationBroker"
    scan(registry, path_key)
