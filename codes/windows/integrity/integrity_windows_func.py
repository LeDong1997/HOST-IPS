import sys
import json
from codes.databases.integrity_db_func import *
from codes.systems.hash_func import *
from codes.systems.file_xml_func import *
from codes.systems.file_csv_func import *


def scan_integrity()


def main_integrity():
    try:
        create_integrity_db()
        argv = sys.argv
        argc = len(argv)

        if argc == 4:
            # Insert sys_check_object to database
            # Example: demo_integrity.py -i "test.txt" file[0] / directory [1]
            if argv[1] == '-i':
                result, error_msg = validate_insert_sys_check_object(argv[2], argv[3])
                if result == SUCCESS_CODE:
                    result = insert_or_update_sys_check_object(argv[2], argv[3])
                    check_list = get_list_sys_check_object()
                    print(json.dumps({'result': result == SUCCESS_CODE, 'check_list': check_list}))
                else:
                    print(json.dumps({'result': result == SUCCESS_CODE, 'error_msg': error_msg}))
            # Remove sys_check_object from database
            # Example: demo_integrity.py -r "test.txt" file[0] / directory [1]
            elif argv[1] == '-r':
                result = remove_sys_check_object(argv[2], argv[3])
                if result == SUCCESS_CODE:
                    check_list = get_list_sys_check_object()
                    print(json.dumps({'result': result == SUCCESS_CODE, 'check_list': check_list}))
                else:
                    print(json.dumps({'result': result == SUCCESS_CODE, 'error_msg': "Error remove sys_check_object"}))
            # Scan integrity for system
            # Example: demo_integrity.py -s "test.txt" file[0] / directory [1] / registry[3]
            elif argv[1] == '-s':
                res, msg = scan_integrity(argv[2], argv[3])
                # alertList = get_alert_list()
                success = res == 0
                if res != 0:
                    print(json.dumps({'result': success, 'error_msg': msg}))
                else:
                    print(json.dumps({'result': success, 'message': msg}))
            return SUCCESS_CODE
        else:
            if argc == 3:
                # Add sys_check_object from XML file
                # Example: demo_crypto.py -x sample.xml
                if argv[1] == '-x':
                    result, msg = validate_path_sys_check_object(argv[2])
                    if result == SUCCESS_CODE:
                        if msg == SYS_CHECK_OBJECT_XML_FILE:
                            result = add_sys_check_object_from_xml(argv[2])
                        elif msg == SYS_CHECK_OBJECT_CSV_FILE:
                            result = add_sys_check_object_from_csv(argv[2])
                        check_list = get_list_sys_check_object()
                        print(json.dumps({'result': result == SUCCESS_CODE, 'check_list': check_list}))
                    else:
                        print(json.dumps({'result': result == SUCCESS_CODE, 'error_msg': msg}))
                # Calculate the hash message (SHA-256) for file
                # Example: demo_crypto.py -m "test.txt"
                if argv[1] == '-m':
                    result = check_file_exist(FILE_TYPE, argv[2])
                    if result == FILE_NOT_FOUND_CODE:
                        print(json.dumps({'result': False, 'error_msg': "Path file invalid."}))
                    else:
                        result, msg = hash_sha256(argv[2])
                        if result == SUCCESS_CODE:
                            print(json.dumps({'result': True, 'hash_str': msg}))
                        else:
                            print(json.dumps({'result': False, 'error_msg': msg}))
                # Get list alert have id gather than id_alert old
                # Example: demo_crypto.py -a id
                if argv[1] == '-a':
                    result = get_list_last_alert_from_id(argv[2])
                    print(json.dumps({'list_alert': result}))
                return SUCCESS_CODE
            if argc == 2:
                # Get list sys_check_object from database
                # Example: demo_crypto.py -l
                if argv[1] == '-l':
                    check_list = get_list_sys_check_object()
                    if check_list == ERROR_CODE:
                        print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                    else:
                        print(json.dumps({'result': True, 'check_list': check_list}))
                    return SUCCESS_CODE
                # Get list last 1000 alert integrity from database
                # Example: demo_crypto.py -a
                elif argv[1] == '-a':
                    alert_list = get_list_alert_limit_1000()
                    if alert_list == ERROR_CODE:
                        print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                    else:
                        print(json.dumps({'result': True, 'alert_list': alert_list}))
                    return SUCCESS_CODE
                # Get last alert_id from database
                # Example: demo_crypto.py -e
                elif argv[1] == '-e':
                    id_alert = get_last_alert_id_integrity()
                    if id_alert == ERROR_CODE:
                        print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                    else:
                        print(json.dumps({'result': True, 'last_alert_id': id_alert}))
                    return SUCCESS_CODE
                # Get list hash_file from database
                # Example: demo_crypto.py -h
                elif argv[1] == '-h':
                    hash_file_list = get_list_hash_file_limit_1000()
                    if hash_file_list == ERROR_CODE:
                        print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                    else:
                        print(json.dumps({'result': True, 'hash_file_list': hash_file_list}))
                    return SUCCESS_CODE
                # Get list hash registry from database
                # Example: demo_crypto.py -g
                elif argv[1] == '-g':
                    hash_registry_list = get_list_hash_registry_limit_1000()
                    if hash_registry_list == ERROR_CODE:
                        print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                    else:
                        print(json.dumps({'result': True, 'hash_registry_list': hash_registry_list}))
                    return SUCCESS_CODE
                else:
                    return usage_integrity_func()
            return usage_integrity_func()
    except Exception as e:
        print(e)
        return ERROR_CODE


def usage_integrity_func():
    print("\nAdd argument to integrity check function.")
    print("-i [path] [type]: insert check object to database")
    print("-d [path] [type]: insert check object from database")
    print("\t[type]: the file[0] / folder[1] / registry[2]")
    print("Example:\n$ python demo_crypto.py -e -f \"C:\\test.txt\" \"abc\"")
    print("$ python demo_crypto.py -d -d \"C:\\test\" \"abc\" 1")
    return 0


# Validate insert system check object
def validate_insert_sys_check_object(path_object, type_object):
    # Validate type object
    if type_object == FILE_TYPE or str(type_object) == str(FILE_TYPE):
        result = check_file_exist(FILE_TYPE, path_object)
        if result == FILE_NOT_FOUND_CODE:
            return ERROR_CODE, "File don't exist. The sys_check_object invalid."
    elif type_object == DIR_TYPE or str(type_object) == str(DIR_TYPE):
        result = check_file_exist(DIR_TYPE, path_object)
        if result == DIR_NOT_FOUND_CODE:
            return ERROR_CODE, "Directory don't exist. The sys_check_object invalid."
    else:
        return ERROR_CODE, "The type object invalid."
    return SUCCESS_CODE, 'OK'


# Validate insert system integrity_object from XML file
def validate_path_sys_check_object(path_file):
    name_file = os.path.basename(path_file)
    ext_file = name_file[-3:]
    if ext_file == SYS_CHECK_OBJECT_XML_FILE or ext_file == SYS_CHECK_OBJECT_CSV_FILE:
        result = check_file_exist(FILE_TYPE, path_file)
        if result == FILE_NOT_FOUND_CODE:
            error_msg = "File " + name_file + " not found."
            return ERROR_CODE, error_msg
        else:
            return SUCCESS_CODE, ext_file
    else:
        error_msg = "The program only support XML or CSV file."
        return ERROR_CODE, error_msg
