import sys
import json
from datetime import timedelta

from codes.integrity.integrity_func import *


# Scan integrity for eacch sys_check_object for system
def scan_integrity_object(path_object, type_object):
    current_time = datetime.now()
    current_time = current_time.strftime('%Y-%m-%d %H:%M:%S')

    if type_object == FILE_TYPE or str(type_object) == str(FILE_TYPE):
        return scan_file(path_object, current_time)
    elif type_object == DIR_TYPE or str(type_object) == str(DIR_TYPE):
        return scan_dir(path_object, current_time)


def scan_all_integrity_object():
    check_list = get_list_sys_check_object()
    if check_list == ERROR_CODE:
        return ERROR_CODE

    if check_list is None:
        print('Check list is empty.')
        return SUCCESS_CODE
    else:
        for sys_object in check_list:
            scan_integrity_object(sys_object[2], sys_object[1])
        return SUCCESS_CODE


def main_integrity():
    try:
        create_integrity_db()
        argv = sys.argv
        argc = len(argv)

        if argc == 4:
            # Insert sys_check_object (file / directory) to database
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
            # Scan integrity for eacch sys_check_object for system
            # Example: demo_integrity.py -s "test.txt" file[0] / directory [1]
            elif argv[1] == '-s':
                result, msg = scan_integrity_object(argv[2], argv[3])
                # alertList = get_alert_list()
                success = result == 0
                if result != 0:
                    print(json.dumps({'result': success, 'error_msg': msg}))
                else:
                    print(json.dumps({'result': success, 'msg': msg}))
            elif argv[1] == '-l':
                # Get integrity alert in start_time and end_time in database
                # Example: python demo_integrity.py -l "2020-06-08 10:24:19" "2020-06-10 10:24:19"
                alert_list = get_list_alert_at_time(argv[2], argv[3])
                if alert_list == ERROR_CODE:
                    print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                else:
                    print(json.dumps({'result': True, 'alert_list': alert_list}))
            return SUCCESS_CODE
        else:
            if argc == 3:
                # Add sys_check_object from XML file
                # Example: demo_integrity.py -x sample.xml
                if argv[1] == '-x':
                    result, msg = validate_path_sys_check_object(argv[2])
                    if result == SUCCESS_CODE:
                        if msg == SYS_CHECK_OBJECT_XML_FILE:
                            result = add_sys_check_object_from_xml_linux(argv[2])
                        elif msg == SYS_CHECK_OBJECT_CSV_FILE:
                            result = add_sys_check_object_from_csv_linux(argv[2])
                        check_list = get_list_sys_check_object()
                        print(json.dumps({'result': result == SUCCESS_CODE, 'check_list': check_list}))
                    else:
                        print(json.dumps({'result': result == SUCCESS_CODE, 'error_msg': msg}))
                # Calculate the hash message (SHA-256) for file
                # Example: demo_integrity.py -m "test.txt"
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
                # Example: demo_integrity.py -a id
                if argv[1] == '-a':
                    result = get_list_last_alert_from_id(argv[2])
                    print(json.dumps({'list_alert': result}))
                return SUCCESS_CODE
            if argc == 2:
                # Get list sys_check_object from database
                # Example: demo_integrity.py -l
                if argv[1] == '-l':
                    check_list = get_list_sys_check_object()
                    if check_list == ERROR_CODE:
                        print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                    else:
                        print(json.dumps({'result': True, 'check_list': check_list}))
                    return SUCCESS_CODE
                # Get list last 1000 alert integrity from database
                # Example: demo_integrity.py -a
                elif argv[1] == '-a':
                    alert_list = get_list_alert_limit_1000()
                    if alert_list == ERROR_CODE:
                        print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                    else:
                        print(json.dumps({'result': True, 'alert_list': alert_list}))
                    return SUCCESS_CODE
                # Get last alert_id from database
                # Example: demo_integrity.py -e
                elif argv[1] == '-e':
                    id_alert = get_last_alert_id_integrity()
                    if id_alert == ERROR_CODE:
                        print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                    else:
                        print(json.dumps({'result': True, 'last_alert_id': id_alert}))
                    return SUCCESS_CODE
                # Get list hash_file from database
                # Example: demo_integrity.py -h
                elif argv[1] == '-h':
                    hash_file_list = get_list_hash_file_limit_1000()
                    if hash_file_list == ERROR_CODE:
                        print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                    else:
                        print(json.dumps({'result': True, 'hash_file_list': hash_file_list}))
                    return SUCCESS_CODE
                # Scan all sys_check_object in database
                # Example: demo_integrity.py -s_a
                elif argv[1] == '-s_a':
                    result = scan_all_integrity_object()
                    if result == ERROR_CODE:
                        print(json.dumps({'result': result == SUCCESS_CODE, 'error_msg': "The error while check integrity."}))
                    else:
                        print(json.dumps({'result': result == SUCCESS_CODE, 'msg': 'Done check integrity for system.'}))
                    return SUCCESS_CODE
                elif argv[1] == '-l_7':
                    # Get integrity alert in 7 day ago in database
                    # Example: demo_integrity.py -l_7
                    current_time = datetime.now()
                    date_7_day_ago = current_time - timedelta(days=7)
                    date_7_day_ago = date_7_day_ago.strftime('%Y-%m-%d %H:%M:%S')
                    alert_list = get_list_alert_7day_ago(date_7_day_ago)
                    if alert_list == ERROR_CODE:
                        print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                    else:
                        print(json.dumps({'result': True, 'alert_list': alert_list}))
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
    print("\t[type]: the file[0] / folder[1]")
    print("Example:\n$ python demo_integrity.py -e -f \"C:\\test.txt\" \"abc\"")
    print("$ python demo_integrity.py -d -d \"C:\\test\" \"abc\" 1")
    return 0
