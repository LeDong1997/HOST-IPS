import sys
import json
from codes.systems.hash_func import *
from codes.systems.file_xml_func import *
from codes.systems.file_csv_func import *
from codes.systems.os_func import *
from codes.windows.integrity.handle_registry import *


def scan_file(path_file, current_time):
    print('###\nStarting check integrity for file ...')

    error_msg = 'The error connect to database.'
    msg = 'Done check integrity for file.'
    info_sys_check = get_info_sys_check_object(FILE_TYPE, path_file)

    if info_sys_check == ERROR_CODE:
        return ERROR_CODE, error_msg

    if info_sys_check is None:
        error_msg = 'The file is not in check list.'
        return ERROR_CODE, error_msg

    hash_record = get_hash_record_db(FILE_TYPE, path_file)
    if hash_record == ERROR_CODE:
        return ERROR_CODE, error_msg

    result = check_file_exist(FILE_TYPE, path_file)
    # File remove
    if result == FILE_NOT_FOUND_CODE:
        result = remove_sys_check_object(path_file, FILE_TYPE)
        if result == ERROR_CODE:
            return ERROR_CODE, error_msg

        if hash_record is not None:
            result = del_hash_record_by_id(FILE_TYPE, hash_record[0])
            if result == ERROR_CODE:
                return ERROR_CODE, error_msg

            result = insert_alert_integrity(current_time, DELETE_FILE_MSG, path_file)
            print(DELETE_FILE_MSG + path_file)

            if result == ERROR_CODE:
                return ERROR_CODE, error_msg
        print(msg)
        return SUCCESS_CODE, msg

    # file exist
    insert_alert_flag = info_sys_check[3] != SYS_CHECK_OBJECT_NEW
    result, hash_str = hmac_sha256_password(path_file, DEFAULT_PASSWORD)
    if result == ERROR_CODE:
        return ERROR_CODE, 'Cannot caculate hash string for file.'

    # Cannot find data of file in database
    if hash_record is None:
        result = insert_hash_to_db(FILE_TYPE, path_file, hash_str)
        if result == ERROR_CODE:
            return ERROR_CODE, error_msg

        if insert_alert_flag:
            result = insert_alert_integrity(current_time, ADD_FILE_MSG, path_file)
            if result == ERROR_CODE:
                return ERROR_CODE, error_msg
            print(ADD_FILE_MSG + path_file)
        else:
            update_state_sys_check_object_by_id(info_sys_check[0])
    else:
        if hash_record[2] != hash_str:
            result = update_hash_record_by_id(FILE_TYPE, hash_record[0], hash_str)
            if result == ERROR_CODE:
                return ERROR_CODE, error_msg

            result = insert_alert_integrity(current_time, CHANGE_FILE_MSG, path_file)
            if result == ERROR_CODE:
                return ERROR_CODE, error_msg
            print(CHANGE_FILE_MSG + path_file)
    print(msg)
    return SUCCESS_CODE, msg


def compare_state(all_file, parent_dir, list_file, current_time, key, insert_alert_flag=True):
    add_s = 0
    add_i = 0
    add_u = 0

    for file in list_file:
        add_s = add_s + 1
        path_file = os.path.join(parent_dir, file)
        record = get_hash_record_db(FILE_TYPE, path_file)
        # Cannot connect to database
        if record == ERROR_CODE:
            continue

        result, hash_str = hmac_sha256_key(path_file, key)
        if result == ERROR_CODE:
            continue

        # Cannot find data of file in database
        if record is None:
            add_i = add_i + 1
            result = insert_hash_to_db(FILE_TYPE, path_file, hash_str)
            if result == SUCCESS_CODE and insert_alert_flag:
                insert_alert_integrity(current_time, ADD_FILE_MSG, path_file)
                print(ADD_FILE_MSG + path_file)

            if path_file in all_file:
                del all_file[path_file]
        else:
            # File is changed
            if record[2] != hash_str:
                add_u = add_u + 1
                result = update_hash_record_by_id(FILE_TYPE, record[0], hash_str)
                if result == SUCCESS_CODE:
                    insert_alert_integrity(current_time, CHANGE_FILE_MSG, path_file)
                    print(CHANGE_FILE_MSG + path_file)
            if path_file in all_file:
                del all_file[path_file]
    return all_file, add_s, add_i, add_u


def scan_dir(path_dir, current_time):
    print('### \nStarting check integrity for directory ...')

    error_msg = 'The error connect to database.'
    info_sys_check = get_info_sys_check_object(DIR_TYPE, path_dir)

    if info_sys_check == ERROR_CODE:
        return ERROR_CODE, error_msg

    if info_sys_check is None:
        error_msg = 'The directory is not in check list.'
        return ERROR_CODE, error_msg

    all_hash_record = get_list_file_from_current_dir_and_child(path_dir)

    file_scan = 0       # File scan in directory
    file_update = 0     # File update in directory
    file_del = 0        # File delete in directory
    file_add = 0        # File new add in directory

    # Check state sys_check_object is new or old
    insert_alert = (info_sys_check[3] != SYS_CHECK_OBJECT_NEW)

    result = check_file_exist(DIR_TYPE, path_dir)
    # The directory was remove
    if result == DIR_NOT_FOUND_CODE:
        for hash_record in all_hash_record:
            file_del = file_del + 1
            insert_alert_integrity(current_time, DELETE_FILE_MSG, hash_record[1])
            del_hash_record_by_id(FILE_TYPE, hash_record[0])
        remove_sys_check_object(path_dir, DIR_TYPE)
    else:
        all_hash_dic = convert_list_to_dic(all_hash_record)
        key = get_key_from_password(DEFAULT_PASSWORD)

        for parent_dir, list_dir, list_file in os.walk(path_dir):
            all_hash_dic, add_s, add_i, add_u = compare_state(all_hash_dic, parent_dir, list_file, current_time, key, insert_alert)
            file_scan = file_scan + add_s
            file_add = file_add + add_i
            file_update = file_update + add_u

        for path_file_dic in all_hash_dic:
            file_del = file_del + 1
            insert_alert_integrity(current_time, DELETE_FILE_MSG, path_file_dic)
            print(DELETE_FILE_MSG + path_file_dic)
            del_hash_record_by_id(FILE_TYPE, all_hash_dic[path_file_dic][0])

        if insert_alert is False:
            update_state_sys_check_object_by_id(info_sys_check[0])

    msg = "Done check integrity for dir. " \
          "\nScan: " + str(file_scan) + " files." \
          "\nNew file: " + str(file_add) + " files." \
          "\nUpdate file: " + str(file_update) + " files." \
          "\nDelete file: " + str(file_del) + " files."
    print(msg)
    return SUCCESS_CODE, msg


# Scan integrity for eacch sys_check_object for system
def scan_integrity_object(path_object, type_object):
    current_time = datetime.now()
    current_time = current_time.strftime('%Y-%m-%d %H:%M:%S')

    if type_object == FILE_TYPE or str(type_object) == str(FILE_TYPE):
        return scan_file(path_object, current_time)
    elif type_object == DIR_TYPE or str(type_object) == str(DIR_TYPE):
        return scan_dir(path_object, current_time)
    elif type_object == REGISTRY_TYPE or str(type_object) == str(REGISTRY_TYPE):
        return scan_registry_key(path_object, current_time)


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
            # Example: demo_integrity.py -s "test.txt" file[0] / directory [1] / registry[3]
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
                            result = add_sys_check_object_from_xml(argv[2])
                        elif msg == SYS_CHECK_OBJECT_CSV_FILE:
                            result = add_sys_check_object_from_csv(argv[2])
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
                # Get list hash registry from database
                # Example: demo_integrity.py -g
                elif argv[1] == '-g':
                    hash_registry_list = get_list_hash_registry_limit_1000()
                    if hash_registry_list == ERROR_CODE:
                        print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                    else:
                        print(json.dumps({'result': True, 'hash_registry_list': hash_registry_list}))
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
    print("\t[type]: the file[0] / folder[1] / registry[2]")
    print("Example:\n$ python demo_integrity.py -e -f \"C:\\test.txt\" \"abc\"")
    print("$ python demo_integrity.py -d -d \"C:\\test\" \"abc\" 1")
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
