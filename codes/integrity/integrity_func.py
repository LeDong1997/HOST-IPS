from codes.systems.os_func import *
from codes.systems.hash_func import *
from codes.systems.file_xml_func import *
from codes.systems.file_csv_func import *


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
