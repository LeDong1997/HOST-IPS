from codes.systems.file_func import *


# Validate insert system check object
def validate_insert_monitor_object(path_object, type_object):
    # Validate type object
    if type_object == FILE_TYPE or str(type_object) == str(FILE_TYPE):
        result = check_file_exist(FILE_TYPE, path_object)
        if result == FILE_NOT_FOUND_CODE:
            return ERROR_CODE, "File don't exist. The monitor_object invalid."
    elif type_object == DIR_TYPE or str(type_object) == str(DIR_TYPE):
        result = check_file_exist(DIR_TYPE, path_object)
        if result == DIR_NOT_FOUND_CODE:
            return ERROR_CODE, "Directory don't exist. The monitor_object invalid."
    else:
        return ERROR_CODE, "The type object invalid."
    return SUCCESS_CODE, 'OK'
