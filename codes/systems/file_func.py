from datetime import datetime
import os
import time
import zipfile
from codes.program_msg import *


LOG_PATH = os.path.dirname(os.path.abspath(__file__)) + "\\..\\..\\logs"


# Check file or directory exist
# @return FILE_NOT_FOUND_CODE / DIR_NOT_FOUND_CODE or path_file / path_dir
def check_file_exist(type_object, path_object):
    # Check file exist
    if type_object == FILE_TYPE or str(type_object) == str(FILE_TYPE):
        if os.path.isfile(path_object):
            return path_object
        else:
            return FILE_NOT_FOUND_CODE

    # Check directory exist
    if type_object == DIR_TYPE or str(type_object) == str(DIR_TYPE):
        if os.path.isdir(path_object):
            return path_object
        else:
            return DIR_NOT_FOUND_CODE


# Search all files in dictionary and sub-dictionary by name
# Example:
# search_file('Test', r'C:\Users\Cu Lee\Desktop', False)
def search_file(name_file, path_dir, sub_dir=True):
    res = check_file_exist(DIR_TYPE, path_dir)
    if res == DIR_NOT_FOUND_CODE:
        print('No such directory for search.')
        return ERROR_CODE

    count_file = 0
    # type<list_dir, list_file>: list
    # type<parent_dir>: string
    for parent_dir, list_dir, list_file in os.walk(path_dir):
        for file_obj in list_file:
            if name_file in file_obj:
                print(os.path.join(parent_dir, file_obj))
                count_file += 1
        if sub_dir is False:
            break

    if count_file:
        print('Find %d file in directory.' % (count_file,))
    else:
        print('File not found in directory.')
    return SUCCESS_CODE


# Get last time create/modify/access file
def get_time_property_file(path_file):
    try:
        time_property = {}
        # Get last create/modify/access time of file in seconds since epoch
        create_time_second = os.path.getctime(path_file)
        # Convert second to format string
        create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(create_time_second))
        time_property.update({'create_time': create_time})

        modify_time_second = os.path.getmtime(path_file)
        modify_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(modify_time_second))
        time_property.update({'modify_time': modify_time})

        access_time_second = os.path.getatime(path_file)
        access_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(access_time_second))
        time_property.update({'access_time': access_time})
        return time_property
    except Exception as e:
        print("Error: %s", e)
        return ERROR_CODE


# Write event to log file
def write_log_crypto(time_stamp, state, action, path_file):
    ENCRYPT_LOG_PATH = LOG_PATH + "\\crypto.txt"
    try:
        with open(ENCRYPT_LOG_PATH, 'a') as f_out:
            f_out.write("%s|%s|%s|%s\n" % (time_stamp, state, action, path_file))
    except (Exception, ValueError):
        return ERROR_CODE


# Compress file with zip
def compress_file(path_dir, list_path_file):
    try:
        if len(list_path_file) == 0:
            return SUCCESS_CODE, "The empty compress file."

        current_time = datetime.now()
        current_time = current_time.strftime('%Y-%m-%d %H-%M-%S')
        path_zip = path_dir + "\\" + current_time + '.zip'
        zip_handle = zipfile.ZipFile(path_zip, 'w', zipfile.ZIP_DEFLATED)
        print("Start zip file: " + path_zip)

        success = 0
        error = 0
        for path_file in list_path_file:
            try:
                print('Handle file: ' + path_file)
                zip_handle.write(path_file)
                success = success + 1
            except (Exception, ValueError):
                error = error + 1
                continue
        zip_handle.close()
        msg = "Done zip file.\n" + "Success: " + str(success) + "\nError: " + str(error)
        print(msg)
        return SUCCESS_CODE, msg
    except Exception as e:
        print(e)
        return ERROR_CODE, "Error while compress many file."
