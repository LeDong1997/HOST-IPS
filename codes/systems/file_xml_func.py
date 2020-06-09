import xml.etree.ElementTree as eT
from codes.databases.integrity_db_func import *


# Add system check object from XML file
def add_sys_check_object_from_xml(path_file):
    try:
        tree = eT.parse(path_file)
        root = tree.getroot()
        # c_list = []

        if root.tag == CHECK_LIST_TAG:
            for child in root:
                if child.tag == FILE_CHECK_TAG:
                    result = check_file_exist(FILE_TYPE, child.text)
                    if result != FILE_NOT_FOUND_CODE:
                        insert_or_update_sys_check_object(child.text, FILE_TYPE)
                        # c_list.append((child.text, FILE_TYPE))
                elif child.tag == FOLDER_CHECK_TAG:
                    result = check_file_exist(DIR_TYPE, child.text)
                    if result != DIR_NOT_FOUND_CODE:
                        insert_or_update_sys_check_object(child.text, DIR_TYPE)
                        # c_list.append((child.text, DIR_TYPE))
                elif child.tag == REGISTRY_CHECK_TAG:
                    insert_or_update_sys_check_object(child.text, REGISTRY_TYPE)
                    # c_list.append((child.text, REGISTRY_TYPE))
            return SUCCESS_CODE
        else:
            print("The data in XML file invalid.")
            return ERROR_CODE
    except Exception as e:
        print("Error: %s", e)
        return ERROR_CODE
