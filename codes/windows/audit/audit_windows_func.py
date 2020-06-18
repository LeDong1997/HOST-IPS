import win32con
import winerror
import subprocess
import win32evtlog
from codes.databases.monitor_db_func import *

event_types = {win32con.EVENTLOG_AUDIT_FAILURE: 'EVENTLOG_AUDIT_FAILURE',
               win32con.EVENTLOG_AUDIT_SUCCESS: 'EVENTLOG_AUDIT_SUCCESS',
               win32con.EVENTLOG_INFORMATION_TYPE: 'EVENTLOG_INFORMATION_TYPE',
               win32con.EVENTLOG_WARNING_TYPE: 'EVENTLOG_WARNING_TYPE',
               win32con.EVENTLOG_ERROR_TYPE: 'EVENTLOG_ERROR_TYPE'}

event_object_access = {12800: 'File System',
                       12801: 'Registry',
                       12802: 'Kernel Object',
                       12803: 'SAM',
                       12804: 'Other Object Access Events',
                       12805: 'Certification Services',
                       12806: 'Application Generated',
                       12807: 'Handle Manipulation',
                       12808: 'File Share',
                       12809: 'Filtering Platform Packet Drop',
                       12810: 'Filtering Platform Connection',
                       12811: 'Detailed File Share',
                       12812: 'Removable Storage',
                       12813: 'Central Policy Staging'}


# Add new audit rule for file / directory
def add_audit_rules(path_object, type_object):
    try:
        cmd = r'.\codes\windows\audit\powershell\add_rules_audit.ps1'
        arg_path = path_object.replace(' ', "' '")
        p = subprocess.Popen(["powershell.exe", cmd, type_object, arg_path], stdout=subprocess.PIPE, shell=True)

        (output, err) = p.communicate()
        p.wait()

        result = str(output).find("-1")
        if result != -1:
            print("Error in add audit permission for object.")
            return ERROR_CODE
        return SUCCESS_CODE
    except Exception as e:
        print(e)
        return ERROR_CODE


# Remove audit rule for file / directory
def remove_audit_rules(path_object):
    try:
        cmd = r'.\codes\windows\audit\powershell\remove_rules_audit.ps1'
        arg_path = path_object.replace(' ', "' '")
        p = subprocess.Popen(["powershell.exe", cmd, arg_path], stdout=subprocess.PIPE, shell=True)

        (output, err) = p.communicate()
        p.wait()

        result = str(output).find("-1")
        if result != -1:
            print("Error in remove audit permission for object.")
            return ERROR_CODE
        return SUCCESS_CODE
    except Exception as e:
        print(e)
        return ERROR_CODE


# Check key has contain in dictionary
def has_key(key, dict_data):
    return key in dict_data


# Check str1 contain in str2
def is_contain_str(str1, str2):
    if str2.find(str1) == -1:
        return False
    return True


# Get file_name from path_file
def get_file_name(path_file):
    path, file_name = os.path.split(path_file)
    return file_name


# Get folder_name from path_dir
def get_folder_name(path_dir):
    return os.path.basename(path_dir)


# List filter event id
def filter_id(event_id, list_id):
    for _id in list_id:
        if _id == event_id:
            return True
    return False


def is_insert_alert(alert_dict1, alert_dict2):
    b_time = (alert_dict1['time'] == alert_dict2['time'])
    b_user = (alert_dict1['user'] == alert_dict2['user'])
    b_domain = (alert_dict1['domain'] == alert_dict2['domain'])
    b_access_mask = (alert_dict1['note'] == alert_dict2['note'])

    if b_time and b_user and b_domain and b_access_mask:
        return False
    return True


# Get alert by one audit_log
def scan_one_audit_log(path_event_log, backup_flag=True):
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    list_id = [4656, 4663, 4660, 4659]
    try:
        if backup_flag:
            handle = win32evtlog.OpenBackupEventLog(None, path_event_log)
        else:
            handle = win32evtlog.OpenEventLog(None, "Security")

        num_records = win32evtlog.GetNumberOfEventLogRecords(handle)
        total = 0

        pending_delete = {}
        alert_dict = {}
        events = 1  # Object
        while events:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            for event in events:
                event_category = event.EventCategory
                # ID of event
                event_id = winerror.HRESULT_CODE(event.EventID)
                # Category: File System
                if event_category == 12800 and filter_id(event_id, list_id):
                    # Time generated event
                    event_time = event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')
                    event_computer = str(event.ComputerName)
                    event_user = event.StringInserts[1]
                    event_object = event.StringInserts[6]

                    alert_dict['time'] = event_time
                    alert_dict['user'] = event_user
                    alert_dict['domain'] = event_computer
                    alert_dict['resource'] = event_object

                    # A handle was requested.
                    if event_id == 4656 and has_key(event_object, pending_delete):
                        # The file was not deleted -> created/modified
                        pending_delete[event_object]['alive'] = True
                    # Event 4663 = object access.
                    elif event_id == 4663:
                        event_access_mask = event.StringInserts[9]
                        # 0x10000 = Delete, but this can mean different things - delete, overwrite, rename, move.
                        if event_access_mask == '0x10000' and not is_contain_str("RECYCLE.BIN", event_object):
                            # Ignore metadata files in the recycle bin.
                            if has_key(event_object, pending_delete):
                                # Is it already in the list?  If so, kick it out and replace it.
                                # The most recent handle is used to track a moved file.
                                del pending_delete[event_object]
                            # Record the filename, username, handle ID, and time.
                            pending_delete[event_object] = {}
                            pending_delete[event_object]['user'] = event_user
                            pending_delete[event_object]['handle_id'] = event.StringInserts[7]
                            pending_delete[event_object]['time_created'] = event_time
                            pending_delete[event_object]['alive'] = False
                            pending_delete[event_object]['confirmed'] = False
                        # 0x2 = is a classic "object was modified" signal.
                        if event_access_mask == '0x2' and not is_contain_str("RECYCLE.BIN", event_object):
                            # Generate report
                            alert_dict['action'] = ADD_FILE_ACTION_MSG
                            alert_dict['note'] = '0x2'
                            print("Time: %s, User: %s, Domain: %s, Action: %s, Resource: %s, AccessMask: %s."
                                  % (event_time, event_user, event_computer, ADD_FILE_ACTION_MSG, event_object, "0x2"))
                            insert_alert_monitor(alert_dict)
                            # The file was not actually deleted, so remove it from this array.
                            try:
                                del pending_delete[event_object]
                            except (Exception, ValueError):
                                continue
                        # A 4663 event with 0x80 (Read Attributes) is logged
                        # with the same handle ID when files/folders are moved or renamed.
                        if event_access_mask == '0x80':
                            for key in pending_delete.keys():
                                # If the Handle & User match...and the object wasn't deleted...
                                # figure out whether it was moved or renamed.
                                if pending_delete[key]['handle_id'] == event.StringInserts[7] \
                                        and pending_delete[key]['user'] == event_user \
                                        and event_object != key \
                                        and not pending_delete[key]['confirmed']:
                                    # Files moved to a different folder (same filename, different folder)
                                    if get_file_name(event_object) == get_file_name(key):
                                        alert_dict['action'] = MOVE_FILE_ACTION_MSG
                                        alert_dict['note'] = '0x2'
                                        print(
                                            "Time: %s, User: %s, Domain: %s, Action: %s, Resource: %s, AccessMask: %s."
                                            % (event_time, event_user, event_computer, MOVE_FILE_ACTION_MSG, event_object, "0x2"))
                                        insert_alert_monitor(alert_dict)
                                        del pending_delete[key]
                                    # Files moved into the recycle bin
                                    elif is_contain_str('RECYCLE.BIN', event_object):
                                        alert_dict['action'] = RECYCLE_FILE_ACTION_MSG
                                        alert_dict['note'] = '0x2'
                                        print(
                                            "Time: %s, User: %s, Domain: %s, Action: %s, Resource: %s, AccessMask: %s."
                                            % (event_time, event_user, event_computer, RECYCLE_FILE_ACTION_MSG, event_object, "0x2"))
                                        insert_alert_monitor(alert_dict)
                                        del pending_delete[key]
                                    # Files moved out of the recycle bin
                                    elif is_contain_str('RECYCLE.BIN', key):
                                        alert_dict['action'] = RESTORE_FILE_ACTION_MSG
                                        alert_dict['note'] = '0x2'
                                        print(
                                            "Time: %s, User: %s, Domain: %s, Action: %s, Resource: %s, AccessMask: %s."
                                            % (event_time, event_user, event_computer, RESTORE_FILE_ACTION_MSG, event_object, "0x2"))
                                        insert_alert_monitor(alert_dict)
                                        del pending_delete[key]
                                    # Created / renamed files
                                    elif get_folder_name(event_object) == get_folder_name(key):
                                        if get_file_name(key) == "New Folder":
                                            alert_dict['action'] = ADD_FILE_ACTION_MSG
                                            alert_dict['note'] = ''
                                            print(
                                                "Time: %s, User: %s, Domain: %s, Action: %s, Resource: %s, AccessMask: %s."
                                                % (event_time, event_user, event_computer, ADD_FILE_ACTION_MSG, event_object, ""))
                                        else:
                                            alert_dict['action'] = RENAME_FILE_ACTION_MSG
                                            alert_dict['note'] = ''
                                            print(
                                                "Time: %s, User: %s, Domain: %s, Action: %s, Resource: %s, AccessMask: %s."
                                                % (event_time, event_user, event_computer, RENAME_FILE_ACTION_MSG, key, ""))
                                            insert_alert_monitor(alert_dict)
                                        del pending_delete[key]
                                    break
                            # If none of those conditions match, at least note that the file still exists (if applicable).
                            if has_key(event_object, pending_delete):
                                pending_delete[event_object]['alive'] = True
                    # Event 4659 = a handle was requested with intent to delete
                    elif event_id == 4659:
                        alert_dict['action'] = DELETE_FILE_ACTION_MSG
                        alert_dict['note'] = ''
                        print("Time: %s, User: %s, Domain: %s, Action: %s, Resource: %s, AccessMask: %s."
                              % (event_time, event_user, event_computer, DELETE_FILE_ACTION_MSG, event_object, ""))
                        insert_alert_monitor(alert_dict)
                    # This delete confirmation doesn't happen when objects are moved/renamed;
                    # it does when files are created/deleted/recycled.
                    elif event_id == 4660:
                        for key in pending_delete.keys():
                            # print(event.StringInserts[5], pending_delete[key]['handle_id'])
                            if pending_delete[key]['handle_id'] == event.StringInserts[5] \
                                    and pending_delete[key]['user'] == event_user:
                                pending_delete[key]['confirmed'] = True
                        # msg = win32evtlogutil.SafeFormatMessage(event, log_type)
            total = total + len(events)
        win32evtlog.CloseEventLog(handle)
        msg = "Done read event_log. Scan: " + str(total) + "/" + str(num_records) + "."
        return SUCCESS_CODE, msg
    except Exception as e:
        print(e, 123)
        return ERROR_CODE, "Cannot read windows event_log."


# Scan all audit in windows event log
def scan_all_audit_log():
    path_event_dir = PATH_DIR_EVENT_LOG
    result = check_file_exist(DIR_TYPE, path_event_dir)
    if result == DIR_NOT_FOUND_CODE:
        os.mkdir(path_event_dir)

    p_list_file = []
    for parent_dir, list_dir, list_file in os.walk(path_event_dir):
        for file_obj in list_file:
            ext_file = os.path.splitext(file_obj)[1]
            # Only handle file event viewer
            if ext_file == '.evtx':
                path_file = os.path.join(parent_dir, file_obj)
                print("\nHandle file: " + path_file)
                if file_obj == "Security.evtx":
                    scan_one_audit_log(path_file, backup_flag=False)
                else:
                    p_list_file.append(path_file)
                    scan_one_audit_log(path_file, backup_flag=True)
        break
    result, msg = compress_file(path_event_dir, p_list_file)
    for path_file in p_list_file:
        try:
            os.remove(path_file)
        except Exception as e:
            print(e)
            continue
    return result, msg


# Demo scan event_log
def scan_event_log(path_log_event):
    print(path_log_event)
    # log_type = "Security"
    # path_log = r"C:\Audit"
    # # path_log_event = r"C:\Event_Logs\Archive-Security-2020-06-14-08-43-22-478.evtx"
    # flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    # handle = win32evtlog.OpenEventLog(None, log_type)
    # # handle = win32evtlog.OpenBackupEventLog(None, path_log_event)
    # num_records = win32evtlog.GetNumberOfEventLogRecords(handle)
    # total = 0
    # print(num_records)
    #
    # path_csv = path_log + strftime('%y-%m-%d_%H.%M.%S') + ".csv"
    # list_id = [4656, 4663, 4660, 4659]
    #
    # pending_delete = {}
    # events = 1  # Object
    # while events:
    #     events = win32evtlog.ReadEventLog(handle, flags, 0)
    #     for event in events:
    #         event_category = event.EventCategory
    #         # ID of event
    #         event_id = winerror.HRESULT_CODE(event.EventID)
    #         # Category: File System
    #         if event_category == 12800 and filter_id(event_id, list_id):
    #             # Time generated event
    #             event_time = event.TimeGenerated.Format("%y-%m-%d %H:%M:%S")
    #             # Domain
    #             event_computer = str(event.ComputerName)
    #             event_user = event.StringInserts[1]
    #             event_object = event.StringInserts[6]
    #             # pending_delete[event_object] = {}
    #             # pending_delete[event_object]['Alive'] = True
    #
    #             # A handle was requested.
    #             if event_id == 4656 and has_key(event_object, pending_delete):
    #                 # The file was not deleted -> created/modified
    #                 pending_delete[event_object]['alive'] = True
    #             # Event 4663 = object access.
    #             elif event_id == 4663:
    #                 event_access_mask = event.StringInserts[9]
    #
    #                 # 0x10000 = Delete, but this can mean different things - delete, overwrite, rename, move.
    #                 if event_access_mask == '0x10000' and not is_contain_str("RECYCLE.BIN", event_object):
    #                     # Ignore metadata files in the recycle bin.
    #                     if has_key(event_object, pending_delete):
    #                         # Is it already in the list?  If so, kick it out and replace it.
    #                         # The most recent handle is used to track a moved file.
    #                         del pending_delete[event_object]
    #                     # Record the filename, username, handle ID, and time.
    #                     pending_delete[event_object] = {}
    #                     pending_delete[event_object]['user'] = event_user
    #                     pending_delete[event_object]['handle_id'] = event.StringInserts[7]
    #                     pending_delete[event_object]['time_created'] = event_time
    #                     pending_delete[event_object]['alive'] = False
    #                     pending_delete[event_object]['confirmed'] = False
    #                     # print(pending_delete)
    #
    #                 # 0x2 = is a classic "object was modified" signal.
    #                 if event_access_mask == '0x2' and not is_contain_str("RECYCLE.BIN", event_object):
    #                     # Generate report
    #                     print("User: " + event_user + ", Action: created/modified, Object: " + event_object +
    #                           ", Time: " + event_time + ", AccessMask: 0x2.")
    #                     # The file was not actually deleted, so remove it from this array.
    #                     try:
    #                         del pending_delete[event_object]
    #                     except Exception as e:
    #                         # print(e)
    #                         continue
    #
    #                 # A 4663 event with 0x80 (Read Attributes) is logged
    #                 # with the same handle ID when files/folders are moved or renamed.
    #                 if event_access_mask == '0x80':
    #                     for key in pending_delete.keys():
    #                         # If the Handle & User match...and the object wasn't deleted...
    #                         # figure out whether it was moved or renamed.
    #                         if pending_delete[key]['handle_id'] == event.StringInserts[7] \
    #                                 and pending_delete[key]['user'] == event_user \
    #                                 and event_object != key \
    #                                 and not pending_delete[key]['confirmed']:
    #                             # Files moved to a different folder (same filename, different folder)
    #                             if get_file_name(event_object) == get_file_name(key):
    #                                 print("User: " + event_user + ", Action: moved, Object: " + event_object +
    #                                       ", Time: " + event_time + ", AccessMask: 0x2.")
    #                                 del pending_delete[key]
    #                             # Files moved into the recycle bin
    #                             elif is_contain_str('RECYCLE.BIN', event_object):
    #                                 print("User: " + event_user + ", Action: recycled, Object: " + event_object +
    #                                       ", Time: " + event_time + ", AccessMask: 0x2.")
    #                                 del pending_delete[key]
    #                             # Files moved out of the recycle bin
    #                             elif is_contain_str('RECYCLE.BIN', key):
    #                                 print("User: " + event_user + ", Action: restored, Object: " + event_object +
    #                                       ", Time: " + event_time + ", AccessMask: 0x2.")
    #                                 del pending_delete[key]
    #                             # Created / renamed files
    #                             elif get_folder_name(event_object) == get_folder_name(key):
    #                                 if get_file_name(key) == "New Folder":
    #                                     print("User: " + event_user + ", Action: created, Object: " + event_object +
    #                                           ", Time: " + event_time)
    #                                 else:
    #                                     print("User: " + event_user + ", Action: renamed, Object: " + key +
    #                                           ", Time: " + event_time)
    #                                 del pending_delete[key]
    #                             break
    #                     # If none of those conditions match, at least note that the file still exists (if applicable).
    #                     if has_key(event_object, pending_delete):
    #                         pending_delete[event_object]['alive'] = True
    #             # Event 4659 = a handle was requested with intent to delete
    #             elif event_id == 4659:
    #                 print("User: " + event_user + ", Action: deleted, Object: " + event_object +
    #                       ", Time: " + event_time + ", Event: 4659.")
    #             # This delete confirmation doesn't happen when objects are moved/renamed; it does when files are created/deleted/recycled.
    #             elif event_id == 4660:
    #
    #                 for key in pending_delete.keys():
    #                     print(event.StringInserts[5], pending_delete[key]['handle_id'])
    #                     if pending_delete[key]['handle_id'] == event.StringInserts[5] \
    #                             and pending_delete[key]['user'] == event_user:
    #                         pending_delete[key]['confirmed'] = True
    #                 # msg = win32evtlogutil.SafeFormatMessage(event, log_type)
    #     total = total + len(events)
    # if num_records == total:
    #     print("Successfully read all %d records." % num_records)
    # else:
    #     print("Couldn't get all records - reported %d, but found %d" % (num_records, total))
    #     print("(Note that some other app may have written records while we were running!)")
    pass
