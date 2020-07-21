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
        # cmd = r'codes\windows\audit\powershell\.add_rules_audit.ps1'
        cmd = r'.\codes\powershell\add_rules_audit.ps1'
        arg_path = path_object.replace(' ', "' '")
        # print(cmd, type_object, arg_path)
        p = subprocess.Popen(["powershell.exe", cmd, type_object, arg_path], stdout=subprocess.PIPE, shell=True)

        (output, err) = p.communicate()
        p.wait()
        print(str(output))

        result = str(output).find("-1")
        if result != -1:
            print("Error in add audit permission for object.")
            return ERROR_CODE
        result = str(output).find("Exception")
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


# List filter event id
def filter_id(event_id, list_id):
    for _id in list_id:
        if _id == event_id:
            return True
    return False


def is_has_key(key, dict_data):
    return key in dict_data


def check_is_file(path_file):
    temp, ext = os.path.splitext(path_file)
    if len(ext):
        return True
    else:
        return False


def insert_alert(alert_temp, evt_time, domain, user, action, resource, note):
    if alert_temp['time'] != evt_time:
        insert_alert_monitor(evt_time, domain, user, action, resource, note)
        return

    if alert_temp['domain'] != domain:
        insert_alert_monitor(evt_time, domain, user, action, resource, note)
        return

    if alert_temp['user'] != user:
        insert_alert_monitor(evt_time, domain, user, action, resource, note)
        return

    if alert_temp['action'] != action:
        insert_alert_monitor(evt_time, domain, user, action, resource, note)
        return
    if alert_temp['resource'] != resource:
        insert_alert_monitor(evt_time, domain, user, action, resource, note)
        return


def init_alert_temp(evt_time, domain, user, action, resource):
    alert_temp = {'time': evt_time, 'domain': domain, 'user': user, 'action': action, 'resource': resource}
    return alert_temp


def scan_one_audit_log(path_event_log, backup_flag=True):
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    list_id = [4658, 4663, 4658, 4660, 4659]
    pending_del = {}
    alert_temp = init_alert_temp('', '', '', '', '')
    try:
        if backup_flag:
            handle = win32evtlog.OpenBackupEventLog(None, path_event_log)
        else:
            handle = win32evtlog.OpenEventLog(None, "Security")
        num_records = win32evtlog.GetNumberOfEventLogRecords(handle)
        print(num_records, backup_flag)
        totals = 0

        events = 1  # Object
        while events:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            for event in events:
                event_category = event.EventCategory
                event_id = winerror.HRESULT_CODE(event.EventID)
                if filter_id(event_id, list_id) and (event_category == 12800 or event_category == 12812):
                    event_time = event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')
                    event_computer = str(event.ComputerName)
                    event_user = event.StringInserts[1]

                    if event_id == 4658:
                        event_handle_id = event.StringInserts[5]
                        event_process_id = event.StringInserts[6]
                        if is_has_key(event_handle_id, pending_del.keys()) is False:
                            pending_del[event_handle_id] = {}
                            pending_del[event_handle_id]['process_id'] = event_process_id
                    if event_id == 4663:
                        event_object = event.StringInserts[6]
                        event_handle_id = event.StringInserts[7]
                        event_access_list = event.StringInserts[8]
                        event_access_mask = event.StringInserts[9]
                        event_process_id = event.StringInserts[10]
                        event_process_name = event.StringInserts[11]

                        if is_has_key(event_handle_id, pending_del.keys()):
                            if event_process_id == pending_del[event_handle_id]['process_id']:
                                pending_del[event_handle_id]['process_name'] = event_process_name
                                pending_del[event_handle_id]['object'] = event_object
                                if is_has_key('access_mask', pending_del[event_handle_id].keys()) is False:
                                    pending_del[event_handle_id]['access_mask'] = {}
                                pending_del[event_handle_id]['access_mask'][event_access_mask] = {}
                                pending_del[event_handle_id]['access_mask'][event_access_mask]['time'] = event_time
                                pending_del[event_handle_id]['access_mask'][event_access_mask]['access_list'] = event_access_list
                        else:
                            pending_del[event_handle_id] = {}
                            pending_del[event_handle_id]['process_id'] = event_process_id
                            pending_del[event_handle_id]['process_name'] = event_process_name
                            pending_del[event_handle_id]['object'] = event_object
                            pending_del[event_handle_id]['access_mask'] = {}
                            pending_del[event_handle_id]['access_mask'][event_access_mask] = {}
                            pending_del[event_handle_id]['access_mask'][event_access_mask]['time'] = event_time
                            pending_del[event_handle_id]['access_mask'][event_access_mask]['access_list'] = event_access_list

                        if '%%4417' in event_access_list:
                            is_file = check_is_file(event_object)
                            if is_file:
                                if event_access_mask == '0x2':
                                    insert_alert(alert_temp, event_time, event_computer, event_user, ADD_FILE_ACTION_MSG, event_object, '0x2')
                                    alert_temp = init_alert_temp(event_time, event_computer, event_user, ADD_FILE_ACTION_MSG, event_object)
                                else:
                                    insert_alert(alert_temp, event_time, event_computer, event_user, CHANGE_FILE_ACTION_MSG, event_object, event_access_mask)
                                    alert_temp = init_alert_temp(event_time, event_computer, event_user, CHANGE_FILE_ACTION_MSG, event_object)
                        if event_access_mask == '0x10000' or '%%1537' in event_access_list:
                            is_file = check_is_file(event_object)
                            # print(is_file, "123")
                            if is_file:
                                insert_alert(alert_temp, event_time, event_computer, event_user, DELETE_FILE_ACTION_MSG, event_object, event_access_mask)
                                alert_temp = init_alert_temp(event_time, event_computer, event_user, DELETE_FILE_ACTION_MSG, event_object)
                            else:
                                insert_alert(alert_temp, event_time, event_computer, event_user, DELETE_DIR_ACTION_MSG, event_object, event_access_mask)
                                alert_temp = init_alert_temp(event_time, event_computer, event_user, DELETE_DIR_ACTION_MSG, event_object)
                        if event_access_mask == '0x40000' or '%%1539' in event_access_list:
                            is_file = check_is_file(event_object)
                            if is_file:
                                insert_alert(alert_temp, event_time, event_computer, event_user, CHANGE_FILE_ACL, event_object, event_access_mask)
                                alert_temp = init_alert_temp(event_time, event_computer, event_user, CHANGE_FILE_ACL, event_object)
                    if event_id == 4656:
                        event_handle_id = event.StringInserts[7]
                        event_process_id = event.StringInserts[14]
                        if is_has_key(event_handle_id, pending_del.keys()) \
                                and event_process_id == pending_del[event_handle_id]['process_id']:
                            del pending_del[event_handle_id]
            totals = totals + len(events)
        win32evtlog.CloseEventLog(handle)
        msg = "Done read Windows Event Logs. Scan: " + str(totals) + "/" + str(num_records) + "."
        print(msg)
        return SUCCESS_CODE, msg
    except Exception as e:
        print(e)
        return ERROR_CODE, "Cannot handle Windows Event Logs"


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
                if file_obj == "Security.evtx":
                    print("\nHandle file: " + file_obj)
                    scan_one_audit_log(file_obj, backup_flag=False)
                else:
                    path_file = os.path.join(parent_dir, file_obj)
                    p_list_file.append(path_file)
                    scan_one_audit_log(path_file, backup_flag=True)
        # break
    # msg = ""
    # result = SUCCESS_CODE
    result, msg = compress_file(path_event_dir, p_list_file)
    for path_file in p_list_file:
        try:
            os.remove(path_file)
        except Exception as e:
            print(e)
            continue
    return result, msg
