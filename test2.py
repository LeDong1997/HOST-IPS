# import os
#
# path = r"C:\Users\Cu Lee\Desktop\ThuMuc\test2.txt"
# with open(path, 'w+') as f:
#     f.write('')

import os
import win32con
import winerror
import win32evtlog


# List filter event id
def filter_id(event_id, list_id):
    for _id in list_id:
        if _id == event_id:
            return True
    return False


# Check key has contain in dictionary
def is_has_key(key, dict_data):
    return key in dict_data


def check_is_file(path_file):
    temp_file, ext = os.path.splitext(path_file)
    if len(ext):
        return True
    else:
        return False


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


def insert_alert(alert_temp, time, domain, user, action, resource):
    if alert_temp['time'] != time:
        print('%s: %s: %s :%s :%s' % (time, domain, user, action, resource))
        return

    if alert_temp['domain'] != domain:
        print('%s: %s: %s :%s :%s' % (time, domain, user, action, resource))
        return

    if alert_temp['user'] != user:
        print('%s: %s: %s :%s :%s' % (time, domain, user, action, resource))
        return

    if alert_temp['action'] != action:
        print('%s: %s: %s :%s :%s' % (time, domain, user, action, resource))
        return
    if alert_temp['resource'] != resource:
        print('%s: %s: %s :%s :%s' % (time, domain, user, action, resource))
        return


def init_alert_temp(time, domain, user, action, resource):
    alert_temp = {'time': time, 'domain': domain, 'user': user, 'action': action, 'resource': resource}
    return alert_temp


def analysis_event_log():
    # path_log = r"C:\Users\Cu Lee\Desktop\DeleteDir.evtx"
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    # flags = win32evtlog.EVENTLOG_SEEK_READ | win32evtlog.EVENTLOG_FORWARDS_READ
    list_id = [4656, 4663, 4660, 4658, 4659]
    # handle = win32evtlog.OpenBackupEventLog(None, path_log)
    handle = win32evtlog.OpenEventLog(None, 'Security')
    pending_del = {}
    alert_temp = init_alert_temp('', '', '', '', '')
    count = 0
    try:
        num_records = win32evtlog.GetNumberOfEventLogRecords(handle)
        totals = 0
        print(num_records)

        events = 1  # Object
        while events:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            for event in events:
                event_category = event.EventCategory
                event_id = winerror.HRESULT_CODE(event.EventID)
                event_time = event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')
                print(event_time)
                exit(1)

                if filter_id(event_id, list_id) and (event_category == 12800 or event_category == 12812):

                    # print(event_time)
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
                                    insert_alert(alert_temp, event_time, event_computer, event_user, 'CreateFile', event_object)
                                    alert_temp = init_alert_temp(event_time, event_computer, event_user, 'CreateFile', event_object)
                                else:
                                    insert_alert(alert_temp, event_time, event_computer, event_user, 'ModifyFile', event_object)
                                    alert_temp = init_alert_temp(event_time, event_computer, event_user, 'ModifyFile', event_object)
                        if event_access_mask == '0x10000' or '%%1537' in event_access_list:
                            is_file = check_is_file(event_object)
                            if is_file:
                                insert_alert(alert_temp, event_time, event_computer, event_user, 'DeleteFile', event_object)
                                alert_temp = init_alert_temp(event_time, event_computer, event_user, 'DeleteFile', event_object)
                            else:
                                insert_alert(alert_temp, event_time, event_computer, event_user, 'DeleteDir', event_object)
                                alert_temp = init_alert_temp(event_time, event_computer, event_user, 'DeleteDir', event_object)
                        if event_access_mask == '0x40000' or '%%1539' in event_access_list:
                            is_file = check_is_file(event_object)
                            if is_file:
                                insert_alert(alert_temp, event_time, event_computer, event_user, 'ModifyACL', event_object)
                                alert_temp = init_alert_temp(event_time, event_computer, event_user, 'ModifyACL', event_object)
                    if event_id == 4656:
                        event_object = event.StringInserts[6]
                        event_handle_id = event.StringInserts[7]
                        event_process_id = event.StringInserts[14]
                        if is_has_key(event_handle_id, pending_del.keys()) \
                                and event_process_id == pending_del[event_handle_id]['process_id']:
                            del pending_del[event_handle_id]
            totals = totals + len(events)
        win32evtlog.CloseEventLog(handle)
        msg = "Done read Windows Event Logs. Scan: " + str(totals) + "/" + str(num_records) + "."
        print(msg)
        print(count)
    except Exception as e:
        print(e)


# path_dir = r"C:\Users\Cu Lee\Desktop\Data"
# # for parent_dir, list_dir, list_file in os.walk(path_dir):
# #     for file_obj in list_file:
# #         path_file = os.path.join(parent_dir, file_obj)
# #         print(path_file)
# #         analysis_event_log(path_file)
analysis_event_log()
