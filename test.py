# import win32con
# import winerror
# import win32evtlog
#
#
# # List filter event id
# def filter_id(event_id, list_id):
#     for _id in list_id:
#         if _id == event_id:
#             return True
#     return False
#
#
# # Check key has contain in dictionary
# def is_has_key(key, dict_data):
#     return key in dict_data
#
#
# event_types = {win32con.EVENTLOG_AUDIT_FAILURE: 'EVENTLOG_AUDIT_FAILURE',
#                win32con.EVENTLOG_AUDIT_SUCCESS: 'EVENTLOG_AUDIT_SUCCESS',
#                win32con.EVENTLOG_INFORMATION_TYPE: 'EVENTLOG_INFORMATION_TYPE',
#                win32con.EVENTLOG_WARNING_TYPE: 'EVENTLOG_WARNING_TYPE',
#                win32con.EVENTLOG_ERROR_TYPE: 'EVENTLOG_ERROR_TYPE'}
#
# event_object_access = {12800: 'File System',
#                        12801: 'Registry',
#                        12802: 'Kernel Object',
#                        12803: 'SAM',
#                        12804: 'Other Object Access Events',
#                        12805: 'Certification Services',
#                        12806: 'Application Generated',
#                        12807: 'Handle Manipulation',
#                        12808: 'File Share',
#                        12809: 'Filtering Platform Packet Drop',
#                        12810: 'Filtering Platform Connection',
#                        12811: 'Detailed File Share',
#                        12812: 'Removable Storage',
#                        12813: 'Central Policy Staging'}
#
#
# def insert_alert(alert_temp, time, domain, user, action, resource):
#     if alert_temp['time'] != time:
#         print('%s: %s: %s :%s :%s' % (time, domain, user, action, resource))
#         return
#
#     if alert_temp['domain'] != domain:
#         print('%s: %s: %s :%s :%s' % (time, domain, user, action, resource))
#         return
#
#     if alert_temp['user'] != user:
#         print('%s: %s: %s :%s :%s' % (time, domain, user, action, resource))
#         return
#
#     if alert_temp['action'] != action:
#         print('%s: %s: %s :%s :%s' % (time, domain, user, action, resource))
#         return
#     if alert_temp['resource'] != resource:
#         print('%s: %s: %s :%s :%s' % (time, domain, user, action, resource))
#         return
#
#
# def init_alert_temp(time, domain, user, action, resource):
#     alert_temp = {'time': time, 'domain': domain, 'user': user, 'action': action, 'resource': resource}
#     return alert_temp
#
#
# def analysis_event_log():
#     path_log = r"C:\Users\Cu Lee\Desktop\RenameFile.evtx"
#     flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
#     # flags = win32evtlog.EVENTLOG_SEEK_READ | win32evtlog.EVENTLOG_FORWARDS_READ
#     list_id = [4656, 4663, 4660, 4658, 4659]
#     # handle = win32evtlog.OpenBackupEventLog(None, path_log)
#     handle = win32evtlog.OpenEventLog(None, 'Security')
#     pending_del = {}
#     alert_temp = init_alert_temp('', '', '', '', '')
#     count = 0
#     try:
#         num_records = win32evtlog.GetNumberOfEventLogRecords(handle)
#         totals = 0
#
#         events = 1  # Object
#         while events:
#             events = win32evtlog.ReadEventLog(handle, flags, 0)
#             for event in events:
#                 event_category = event.EventCategory
#                 event_id = winerror.HRESULT_CODE(event.EventID)
#
#                 if filter_id(event_id, list_id) and (event_category == 12800 or event_category == 12812):
#                     event_time = event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S')
#                     # print(event_time)
#                     event_computer = str(event.ComputerName)
#                     event_user = event.StringInserts[1]
#
#                     if event_id == 4658:
#                         event_handle_id = event.StringInserts[5]
#                         event_process_id = event.StringInserts[6]
#                         if is_has_key(event_handle_id, pending_del.keys()) is False:
#                             pending_del[event_handle_id] = {}
#                             # pending_del[event_handle_id]['alive'] = True
#                             pending_del[event_handle_id]['process_id'] = event_process_id
#                     # if event_id == 4660:
#                     #     event_handle_id = event.StringInserts[5]
#                     #     event_process_id = event.StringInserts[6]
#                     #     if is_has_key(event_handle_id, pending_del.keys()) \
#                     #             and event_process_id == pending_del[event_handle_id]['process_id']:
#                     #         pending_del[event_handle_id]['4660'] = 'Delete'
#                     #         pending_del[event_handle_id]['access_mask'] = '0x10000'
#                     if event_id == 4663:
#                         event_object = event.StringInserts[6]
#                         event_handle_id = event.StringInserts[7]
#                         event_access_mask = event.StringInserts[9]
#                         event_process_id = event.StringInserts[10]
#                         event_process_name = event.StringInserts[11]
#
#                         if is_has_key(event_handle_id, pending_del.keys()) \
#                                 and event_process_id == pending_del[event_handle_id]['process_id']:
#                             pending_del[event_handle_id]['time'] = event_time
#                             pending_del[event_handle_id]['object'] = event_object
#                             pending_del[event_handle_id]['process_name'] = event_process_name
#                             pending_del[event_handle_id]['access_mask'] = event_access_mask
#                             # if is_has_key('4660', pending_del[event_handle_id].keys()) is False:
#                             #     pending_del[event_handle_id]['access_mask'] = event_access_mask
#                             #     count += 1
#
#                             if event_access_mask == '0x10000':
#                                 insert_alert(alert_temp, pending_del[event_handle_id]['time'], event_computer,
#                                              event_user, 'Delete File', event_object)
#                                 alert_temp = init_alert_temp(pending_del[event_handle_id]['time'], event_computer,
#                                                              event_user, 'Delete File', event_object)
#                                 del pending_del[event_handle_id]
#                     if event_id == 4656:
#                         event_object = event.StringInserts[6]
#                         event_handle_id = event.StringInserts[7]
#                         # event_access_mask = event.StringInserts[11]
#                         event_process_id = event.StringInserts[14]
#                         if is_has_key(event_handle_id, pending_del.keys()) \
#                                 and event_process_id == pending_del[event_handle_id]['process_id']:
#                             if is_has_key('access_mask', pending_del[event_handle_id].keys()):
#                                 access_mask = pending_del[event_handle_id]['access_mask']
#                                 # if pending_del[event_handle_id]['access_mask'] == '0x1':
#                                 #     insert_alert(alert_temp, pending_del[event_handle_id]['time'], event_computer,
#                                 #                  event_user, 'Read Data', event_object)
#                                 #     alert_temp = init_alert_temp(pending_del[event_handle_id]['time'], event_computer,
#                                 #                                  event_user, 'Read Data', event_object)
#                                 # if pending_del[event_handle_id]['access_mask'] == '0x20000':
#                                 #     insert_alert(alert_temp, pending_del[event_handle_id]['time'], event_computer,
#                                 #                  event_user, 'Read Control', event_object)
#                                 #     alert_temp = init_alert_temp(pending_del[event_handle_id]['time'], event_computer,
#                                 #                                  event_user, 'Read Control', event_object)
#                                 if access_mask == '0x2' or access_mask == '0x6':    # Create File
#                                     insert_alert(alert_temp, pending_del[event_handle_id]['time'], event_computer,
#                                                  event_user, 'Create/Modify', event_object)
#                                     alert_temp = init_alert_temp(pending_del[event_handle_id]['time'], event_computer,
#                                                                  event_user, 'Create/Modify', event_object)
#                                 if access_mask == '0x10000':
#                                     insert_alert(alert_temp, pending_del[event_handle_id]['time'], event_computer,
#                                                  event_user, 'Delete File', event_object)
#                                     alert_temp = init_alert_temp(pending_del[event_handle_id]['time'], event_computer,
#                                                                  event_user, 'Delete File', event_object)
#                                 # if access_mask == '0x80':
#                                 #     insert_alert(alert_temp, pending_del[event_handle_id]['time'], event_computer,
#                                 #                  event_user, 'Create Dir', event_object)
#                                 #     alert_temp = init_alert_temp(pending_del[event_handle_id]['time'], event_computer,
#                                 #                                  event_user, 'Create Dir', event_object)
#                             del pending_del[event_handle_id]
#             totals = totals + len(events)
#         win32evtlog.CloseEventLog(handle)
#         msg = "Done read Windows Event Logs. Scan: " + str(totals) + "/" + str(num_records) + "."
#         print(msg)
#         print(count)
#     except Exception as e:
#         print(e)
#
#
# analysis_event_log()
import os

# path = r"C:\Users\Cu Lee\Desktop\ThuMuc\test2.txt"
# with open(path, 'w+') as f:
#     f.write('')

# import win32evtlog # requires pywin32 pre-installed
#
# server = 'localhost' # name of the target computer to get event logs
# logtype = 'Security' # 'Application' # 'Security'
# hand = win32evtlog.OpenEventLog(server,logtype)
# flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
# total = win32evtlog.GetNumberOfEventLogRecords(hand)
#
# while True:
#     events = win32evtlog.ReadEventLog(hand, flags,0)
#     if events:
#         for event in events:
#             print('Event Category:', event.EventCategory)
#             print('Time Generated:', event.TimeGenerated)
#             print('Source Name:', event.SourceName)
#             print('Event ID:', event.EventID)
#             print('Event Type:', event.EventType)
#             data = event.StringInserts
#             if data:
#                 print('Event Data:')
#                 for msg in data:
#                     print(msg)
#             print("")
#             break
#     break

PATH_AUDIT_LOG = "/var/log/audit/audit.log"


def del_event(event_id):
    key_word = ":" + str(event_id) + "):"
    try:
        with open(PATH_AUDIT_LOG, 'r') as f_in:
            lines = f_in.readlines()
        with open(PATH_AUDIT_LOG, 'w') as f_out:
            for line in lines:
                if line.strip("\n").find(key_word) == -1:
                    f_out.write(line)
    except Exception as e:
        print(e)


del_event(568)
