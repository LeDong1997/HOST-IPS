import subprocess
from codes.program_msg import *
import os
import csv
import sys
import win32con
import winerror
import traceback
import win32evtlog
import win32evtlogutil
from time import strftime


evt_types = {win32con.EVENTLOG_AUDIT_FAILURE: 'EVENTLOG_AUDIT_FAILURE',
             win32con.EVENTLOG_AUDIT_SUCCESS: 'EVENTLOG_AUDIT_SUCCESS',
             win32con.EVENTLOG_INFORMATION_TYPE: 'EVENTLOG_INFORMATION_TYPE',
             win32con.EVENTLOG_WARNING_TYPE: 'EVENTLOG_WARNING_TYPE',
             win32con.EVENTLOG_ERROR_TYPE: 'EVENTLOG_ERROR_TYPE'}

evt_obj_access = {12800: 'File System',
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


def scan_event_log():
    log_type = "Security"
    path_log = r"C:\Audit"
    path_log_event = r"C:\Event_Logs\Archive-Security-2020-06-16-02-19-39-113.evtx"
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    # handle = win32evtlog.OpenEventLog(None, log_type)
    handle = win32evtlog.OpenBackupEventLog(None, path_log_event)
    num_records = win32evtlog.GetNumberOfEventLogRecords(handle)

    path_csv = path_log + strftime('%y-%m-%d_%H.%M.%S') + ".csv"

    num = 0
    while True:
        objects = win32evtlog.ReadEventLog(handle, flags, 0)
        if not objects:
            print(123)
            break
        for obj in objects:
            event_id = winerror.HRESULT_CODE(obj.EventID)
            user = obj.StringInserts[1]
            if event_id == 4663 or event_id == 4656:
                # print(obj.ComputerName)
                obj_name = obj.StringInserts[6]
                print(obj_name)
                # print(event_id, user, obj_name)
                # print("x")
                # print(obj.StringInserts[0], obj.StringInserts[1], obj.StringInserts[2], obj.StringInserts[3], obj.StringInserts[4])
                print(obj.StringInserts[5], obj.StringInserts[6], obj.StringInserts[7], obj.StringInserts[8])
                print(obj.StringInserts[9])
                # print(obj.StringInserts[10], obj.StringInserts[11])
                # print(obj.StringInserts[12])

                msg = win32evtlogutil.SafeFormatMessage(obj, log_type)
                print(msg)
                exit(1)
            break


