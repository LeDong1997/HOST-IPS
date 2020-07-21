import sys
import json
from datetime import timedelta
from .audit_windows_func import *
from codes.audit.audit_func import *
from codes.databases.monitor_db_func import *


def usage_audit_func():
    print("\nAdd argument to audit function.")
    print("-i [path] [type]: insert check object to database")
    print("-d [path] [type]: insert check object from database")
    print("\t[type]: the file[0] / folder[1] / registry[2]")
    print("Example:\n$ python demo_audit.py -e -f \"C:\\test.txt\" \"abc\"")
    print("$ python demo_integrity.py -d -d \"C:\\test\" \"abc\" 1")
    return 0


def main():
    try:
        create_monitor_db()
        argv = sys.argv
        argc = len(argv)

        if argc == 4:
            # Insert monitor object (file / directory) to database
            # Example: demo_monitor.py -i "test.txt" file[0] / directory [1]
            if argv[1] == '-i':
                result, error_msg = validate_insert_monitor_object(argv[2], argv[3])
                if result == SUCCESS_CODE:
                    result = insert_or_update_monitor_object(argv[2], argv[3])
                    if result == SUCCESS_CODE:
                        result = add_audit_rules(argv[2], argv[3])
                        if result == ERROR_CODE:
                            remove_monitor_object(argv[2], argv[3])
                    check_list = get_list_monitor_object()
                    print(json.dumps({'result': result == SUCCESS_CODE, 'monitor_list': check_list}))
                else:
                    print(json.dumps({'result': result == SUCCESS_CODE, 'error_msg': error_msg}))
            # Remove monitor_object from database
            # Example: demo_monitor.py -r "test.txt" file[0] / directory [1]
            elif argv[1] == '-r':
                result = remove_audit_rules(argv[2])
                if result == SUCCESS_CODE:
                    result = remove_monitor_object(argv[2], argv[3])
                    check_list = get_list_monitor_object()
                    print(json.dumps({'result': result == SUCCESS_CODE, 'monitor_list': check_list}))
                else:
                    print(json.dumps({'result': result == SUCCESS_CODE, 'error_msg': "Error remove sys_check_object"}))
            # Get list alert monitor in start_time and end_time
            # Example: demo_monitor.py -a "2020-06-08 10:24:19" "2020-06-17 10:24:19"
            elif argv[1] == '-a':
                alert_list = get_list_alert_at_time(argv[2], argv[3])
                if alert_list == ERROR_CODE:
                    print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                else:
                    print(json.dumps({'result': True, 'alert_list': alert_list}))
        elif argc == 3:
            if argv[1] == '-s':
                # Scan windows event log with path_event_file
                # Example: demo_monitor.py -s path_event
                result, msg = scan_one_audit_log(argv[2], backup_flag=True)
                if result == SUCCESS_CODE:
                    print(json.dumps({'result': result == SUCCESS_CODE, 'msg': msg}))
                else:
                    print(json.dumps({'result': result == SUCCESS_CODE, 'error_msg': msg}))
        elif argc == 2:
            # Scan all windows event log
            # Example: demo_monitor.py -s_a
            if argv[1] == '-s_a':
                result, msg = scan_all_audit_log()
                if result == SUCCESS_CODE:
                    print(json.dumps({'result': result == SUCCESS_CODE, 'msg': msg}))
                else:
                    print(json.dumps({'result': result == SUCCESS_CODE, 'error_msg': msg}))
            # Get all list alert_monitor
            # Example: demo_monitor.py -a
            elif argv[1] == '-a':
                alert_list = get_list_alert_limit_1000()
                if alert_list == ERROR_CODE:
                    print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                else:
                    print(json.dumps({'result': True, 'alert_list': alert_list}))
            # Get list alert monitor by 7 day ago
            # Example: demo_monitor.py -a_7
            elif argv[1] == '-a_7':
                current_time = datetime.now()
                date_7_day_ago = current_time - timedelta(days=7)
                date_7_day_ago = date_7_day_ago.strftime('%Y-%m-%d %H:%M:%S')
                alert_list = get_list_alert_7day_ago(date_7_day_ago)
                if alert_list == ERROR_CODE:
                    print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                else:
                    print(json.dumps({'result': True, 'alert_list': alert_list}))
                # Get list monitor object from database
                # Example: demo_integrity.py -l
            elif argv[1] == '-l':
                check_list = get_list_monitor_object()
                if check_list == ERROR_CODE:
                    print(json.dumps({'result': False, 'error_msg': "Cannot connect to database."}))
                else:
                    print(json.dumps({'result': True, 'check_list': check_list}))
                return SUCCESS_CODE
            return SUCCESS_CODE
    except (Exception, ValueError):
        return ERROR_CODE


# Execute main-audit function
main()
