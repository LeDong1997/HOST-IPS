from codes.systems.os_func import *


def main():
    try:
        os_type = os_check()
        if os_type == WINDOWS_PLATFORM or UNKNOWN_PLATFORM:
            import codes.windows.audit.main_audit
        else:
            import codes.linux.audit.main_audit
    except Exception as e:
        print("Error: %s.", e)
        return ERROR_CODE


if __name__ == '__main__':
    main()

    # demo_monitor.py -i "test.txt" file[0] / directory [1]
    # demo_monitor.py -r "test.txt" file[0] / directory [1]
    # demo_monitor.py -a "2020-06-08 10:24:19" "2020-06-17 10:24:19"
    # demo_monitor.py -s path_event
    # demo_monitor.py -s_a
    # demo_monitor.py -a
    # demo_monitor.py -a_7
