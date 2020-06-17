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
