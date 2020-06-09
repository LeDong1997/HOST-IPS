from codes.systems.os_func import *


def main():
    os_type = os_check()
    if os_type == WINDOWS_PLATFORM or UNKNOWN_PLATFORM:
        from codes.windows.integrity.integrity_windows_func import main_integrity
    else:
        from codes.linux.integrity.integrity_linux_func import main_integrity
    try:
        main_integrity()
    except Exception as e:
        print("Error: %s.", e)
        return ERROR_CODE


if __name__ == '__main__':
    main()
