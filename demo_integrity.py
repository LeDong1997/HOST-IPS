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

    # python demo_integrity.py -i "test.txt" file[0] / directory [1]
    # python demo_integrity.py -r "test.txt" file[0] / directory [1]
    # python demo_integrity.py -s "test.txt" file[0] / directory [1] / registry[3]
    # python demo_integrity.py -x sample.xml
    # python demo_integrity.py -m "test.txt"
    # python demo_integrity.py -a id
    # python demo_integrity.py -l
    # python demo_integrity.py -a
    # python demo_integrity.py -e
    # python demo_integrity.py -h
    # python demo_integrity.py -g
    # python demo_integrity.py -s_a
    # python demo_integrity.py -l_7
    # python demo_integrity.py -l "2020-06-08 10:24:19" "2020-06-17 10:24:19"
