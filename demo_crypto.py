from codes.crypto.crypto_func import *

if __name__ == '__main__':
    main_crypto()

    # python demo_crypto.py -e -f "C:\test.txt" "abc"
    # python demo_crypto.py -e -d "C:\Test" "abc"
    # python demo_crypto.py -d -f "C:\test.enc" "abc" CONFIRM_DEL [0] / SKIP_CODE [1] / OVERRIDE_CODE [2]
    # python demo_crypto.py -d -d "C:\test.enc" "abc" SKIP_CODE [1] / OVERRIDE_CODE [2]
    # python demo_crypto.py -l "2020-06-08 10:24:19" "2020-06-10 10:24:19"
    # python demo_crypto.py -l_7
