import sys
import struct
import json
from Crypto import Random
from datetime import timedelta
from Crypto.Cipher import AES
from codes.systems.hash_func import *


# Get password from keyboard
# @return password or ERROR_CODE if password invalid
def get_password():
    try_input = 0
    while try_input < 3:
        password = str(input("Enter a password encryption/decryption: "))
        re_password = str(input("Confirm password: "))
        if password == re_password:
            return password
        else:
            print("Password incorrect!")
            try_input += 1
            if try_input == 3:
                print("The password is not valid more than 3 times.")
                return ERROR_CODE


# Handle process encrypt file
# @return ERROR_CODE / SUCCESS_CODE
def process_encrypt(path_file, key):
    tmp_path_file, ext_file = os.path.splitext(path_file)
    i = 0
    # a.txt -> a_001.enc
    path_file_enc = tmp_path_file + "_" + '{:03d}'.format(i) + TYPE_ENCRYPT_FILE

    while True:
        if os.path.isfile(path_file_enc):
            i += 1
            path_file_enc = tmp_path_file + "_" + '{:03d}'.format(i) + TYPE_ENCRYPT_FILE
        else:
            break
    file_size = os.path.getsize(path_file)
    iv = Random.new().read(AES.block_size)
    encryption = AES.new(key, AES.MODE_CBC, iv)

    result, hmac_str = hmac_sha256_key(path_file, key)
    if result == ERROR_CODE:
        return ERROR_CODE

    try:
        with open(path_file, 'rb') as f_in:
            with open(path_file_enc, 'wb') as f_out:
                f_out.write(struct.pack('<Q', file_size))
                f_out.write(iv)
                f_out.write(encryption.encrypt(struct.pack('64s', hmac_str.encode('utf-8'))))
                f_out.write(encryption.encrypt(struct.pack('16s', ext_file.encode('utf-8'))))

                # Encrypt for each data block
                while True:
                    data_block = f_in.read(DATA_BLOCK_SIZE)
                    len_block = len(data_block)
                    if len_block == 0:
                        f_in.close()
                        os.remove(path_file)
                        print(ENCRYPT_FILE_SUCCESS_MSG)
                        current_time = datetime.now()
                        current_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
                        write_log_crypto(current_time, 'Success', '-e', path_file)
                        return SUCCESS_CODE
                    elif len_block % 16 != 0:
                        # Padding with spaces
                        data_block += b' ' * (16 - len_block % 16)
                    f_out.write(encryption.encrypt(data_block))
    except Exception as e:
        print(e)
        current_time = datetime.now()
        current_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
        write_log_crypto(current_time, 'Error', '-e', path_file)
        return ERROR_CODE


# Encrypt a single file
def encrypt_file(path_file, password):
    result = check_file_exist(FILE_TYPE, path_file)
    if result == FILE_NOT_FOUND_CODE:
        print('File encrypt not found.')
        return ERROR_CODE

    print('###\nStarting encrypt file ...')
    key_enc = get_key_from_password(password)
    return process_encrypt(path_file, key_enc)


# Handle process encrypt file
# @return ERROR_CODE / SUCCESS_CODE / PASSWORD_INCORRECT
def process_decrypt(path_file, key, choice):
    try:
        with open(path_file, 'rb') as f_in:
            file_size = struct.unpack('<Q', f_in.read(struct.calcsize('Q')))[0]
            iv = f_in.read(AES.block_size)
            decryption = AES.new(key, AES.MODE_CBC, iv)

            pack_hmac_str_old = decryption.decrypt(f_in.read(64))
            pack_ext_file_old = decryption.decrypt(f_in.read(16))

            try:
                hmac_str_old = struct.unpack('64s', pack_hmac_str_old)[0].decode('utf-8').replace("\x00", "")
                ext_file_old = struct.unpack('16s', pack_ext_file_old)[0].decode('utf-8').replace("\x00", "")
            except (Exception, ValueError):
                print(PASSWORD_INCORRECT_MSG)
                return PASSWORD_INCORRECT_CODE

            # a_001.enc -> a_001.txt
            temp_path_file, name_file_dec = os.path.split(path_file)
            if len(name_file_dec) > 8:
                path_file_dec = path_file[:-8] + ext_file_old
            else:
                # a.enc -> a.txt
                path_file_dec = os.path.splitext(path_file)[0] + ext_file_old

            if os.path.isfile(path_file_dec):
                if choice == OVERRIDE_CODE or str(choice) == str(OVERRIDE_CODE):
                    os.remove(path_file_dec)
                elif choice == SKIP_CODE or str(choice) == str(SKIP_CODE):
                    print(SKIP_OVERRIDE_MSG)
                    return SKIP_CODE
                else:
                    print(CONFIRM_DEL_MSG)
                    return CONFIRM_DEL

            hmac_ctx = hmac.new(key, digestmod=hashlib.sha256)

            # Decrypt for each data block
            with open(path_file_dec, 'wb') as f_out:
                while True:
                    data_block = f_in.read(DATA_BLOCK_SIZE)
                    len_block = len(data_block)
                    if len_block == 0:
                        hmac_str = hmac_ctx.hexdigest()
                        if hmac_str == hmac_str_old:
                            f_in.close()
                            os.remove(path_file)
                            print(DECRYPT_FILE_SUCCESS_MSG)

                            current_time = datetime.now()
                            current_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
                            write_log_crypto(current_time, 'Success', '-d', path_file)
                            return SUCCESS_CODE
                        else:
                            f_out.close()
                            os.remove(path_file_dec)
                            print(PASSWORD_INCORRECT_MSG)

                            current_time = datetime.now()
                            current_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
                            write_log_crypto(current_time, 'Error', '-d', path_file)
                            return PASSWORD_INCORRECT_MSG
                    decode_data_block = decryption.decrypt(data_block)
                    n = len(decode_data_block)
                    if file_size > n:
                        hmac_ctx.update(decode_data_block)
                        f_out.write(decode_data_block)
                    else:
                        # Remove padding on last block
                        f_out.write(decode_data_block[:file_size])
                        hmac_ctx.update(decode_data_block[:file_size])
                    file_size -= n
    except Exception as e:
        print(e)
        current_time = datetime.now()
        current_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
        write_log_crypto(current_time, 'Error', '-d', path_file)
        return ERROR_CODE


# Decrypt a single file
# @return ERROR_CODE / PASSWORD_INCORRECT_CODE / SUCCESS_CODE
def decrypt_file(path_file, password, choice):
    result = check_file_exist(FILE_TYPE, path_file)
    if result == FILE_NOT_FOUND_CODE:
        print('File decrypt not found.')
        return ERROR_CODE

    ext_file = os.path.splitext(path_file)
    if ext_file[1] != TYPE_ENCRYPT_FILE:
        print('File decrypt invalid.')
        return ERROR_CODE

    print('###\nStarting decrypt file ...')
    key_dec = get_key_from_password(password)
    return process_decrypt(path_file, key_dec, choice)


# Encrypt all file in directory and sub-directory
# return ERROR_CODE or SUCCESS_CODE
def encrypt_dir(path_dir, password):
    result = check_file_exist(DIR_TYPE, path_dir)
    if result == DIR_NOT_FOUND_CODE:
        return ERROR_CODE

    print('###\nStarting encrypt directory ...')
    key_enc = get_key_from_password(password)

    # Scan directory
    # type<list_dir, list_file> = list
    # type<parent_dir> = string
    for parent_dir, list_dir, list_file in os.walk(path_dir):
        for file in list_file:
            process_encrypt(os.path.join(parent_dir, file), key_enc)

    print(ENCRYPT_DIR_SUCCESS_MSG)
    return SUCCESS_CODE


# Decrypt all file in directory and sub-directory
def decrypt_dir(path_dir, password, choice):
    result = check_file_exist(DIR_TYPE, path_dir)
    if result == DIR_NOT_FOUND_CODE:
        return ERROR_CODE

    print('###\nStarting decrypt directory ...')
    key_dec = get_key_from_password(password)

    # Scan directory
    # type<list_dir, list_files> = list
    # type<parent_dir> = string
    for parent_dir, list_dir, list_file in os.walk(path_dir):
        for file in list_file:
            path_file = os.path.join(parent_dir, file)
            ext_file = os.path.splitext(path_file)
            if ext_file[1] == TYPE_ENCRYPT_FILE:  # ext = ".enc"
                result = process_decrypt(path_file, key_dec, choice)
                if result == PASSWORD_INCORRECT_CODE:
                    return PASSWORD_INCORRECT_CODE
    print(DECRYPT_DIR_SUCCESS_MSG)
    return SUCCESS_CODE


# Get event in start_time and end_time
def get_events_encrypt(start_time, end_time):
    ENCRYPT_LOG_PATH = LOG_PATH + "\\crypto.txt"
    totals = 0
    events = []
    try:
        with open(ENCRYPT_LOG_PATH) as f_read:
            while True:
                line = f_read.readline()
                line_parse = line.split('|')
                if not line:
                    break
                if (line_parse[0] > start_time) and (line_parse[0] < end_time):
                    events.append(line_parse)
                    totals = totals + 1
        msg = "Total events: " + str(totals) + "."
        print(msg)
        return SUCCESS_CODE, events
    except Exception as e:
        print(e)
        return ERROR_CODE, "Cannot open log file."


# Get event_log in 7 day ago
def get_events_encrypt_7ago(start_time):
    ENCRYPT_LOG_PATH = LOG_PATH + "\\crypto.txt"
    totals = 0
    events = []
    try:
        with open(ENCRYPT_LOG_PATH) as f_read:
            while True:
                line = f_read.readline()
                line_parse = line.split('|')
                if not line:
                    break
                if line_parse[0] > start_time:
                    events.append(line_parse)
                    totals = totals + 1
        msg = "Total events: " + str(totals) + "."
        print(msg)
        return SUCCESS_CODE, events
    except Exception as e:
        print(e)
        return ERROR_CODE, "Cannot open log file."


def usage_crypto_func():
    print("\nAdd argument to crypto function.")
    print("$ python demo_crypto.py -operation -object -path -password [options]")
    print("\t--operation: choice encryption [-e] / decryption [-d]")
    print("\t--object: choice file [-f] / directory [-d]")
    print("\t--path: path of file / directory")
    print("\t--password: choice password use encrypt / decrypt")
    print("\t[--option]: the default CONFIRM_DEL [0] / SKIP [1] / OVERRIDE [2]")
    print("Example:\n$ python demo_crypto.py -e -f \"C:\\test.txt\" \"abc\"")
    print("$ python demo_crypto.py -d -d \"C:\\test\" \"abc\" 1")
    return 0


# Main crypto
def main_crypto():
    try:
        argv = sys.argv
        argc = len(argv)
        if argc == 5 and argv[1] == '-e':  # Encryption
            # python demo_crypto.py -e -f "C:\test.txt" "abc"
            if argv[2] == '-f':
                return encrypt_file(argv[3], argv[4])
            # python demo_crypto.py -e -d "C:\Test" "abc"
            elif argv[2] == '-d':
                return encrypt_dir(argv[3], argv[4])
            else:
                return usage_crypto_func()
        elif argc == 6 and argv[1] == '-d':  # Decryption
            choice = int(argv[5])
            # python demo_crypto.py -d -f "C:\test.enc" "abc" CONFIRM_DEL [0] / SKIP_CODE [1] / OVERRIDE_CODE [2]
            if argv[2] == '-f':
                if choice == CONFIRM_DEL:  # Choice SKIP or OVERRIDE ?
                    return decrypt_file(argv[3], argv[4], CONFIRM_DEL)
                elif choice == SKIP_CODE or choice == OVERRIDE_CODE:
                    return decrypt_file(argv[3], argv[4], choice)
                else:
                    return usage_crypto_func()
            # python demo_crypto.py -d -f "C:\test.enc" "abc" SKIP_CODE [1] / OVERRIDE_CODE [2]
            elif argv[2] == '-d':
                if choice == SKIP_CODE or choice == OVERRIDE_CODE:
                    return decrypt_dir(argv[3], argv[4], choice)
                else:
                    return usage_crypto_func()
            else:
                return usage_crypto_func()
        elif argc == 4 and argv[1] == '-l':
            # python demo_crypto.py -l "2020-06-08 10:24:19" "2020-06-10 10:24:19"
            result, events = get_events_encrypt(argv[2], argv[3])
            if result == ERROR_CODE:
                print(json.dumps({'result': result == SUCCESS_CODE, 'error_msg': "The error get events logs."}))
            else:
                print(json.dumps({'result': result == SUCCESS_CODE, 'events': events}))
        elif argc == 2 and argv[1] == '-l_7':
            # python demo_crypto.py -l_7
            current_time = datetime.now()
            date_7_day_ago = current_time - timedelta(days=7)
            date_7_day_ago = date_7_day_ago.strftime('%Y-%m-%d %H:%M:%S')
            print(date_7_day_ago)
            result, events = get_events_encrypt_7ago(date_7_day_ago)
            if result == ERROR_CODE:
                print(json.dumps({'result': result == SUCCESS_CODE, 'error_msg': "The error get events logs."}))
            else:
                print(json.dumps({'result': result == SUCCESS_CODE, 'events': events}))
            return SUCCESS_CODE
        else:
            return usage_crypto_func()
    except (Exception, ValueError):
        return ERROR_CODE
