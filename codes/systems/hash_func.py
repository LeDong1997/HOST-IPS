import hmac
import hashlib
from .file_func import *
from codes.program_msg import *


# Generate key from password
# @return 32 byte (SHA-256) or ERROR_CODE
def get_key_from_password(password):
    salt = b'bkcs'
    iteration = 4096
    len_key = 32

    # Generate key from password using HMAC-PBKDF2
    try:
        key_hex = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iteration, len_key)
        return key_hex
    except Exception as e:
        print(e)
        return ERROR_CODE


# Calculate the hash value for file
# @return hash_value or ERROR_CODE
def hash_file(path_file, hash_type):
    try:
        with open(path_file, 'rb') as f_in:
            while True:
                data_block = f_in.read(DATA_BLOCK_SIZE)
                if not data_block:
                    break
                hash_type.update(data_block)
        return hash_type.hexdigest()
    except Exception as e:
        print('Error: %s.', e)
        return ERROR_CODE


# Calculate hash_value (SHA1) for file
# @return ERROR_CODE & error_msg or SUCCESS_CODE & hash_value
def hash_sha1(path_file):
    result = check_file_exist(FILE_TYPE, path_file)
    if result == FILE_NOT_FOUND_CODE:
        return ERROR_CODE, 'No such file.'

    result_sha1 = hashlib.sha1()
    result = hash_file(path_file, result_sha1)
    if result == ERROR_CODE:
        return ERROR_CODE, 'Can\'t calculate hash value SHA1 for file.'
    else:
        return SUCCESS_CODE, result


# Calculate hash_value (SHA-256) for file
# @return ERROR_CODE & error_msg / SUCCESS_CODE & hash_value
def hash_sha256(path_file):
    result = check_file_exist(FILE_TYPE, path_file)
    if result == FILE_NOT_FOUND_CODE:
        return ERROR_CODE, 'No such file.'

    result_sha256 = hashlib.sha256()
    result = hash_file(path_file, result_sha256)
    if result == ERROR_CODE:
        return ERROR_CODE, 'Can\'t calculate hash value SHA-256 for file.'
    else:
        return SUCCESS_CODE, result


# Calculate the hash value for file with key
# @return hash_value or ERROR_CODE
def hmac_file(path_file, key, hash_type):
    hmac_ctx = hmac.new(key, digestmod=hash_type)
    try:
        with open(path_file, 'rb') as f_in:
            while True:
                data_block = f_in.read(DATA_BLOCK_SIZE)
                if not data_block:
                    break
                hmac_ctx.update(data_block)
        return hmac_ctx.hexdigest()
    except (Exception, ValueError):
        return ERROR_CODE


# Calculate hash_value (HMAC-SHA-1) for file with key
# @return ERROR_CODE & error_msg / SUCCESS_CODE & hash_value
def hmac_sha1_password(path_file, password):
    result = check_file_exist(FILE_TYPE, path_file)
    if result == FILE_NOT_FOUND_CODE:
        return ERROR_CODE, 'No such file.'

    key_byte = get_key_from_password(password)
    if key_byte == ERROR_CODE:
        return ERROR_CODE, 'Can\'t generate key from password.'

    hmac_type = hashlib.sha1
    result = hmac_file(path_file, key_byte, hmac_type)
    if result == ERROR_CODE:
        return ERROR_CODE, 'Can\'t calculate hash value HMAC-SHA-1 for file with key.'
    else:
        return SUCCESS_CODE, result


# Calculate hash_value (HMAC-SHA-256) for file with key
# @return ERROR_CODE & error_msg / SUCCESS_CODE & hash_value
def hmac_sha256_password(path_file, password):
    result = check_file_exist(FILE_TYPE, path_file)
    if result == FILE_NOT_FOUND_CODE:
        return ERROR_CODE, 'No such file.'

    key_byte = get_key_from_password(password)
    if key_byte == ERROR_CODE:
        return ERROR_CODE, 'Can\'t generate key from password.'

    hmac_type = hashlib.sha256
    result = hmac_file(path_file, key_byte, hmac_type)
    if result == ERROR_CODE:
        return ERROR_CODE, 'Can\'t calculate hash value HMAC-SHA-256 for file with key.'
    else:
        return SUCCESS_CODE, result


# Calculate hash_value (HMAC-SHA-256) for file with key
# @return ERROR_CODE & error_msg / SUCCESS_CODE & hash_value
def hmac_sha256_key(path_file, key_byte):
    result = check_file_exist(FILE_TYPE, path_file)
    if result == FILE_NOT_FOUND_CODE:
        return ERROR_CODE, 'No such file.'

    hmac_type = hashlib.sha256
    result = hmac_file(path_file, key_byte, hmac_type)
    if result == ERROR_CODE:
        return ERROR_CODE, 'Can\'t calculate hash value HMAC-SHA-256 for file with key.'
    else:
        return SUCCESS_CODE, result
