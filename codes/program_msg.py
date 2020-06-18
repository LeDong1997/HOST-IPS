#
# Determine messages and constants used in the file-system-protection module
#
# Determine the size of the encrypt/decrypt data_block
DATA_BLOCK_SIZE = 32768

# Determine the value returned by the function
ERROR_CODE = -1
SUCCESS_CODE = 0

ACCESS_DENIED_CODE = 5

# Define operating system platform
UNKNOWN_PLATFORM = -1
WINDOWS_PLATFORM = 0
LINUX_PLATFORM = 1

FILE_NOT_FOUND_CODE = -2
DIR_NOT_FOUND_CODE = -3

FILE_EXIST_MSG = 'File exist.'
DIR_EXIST_MSG = 'Directory exist.'

FILE_TYPE = 0
DIR_TYPE = 1
REGISTRY_TYPE = 2

TYPE_ENCRYPT_FILE = '.enc'

# Determine the messages encrypt/decrypt file and directory
PASSWORD_INCORRECT_MSG = 'Error. Password incorrect'
ENCRYPT_FILE_SUCCESS_MSG = 'Done encrypt file.'
ENCRYPT_FILE_ERROR_MSG = '#Error in process encrypt file.'
DECRYPT_FILE_SUCCESS_MSG = 'Done decrypt file.'
DECRYPT_FILE_ERROR_MSG = '#Error in process decrypt file.'
ENCRYPT_DIR_SUCCESS_MSG = 'Done encrypt directory.'
DECRYPT_DIR_SUCCESS_MSG = 'Done decrypt directory.'

CONFIRM_DEL = 0
SKIP_CODE = 1
OVERRIDE_CODE = 2
PASSWORD_INCORRECT_CODE = -4

CONFIRM_DEL_MSG = 'Confirm override.'
SKIP_OVERRIDE_MSG = 'Skip override.'


DEFAULT_PASSWORD = 'bkcs'

# Determine the error value / messages returned by the database query function
CREATE_DB_ERROR = -4
INSERT_RECORD_ERROR = -5
UPDATE_RECORD_ERROR = -6
DELETE_RECORD_ERROR = -7

CREATE_DB_ERROR_MSG = 'There was an error creating the database.'
CREATE_DB_SUCCESS_MSG = 'Create success database: '

QUERY_TABLE_DB_ERROR_MSG = 'The error connect to database.'

ADD_FILE_MSG = 'The new file add to folder.'
CHANGE_FILE_MSG = 'File is changed.'
DELETE_FILE_MSG = 'File is deleted.'
NOT_CHANGE_FILE_MSG = 'File isn\'t changed.'


FILE_CHECK_TAG = 'file_check'
FOLDER_CHECK_TAG = 'folder_check'
REGISTRY_CHECK_TAG = 'windows_registry'
CHECK_LIST_TAG = 'check_list'

# New sys_check add to database is value 0
SYS_CHECK_OBJECT_NEW = 0
SYS_CHECK_OBJECT_OLD = 1

SYS_CHECK_OBJECT_IGNORE = 1

SYS_CHECK_OBJECT_XML_FILE = 'xml'
SYS_CHECK_OBJECT_CSV_FILE = 'csv'

# Registry
VALUE_CHANGE = 'Registry value change.'
VALUE_ADD = 'Registry value add.'
VALUE_DEL = 'Registry value deleted.'
KEY_ADD = 'Registry key add.'
KEY_DEL = 'Registry key deleted.'

PATH_DIR_EVENT_LOG = r"C:\Event_Logs"


ADD_FILE_ACTION_MSG = 'Create'
CHANGE_FILE_ACTION_MSG = 'Modify'
DELETE_FILE_ACTION_MSG = 'Delete'
RENAME_FILE_ACTION_MSG = 'Rename'
MOVE_FILE_ACTION_MSG = 'Move'
RESTORE_FILE_ACTION_MSG = 'Restore'
RECYCLE_FILE_ACTION_MSG = 'Recycle'
