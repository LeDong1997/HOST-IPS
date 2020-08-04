import subprocess

PATH_AUDIT_LOG = "/var/log/audit/audit.log"


def del_event(event_id):
    key_word = ":" + str(event_id) + "):"
    try:
        with open(PATH_AUDIT_LOG, 'r') as f_in:
            lines = f_in.readlines()
        with open(PATH_AUDIT_LOG, 'w') as f_out:
            for line in lines:
                if line.strip("\n").find(key_word) == -1:
                    f_out.write(line)
    except Exception as e:
        print(e)


# del_event(568)
def read_audit_log(path_file):
    print(path_file)
    # cmd = "ausearch -f " + path_file + " -ts today | aureport -i -f"
    cmd = "ausearch -f " + path_file + " -ts 01/08/2020 10:03:16 | aureport -i -f"
    print(cmd, 123)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    result = p.stdout.read().decode()
    print(result)
    print(1234)


path_object = "/home/bkcs/Desktop/dong"
read_audit_log(path_object)
