# Variable
$log_path = "C:\Event_Logs\"
$report_path = "C:\Audit\File-Audit-Reports\"
$format_date = (Get-Date -UFormat %A-%B-%d-at-%I-%M-%S%p)
$zip_name = "Security-Events-for-" + (Get-Date -UFormat %A-%B-%d) + ".zip"
$report_csv = $report_path + "Audit of changed files on " + $format_date + ".csv"
$report_html = $report_path + "Audit of changed files on " + $format_date + ".html"
$truncated_log_path = $log_path + "Archive-Security_on_" + $format_date + ".evtx"
$today_midnight = (Get-Date -Hour 0 -Minute 0 -Second 0)
$total_events = 0
$start_time = Get-Date

# List file extensions to ignore
$temp_files = "tmp","rgt","mta","tlg",".nd",".ps","log","ldb",":Zone.Identifier","crdownload",".DS_Store",":AFP_AfpInfo",":AFP_Resource"
$ignored_users = ""

# Hashtable
$pending_delete = @{}

# Dynamically expanding array
[System.Collections.ArrayList]$audit_report=@("User,Action,Source,Destination,Time,DebugNotes")

# Files to purge from the Pending_Delete hashtable
[System.Collections.ArrayList]$my_garbage=@()

$error_action_preference = 'Stop'

# Write function
Function is_a_file{
    # If the path still exists, we can know for certain if it's a file or folder
    Try {
        If ((Get-Item $Object) -is [System.IO.FileInfo]) {
            Return $True
        }
    }
    
    # If the path is gone, we'll assume that it's a file if it contains a period.
    Catch {
        If ($Object -like "*.*") {
            Return $True
        }
    }
}

# Return file_name from path of file
Function get_file_name($path_file){
    If ($path_file -ne $null) {
        Return $path_file.Split('\')[-1]
    }
}

# Return folder_name from a path of folder
Function get_folder_name($path_dir){
    If ($path_dir -ne $null) {
        Return $path_dir.Substring(0, $path_dir.LastIndexOf("\"))
    }
}




