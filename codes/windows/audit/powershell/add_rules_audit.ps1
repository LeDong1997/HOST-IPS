Param(
    [Parameter(Position=1)]
    [int] $type_object,

    [Parameter(Position=2)]
    [String] $path_object
)
try{
    $acl = Get-Acl $path_object -Audit -ErrorAction Stop
    $audit_user = "Everyone"
    $audit_types = "Success, Failure"
    $audit_rules = "DeleteSubdirectoriesAndFiles, Modify, ChangePermissions, TakeOwnership"

    if($type_object -eq 0){
        $access_rules = New-Object System.Security.AccessControl.FileSystemAuditRule($audit_user, $audit_rules, "None", "None", $audit_types)
    }elseif($type_object -eq 1){
        # Subfolders and file in directory
        $inherit_type = "ContainerInherit, ObjectInherit"
        $access_rules = New-Object System.Security.AccessControl.FileSystemAuditRule($audit_user, $audit_rules, $inherit_type, "None", $audit_types)
    }else{
        # Write-Host "Invalid"
        return -1
    }

    $acl.SetAuditRule($access_rules)
    $acl | Set-Acl $path_object
    return 0
} catch{
    # Error in set audit rule
    # Write-Host $_
    return -1
}