Param(
    [Parameter(Position=2)]
    [String] $path_object
)
try{
    $acl = Get-Acl $path_object -Audit -ErrorAction Stop
    $audit_rules = $acl.GetAuditRules($True, $False, [System.Security.Principal.SecurityIdentifier])
    $audit_rules | Foreach-Object { $acl.RemoveAuditRule($_); }
    $acl | Set-Acl $path_object
    return 0
} catch{
    # Error in set audit rule
    #Write-Host $_
    return -1
}