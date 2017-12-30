# Get last logged on users of computers
# Author: Ramazan Vapurcu (github.com/wmramazan)
# 28.12.2017

$log_file = ".\get_last_logged_on_users.log"
$computers_file = ".\computers.txt"

Get-Date > $log_file
"$number_of_events event logs have been checked." >> $log_file

$credential = Get-Credential -Message "Please enter the credential to access the computers."

Write-Host "Get last logged on users of computers"
Write-Host " Logon Types:"
Write-Host " 1  -> All types"
Write-Host " 2  -> Interactive"
Write-Host " 3  -> Network"
Write-Host " 4  -> Batch"
Write-Host " 5  -> Service"
Write-Host " 7  -> Unlock"
Write-Host " 8  -> NetworkCleartext"
Write-Host " 9  -> NewCredentials"
Write-Host " 10 -> RemoteInteractive"
Write-Host " 11 -> CachedInteractive"

$logon_type = Read-Host "Logon Type"
$number_of_events = Read-Host "Number of event logs which will check to detect last logged on users"

$computers = New-Object System.Collections.ArrayList
Get-Content $computers_file | ForEach-Object {
    $computers.Add($_) > $null
}

Workflow detectUsers {
    Param([string[]]$computers, [PSCredential]$credential, [int]$logon_type, [int]$number_of_events)

    ForEach -Parallel ($computer in $computers) {
    
        $last_logged_on_users = InlineScript { Invoke-Command -ComputerName $Using:computer -Credential $Using:credential -ArgumentList $Using:number_of_events, $Using:logon_type -ScriptBlock {

            $newest = $args[0]
            $logon_type = $args[1]
			If($logon_type -eq 1) {
				$events = Get-EventLog Security -AsBaseObject -InstanceId 4624 -Newest $newest -EntryType SuccessAudit
			} Else {
				$events = Get-EventLog Security -AsBaseObject -InstanceId 4624 -Newest $newest -EntryType SuccessAudit | Where-Object { ($_.Message -match "Logon Type:\s+$logon_type") }
			}

            $users = @()
            ForEach($event in $events) {
    
                If ($event.Message -match "New Logon:\s*Security ID:\s*.*\s*Account Name:\s*(\w+)"  -and $users -notcontains $matches[1]) {
                    $users += $matches[1]
                }

            }
    
            return $users

        } }

        $computer + ": " + $last_logged_on_users + "`n"

    }

}

Write-Host "Detecting last logged on user in specified computers.."
$result = detectUsers -computers $computers -credential $credential -logon_type $logon_type -number_of_events $number_of_events

$result >> $log_file
Write-Host " $result"