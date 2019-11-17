If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -Verb RunAs
		Exit
	}

Write-Output "Setting Execution Policy" 
Set-ExecutionPolicy RemoteSigned -scope CurrentUser -f

Write-Output "Installing Scoop"
Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://get.scoop.sh')

Write-Output "Setting Up Scoop"
scoop install aria2
scoop install git
scoop install openssh
[environment]::setenvironmentvariable('GIT_SSH', (resolve-path (scoop which ssh)), 'USER')


