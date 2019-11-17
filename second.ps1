If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -Verb RunAs
    Exit
}

Write-Output "Setting Up Scoop"
scoop update
scoop bucket add extras
scoop bucket add games
scoop bucket add java
scoop bucket add jetbrains
scoop bucket add php

Write-Output "Installing Applications"
scoop update
scoop install 7zip adb bulk-crap-uninstaller busy-box cacert calibre-normal coreutils cpu-z crystaldiskmark cura curl dark deluge discord docker docker-compose etcher ffmpeg firefox firefox-developer flac flux github go googlechrome googlechrome-dev gpu -z grep handbrake hexchat imageglass innounp jetbrains-toolbox jq less lessmsi minecraft mpc-hc-fork nano nmap nodejs nodejs-lts obs-studio oraclejdk php plex-player powertoys prime95 pshazz python quicklook ruby rufus scoop sed sharex speedfan steam sudo teamviewer vcredist2015 vcredist2017 vcredist2019 vlc vscode webtorrent wget wireshark youtube-dl youtube-dl-gui zotero

