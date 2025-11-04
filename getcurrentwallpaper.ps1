$TIC=(Get-ItemProperty 'HKCU:\Control Panel\Desktop' TranscodedImageCache -ErrorAction Stop).TranscodedImageCache
$wallpaperPath = [System.Text.Encoding]::Unicode.GetString($TIC) -replace '(.+)([A-Z]:[0-9a-zA-Z\\])+','$2'
$wsh = New-Object -ComObject WScript.Shell
$wsh.popup("Current Wallpaper: " + $wallpaperPath)