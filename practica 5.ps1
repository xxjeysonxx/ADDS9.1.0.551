New-ADOrganizationalUnit -Name “u001” -Path “DC=aboite,DC=com"
New-ADOrganizationalUnit -Name “u002” -Path “DC=aboite,DC=com"
New-ADUser -Name “user01” -UserPrincipalName “user01@aboite.com” -Path “OU=u001,DC=aboite,DC=com”
New-ADUser -Name “user02” -UserPrincipalName “user02@aboite.com” -Path “OU=u002,DC=aboite,DC=com”
Set-ADAccountPassword -Identity user01 -NewPassword  (ConvertTo-SecureString -String “Pass123” -AsPlainText -Force ) #usuario uo1User pass: Pass123
Set-ADAccountPassword -Identity user02 -NewPassword  (ConvertTo-SecureString -String “Pass123” -AsPlainText -Force ) #usuario uo2User pass: Pass123
Enable-ADAccount -Identity user01
Enable-ADAccount -Identity user02
New-GPO -Name u01gp0
New-GPO -Name u02gp0
New-GPLink -Name u01gp0 -Target “OU=u001,DC=aboite,DC=com”
New-GPLink -Name u02gp0 -Target “OU=u002,DC=aboite,DC=com”
Set-GPRegistryValue -Name “u01gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer” -ValueName NoControlPanel -Type DWord -Value 1
Set-GPRegistryValue -Name “u01gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop” -ValueName NoChangingWallpaper -Type DWord -Value 1
Set-GPRegistryValue -Name “u01gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall” -ValueName NoAddRemovePrograms -Type DWord -Value 1
Set-GPRegistryValue -Name “u01gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer” -ValueName RestrictRun -Type DWord -Value 1
Set-GPRegistryValue -Name “u01gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RestrictRun” -ValueName 1 -Type String -Value notepad.exe
Set-GPRegistryValue -Name “u01gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName EnableProfileQuota -Type DWord -Value 1
Set-GPRegistryValue -Name “u01gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName IncludeProfileQuota -Type DWord -Value 1
Set-GPRegistryValue -Name “u01gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName MaxProfileSize -Type DWord -Value 5000
Set-GPRegistryValue -Name “u01gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName ProfileQuotaMessage -Type String -Value “Tamaño Excedido”
Set-GPRegistryValue -Name “u01gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName WarnUser -Type DWord -Value 1
Set-GPRegistryValue -Name “u01gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName WanUserTimeout -Type DWord -Value 10
#comienza el grupo 2
Set-GPRegistryValue -Name “u02gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName NoDispCPL -Type DWord -Value 1
Set-GPRegistryValue -Name “u02gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName DisallowRun -Type DWord -Value 1
Set-GPRegistryValue -Name “u02gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisallowRun” -ValueName 1 -Type String -Value Notepad.exe
Set-GPRegistryValue -Name “u02gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName EnableProfileQuota -Type DWord -Value 1
Set-GPRegistryValue -Name “u02gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName IncludeProfileQuota -Type DWord -Value 1
Set-GPRegistryValue -Name “u02gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName MaxProfileSize -Type DWord -Value 10000
Set-GPRegistryValue -Name “u02gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName ProfileQuotaMessage -Type String -Value “Tamaño Excedido”
Set-GPRegistryValue -Name “u02gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName WarnUser -Type DWord -Value 1
Set-GPRegistryValue -Name “u02gp0” -Key “HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System” -ValueName WanUserTimeout -Type DWord -Value 10
#roaming files
New-Item -ItemType Directory -Name Profiless -Path C:\
New-SmbShare -Path C:\Profiles\ -Name Profiless
Grant-SmbShareAccess -Name Profiless -AccountName Everyone -AccessRight Full
Set-ADUser -Identity user02 -ProfilePath \\WIN-CKPTOSIN78C\Profiles\%username%