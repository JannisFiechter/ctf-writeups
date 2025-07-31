# Powershell Commands

## Help
get-help<br>
update-help -> updates help<br>

## Navigation
Get-Location -> pwd<br>
Get-ChildItem -> ls<br>
Set-Location .\Documents\ -> cd<br>
Get-Content -> cat<br>

## Files
new-Item "Readme.md" -ItemType File<br>
Add-Content .\Readme.md "Title: Insert Document Title Here<br>
new-item -name "SOPs" -type directory<br>
mkdir "Cyber"<br>
Rename-Item .\Cyber-Sec-draft.md -NewName Infosec-SOP-draft.md<br>

## Filtering
Get-LocalUser administrator | get-member<br>
Get-LocalUser * | Sort-Object -Property Name | Group-Object -property Enabled<br>
Get-Service | where DisplayName -like '*Defender*'<br>



## Tips and Tricks
Get-Command -> list commands<br>
Get-Command -noun windows*<br>
Get-Command -verb get  <br>
Set-Alias -Name gh -Value Get-Help<br>

## Modules
Get-Module -ListAvailable
Import-Module .\PowerSploit.psd1<br>
Get-ExecutionPolicy <br>
Set-ExecutionPolicy undefined <br>
Get-Command -Module PowerSploit<br>

## Get Modules
Get-Command -Module PowerShellGet <br>
Find-Module -Name AdminToolbox<br>
Install-Module AdminToolbox<br>

## Tools To Be Aware Of
AdminToolbox: AdminToolbox is a collection of helpful modules that allow system administrators to perform any number of actions dealing with things like Active Directory, Exchange, Network management, file and storage issues, and more.<br><br>

ActiveDirectory: This module is a collection of local and remote administration tools for all things Active Directory. We can manage users, groups, permissions, and much more with it.<br><br>

Empire / Situational Awareness: Is a collection of PowerShell modules and scripts that can provide us with situational awareness on a host and the domain they are apart of. This project is being maintained by BC Security as a part of their Empire Framework.<br><br>

Inveigh: Inveigh is a tool built to perform network spoofing and Man-in-the-middle attacks.<br><br>

BloodHound / SharpHound: Bloodhound/Sharphound allows us to visually map out an Active Directory Environment using graphical analysis tools and data collectors written in C# and PowerShell.<br><br>


## User & Group MGMT
New-LocalUser -Name "JLawrence" -NoPassword<br><br>

PS C:\htb> $Password = Read-Host -AsSecureString<br>
PS C:\htb> Set-LocalUser -Name "JLawrence" -Password $Password -Description "CEO EagleFang" -> Modify<br><br>

Add-LocalGroupMember -Group "Remote Desktop Users" -Member "JLawrence"<br>

Get-ADUser -Filter *<br>

Get-ADUser -Identity TSilver<br>

Get-ADUser -Filter {EmailAddress -like '*greenhorn.corp'}<br>

New-ADUser -Name "MTanaka" -Surname "Tanaka" -GivenName "Mori" -Office "Security" -OtherAttributes @{'title'="Sensei";'mail'="MTanaka@greenhorn.corp"} -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true <br>

Get-ADUser -Filter "GivenName -like '*Robert*'"<br>


## Services
Start-Service WinDefend<br>
get-service WinDefend<br>
Set-Service -Name Spooler -StartType Disabled<br>
get-service -ComputerName ACADEMY-ICL-DC -> Remote PC<br>
Get-Service -ComputerName ACADEMY-ICL-DC | Where-Object {$_.Status -eq "Running"}<br>

## Tasks
Get-Process

## Invoke-Command
invoke-command -ComputerName ACADEMY-ICL-DC,LOCALHOST -ScriptBlock {Get-Service -Name 'windefend'}<br>

## Event Viewer
Get-WinEvent -ListLog *<br>
Get-WinEvent -ListLog Security<br>
Get-WinEvent -LogName 'Security' -MaxEvents 5 | Select-Object -ExpandProperty Message<br>


## additional
Get-ChildItem -hidden | Measure-Object -> like | wc -l<br>
Get-ChildItem -Recurse -Filter flag.txt | Where-Object { $_.Length -gt 0 } | type<br>
Get-Module -ListAvailable | Where-Object { $_.Name -like '*flag*' } -> Just Shows the module<br>
Get-Command -Module Flag-Finder -> Shows the command<br>

Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4625 }<br>
Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4625 } | ForEach-Object { $_.Properties[5].Value } -> showcases with what user was tried to bruteforce<br> 

